"""Auth Service — the identity authority.

Owns global users, tenants, memberships and role assignments. Authenticates the
global identity, then issues tenant-scoped access tokens via select/switch-tenant.
Does NOT make authorization decisions (that is the Authz/PDP service).

Uses identity_session() (BYPASSRLS): the Auth service legitimately operates above
tenant scope — a user's memberships span many tenants, and login happens before a
tenant is chosen. Tenant correctness is enforced in application logic here.

NOTE (scope): management endpoints below require a valid token (authentication).
In production each would additionally be authorized via the PDP (e.g. the
`usermgmt:tenant:create` permission). That is documented as a deliberate
take-home simplification so the access-control story is demonstrated on the
business services (Expense/Payroll).
"""
from __future__ import annotations

import secrets
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy import select

from services.common import cache
from services.common.db import identity_session
from services.common.health import readiness
from services.common.models import (
    AuditLog,
    Membership,
    MembershipRole,
    OrgUnit,
    Role,
    Tenant,
    User,
)
from services.common.security import (
    decode_user_token,
    hash_password,
    issue_access_token,
    issue_identity_token,
    verify_password,
)

from .schemas import (
    AccessTokenResponse,
    AddMemberRequest,
    AssignRoleRequest,
    CreateOrgUnitRequest,
    CreateTenantRequest,
    CreateUserRequest,
    LoginRequest,
    LoginResponse,
    MemberOut,
    MembershipSummary,
    OrgUnitOut,
    RefreshRequest,
    SelectTenantRequest,
    TenantOut,
    TokenResponse,
    UserOut,
)

app = FastAPI(title="Auth Service", version="1.0.0")


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
def require_token(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        return decode_user_token(authorization[7:])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid or expired token")


def require_tenant_admin(authorization: str | None = Header(default=None)) -> dict:
    """Management endpoints require a tenant-scoped access token whose holder is a
    ``tenant_admin``.

    Closes the management-surface gap (docs/DESIGN.md §13.1): a regular member can no
    longer add members, assign roles, edit org-units, or create users/tenants. For
    endpoints that name a tenant in the path, the handler additionally asserts the
    path tenant equals the token's tenant (``_assert_tenant``) so an admin of one
    tenant cannot act on another. NOTE: a true cross-tenant *platform admin* (for
    create/list of tenants and global users) is still future work (§17); these are
    gated to tenant_admin here to remove the any-member hole.
    """
    claims = require_token(authorization)
    if claims.get("type") != "access" or not claims.get("tenant_id"):
        raise HTTPException(status_code=403, detail="tenant-scoped access token required")
    if "tenant_admin" not in (claims.get("roles") or []):
        raise HTTPException(status_code=403, detail="tenant_admin role required")
    return claims


def _assert_tenant(claims: dict, tenant_id) -> None:
    """Reject if the caller's token tenant differs from the path tenant."""
    if str(claims.get("tenant_id")) != str(tenant_id):
        raise HTTPException(status_code=403, detail="not an admin of this tenant")


def _audit_admin(session, tenant_id, actor_sub, action: str, reason: str = "",
                 context: dict | None = None) -> None:
    """Append an admin-change record to the tenant audit trail (docs/DESIGN.md §13).

    Reuses the caller's (BYPASSRLS) identity session; tenant_id is explicit.
    """
    session.add(AuditLog(
        tenant_id=uuid.UUID(str(tenant_id)),
        actor_user_id=uuid.UUID(str(actor_sub)) if actor_sub else None,
        action=action, decision="info", reason=reason or "", context=context or {},
    ))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _roles_for_membership(session, membership_id) -> list[str]:
    return list(
        session.execute(
            select(Role.name)
            .join(MembershipRole, MembershipRole.role_id == Role.id)
            .where(MembershipRole.membership_id == membership_id)
        ).scalars().all()
    )


def _active_membership(session, user_id, tenant_id) -> Membership | None:
    return session.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.tenant_id == tenant_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()


def _issue_session(session, user_id, tenant_id) -> TokenResponse:
    """Mint an access token + refresh session for an active membership."""
    membership = _active_membership(session, user_id, tenant_id)
    if membership is None:
        raise HTTPException(status_code=403, detail="no active membership for this tenant")

    roles = _roles_for_membership(session, membership.id)
    access = issue_access_token(
        user_id=str(user_id),
        tenant_id=str(tenant_id),
        membership_id=str(membership.id),
        roles=roles,
        org_unit_id=str(membership.org_unit_id) if membership.org_unit_id else None,
    )
    refresh_id = secrets.token_urlsafe(32)
    cache.store_refresh(refresh_id, {
        "user_id": str(user_id),
        "tenant_id": str(tenant_id),
        "membership_id": str(membership.id),
    })
    return TokenResponse(access_token=access, refresh_token=refresh_id,
                         tenant_id=tenant_id, roles=roles)


# --------------------------------------------------------------------------
# Auth flow
# --------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    """Liveness probe (process up). No auth, no I/O."""
    return {"status": "ok", "service": "auth"}


@app.get("/readyz")
def readyz():
    """Readiness probe — verifies Postgres + Redis are reachable (503 if not)."""
    return readiness("auth")


@app.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest):
    """Authenticate the GLOBAL identity (email + password).

    Returns the identity token + the user's memberships, and ALSO auto-scopes to
    the user's **primary (first-joined) active membership** — minting an access +
    refresh token in the same call so a caller has a usable tenant-scoped token in
    one step (no separate /auth/select-tenant needed). The token fields are null
    only when the user has no active membership. To act in a different tenant, call
    /auth/switch-tenant. Auth: none (entry point); credentials verified with bcrypt.
    """
    with identity_session() as session:
        user = session.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        if user is None or not verify_password(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")
        if user.status != "active":
            raise HTTPException(status_code=403, detail="user disabled")

        rows = session.execute(
            select(Membership, Tenant)
            .join(Tenant, Tenant.id == Membership.tenant_id)
            .where(Membership.user_id == user.id)
        ).all()
        memberships = [
            MembershipSummary(
                tenant_id=t.id, tenant_name=t.name,
                membership_id=m.id, status=m.status,
            )
            for m, t in rows
        ]
        # Auto-scope to the primary (earliest-joined) ACTIVE membership.
        active = sorted((m for m, _ in rows if m.status == "active"),
                        key=lambda m: m.joined_at)
        token = _issue_session(session, user.id, active[0].tenant_id) if active else None
        return LoginResponse(
            identity_token=issue_identity_token(str(user.id), user.email),
            user_id=user.id, email=user.email, memberships=memberships,
            access_token=token.access_token if token else None,
            refresh_token=token.refresh_token if token else None,
            active_tenant_id=token.tenant_id if token else None,
            roles=token.roles if token else [],
        )


@app.post("/auth/select-tenant", response_model=TokenResponse)
def select_tenant(body: SelectTenantRequest, claims: dict = Depends(require_token)):
    """Pick the active tenant and mint a tenant-scoped access + refresh token.

    Re-verifies an ACTIVE membership for (caller, tenant) before issuing, so a
    token can only ever name a tenant the user actually belongs to.
    Auth: any valid user token (identity or access).
    """
    with identity_session() as session:
        return _issue_session(session, uuid.UUID(claims["sub"]), body.tenant_id)


@app.post("/auth/switch-tenant", response_model=TokenResponse)
def switch_tenant(body: SelectTenantRequest, claims: dict = Depends(require_token)):
    """Re-issue a token for a DIFFERENT tenant the user belongs to.

    Identical guarantees to /auth/select-tenant (active-membership re-check); the
    one-active-tenant-per-token model keeps the PDP/RLS context unambiguous.
    Auth: any valid user token (identity or access).
    """
    # Any valid user token (identity or access) identifies the principal.
    with identity_session() as session:
        return _issue_session(session, uuid.UUID(claims["sub"]), body.tenant_id)


@app.post("/auth/refresh", response_model=AccessTokenResponse)
def refresh(body: RefreshRequest):
    """Exchange a refresh token for a fresh 15-min access token.

    Validates the refresh session in Redis AND re-checks that the membership is
    still active and re-reads current roles — so deactivation/role changes take
    effect at the next refresh (bounded staleness), not only at expiry.
    Auth: a valid, non-revoked refresh token.
    """
    data = cache.get_refresh(body.refresh_token)
    if not data:
        raise HTTPException(status_code=401, detail="invalid refresh token")
    with identity_session() as session:
        roles = _roles_for_membership(session, uuid.UUID(data["membership_id"]))
        membership = session.get(Membership, uuid.UUID(data["membership_id"]))
        if membership is None or membership.status != "active":
            raise HTTPException(status_code=403, detail="membership no longer active")
        access = issue_access_token(
            user_id=data["user_id"], tenant_id=data["tenant_id"],
            membership_id=data["membership_id"], roles=roles,
            org_unit_id=str(membership.org_unit_id) if membership.org_unit_id else None,
        )
        return AccessTokenResponse(access_token=access)


@app.post("/auth/logout")
def logout(body: RefreshRequest):
    """Revoke a refresh session (deletes it from Redis).

    The short-lived access token is stateless and simply expires (≤15 min); this
    immediately stops any further refreshes. Auth: presents the refresh token.
    """
    cache.revoke_refresh(body.refresh_token)
    return {"status": "logged out"}


@app.get("/auth/me")
def me(claims: dict = Depends(require_token)):
    """Return the calling principal's profile and tenant memberships.

    Scoped to the token subject (WHERE user_id = sub), so a caller only ever sees
    their own identity. Auth: any valid user token.
    """
    with identity_session() as session:
        user = session.get(User, uuid.UUID(claims["sub"]))
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        rows = session.execute(
            select(Membership, Tenant)
            .join(Tenant, Tenant.id == Membership.tenant_id)
            .where(Membership.user_id == user.id)
        ).all()
        return {
            "user_id": str(user.id),
            "email": user.email,
            "memberships": [
                {"tenant_id": str(t.id), "tenant_name": t.name,
                 "membership_id": str(m.id), "status": m.status}
                for m, t in rows
            ],
        }


# --------------------------------------------------------------------------
# Management (tenants / users / memberships / org units / role assignment)
# --------------------------------------------------------------------------
@app.post("/tenants", response_model=TenantOut)
def create_tenant(body: CreateTenantRequest, claims: dict = Depends(require_tenant_admin)):
    """Create a tenant (organization). Writes the global `tenants` table.

    Auth: tenant_admin. (Residual: ideally a PLATFORM ADMIN, since this is a global
    create — the platform-admin principal is future work, §17/§13.1. Gating to
    tenant_admin removes the any-member hole.)
    """
    with identity_session() as session:
        tenant = Tenant(name=body.name, tier=body.tier)
        session.add(tenant)
        session.flush()
        return TenantOut(id=tenant.id, name=tenant.name, status=tenant.status, tier=tenant.tier)


@app.get("/tenants", response_model=list[TenantOut])
def list_tenants(limit: int = 50, offset: int = 0, claims: dict = Depends(require_tenant_admin)):
    """List tenants (global `tenants` table), paginated (limit capped at 200).

    Auth: tenant_admin. (Residual: cross-tenant by nature, ideally PLATFORM ADMIN —
    future work, §17/§13.1.)
    """
    with identity_session() as session:
        tenants = session.execute(
            select(Tenant).order_by(Tenant.name)
            .limit(min(max(limit, 1), 200)).offset(max(offset, 0))
        ).scalars().all()
        return [TenantOut(id=t.id, name=t.name, status=t.status, tier=t.tier) for t in tenants]


@app.post("/users", response_model=UserOut)
def create_user(body: CreateUserRequest, claims: dict = Depends(require_tenant_admin)):
    """Create a global user identity (email unique; password hashed).

    Auth: tenant_admin (admins onboard users into their tenant — FR-2). Long term,
    SSO/SCIM provisioning replaces this (§17).
    """
    with identity_session() as session:
        existing = session.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(status_code=409, detail="email already registered")
        user = User(email=body.email, password_hash=hash_password(body.password))
        session.add(user)
        session.flush()
        return UserOut(id=user.id, email=user.email, status=user.status)


@app.get("/users", response_model=list[UserOut])
def list_users(limit: int = 50, offset: int = 0, claims: dict = Depends(require_tenant_admin)):
    """List users (global `users` table), paginated (limit capped at 200).

    Auth: tenant_admin (needed to pick a user to add as a member). Residual: a
    real system would scope/search rather than enumerate all users — §13.1.
    """
    with identity_session() as session:
        users = session.execute(
            select(User).order_by(User.email)
            .limit(min(max(limit, 1), 200)).offset(max(offset, 0))
        ).scalars().all()
        return [UserOut(id=u.id, email=u.email, status=u.status) for u in users]


@app.post("/tenants/{tenant_id}/members", response_model=MemberOut)
def add_member(tenant_id: uuid.UUID, body: AddMemberRequest, claims: dict = Depends(require_tenant_admin)):
    """Add an existing user to `tenant_id` as an active member.

    Auth: tenant_admin of the path tenant (`_assert_tenant`), so an admin of one
    tenant cannot add members to another. Audited.
    """
    _assert_tenant(claims, tenant_id)
    with identity_session() as session:
        if session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        user = session.get(User, body.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        existing = session.execute(
            select(Membership).where(
                Membership.user_id == body.user_id, Membership.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(status_code=409, detail="user already a member of this tenant")
        membership = Membership(
            tenant_id=tenant_id, user_id=body.user_id,
            org_unit_id=body.org_unit_id, status="active",
        )
        session.add(membership)
        session.flush()
        _audit_admin(session, tenant_id, claims["sub"], "admin:member.add",
                     user.email, {"membership_id": str(membership.id), "user_id": str(user.id)})
        return MemberOut(
            membership_id=membership.id, user_id=user.id, email=user.email,
            status=membership.status, org_unit_id=membership.org_unit_id, roles=[],
        )


@app.get("/tenants/{tenant_id}/members", response_model=list[MemberOut])
def list_members(tenant_id: uuid.UUID, limit: int = 50, offset: int = 0,
                 claims: dict = Depends(require_tenant_admin)):
    """List members (and their roles) of `tenant_id`, paginated (limit capped 200).

    Auth: tenant_admin of the path tenant (`_assert_tenant`).
    """
    _assert_tenant(claims, tenant_id)
    with identity_session() as session:
        rows = session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.tenant_id == tenant_id)
            .order_by(User.email)
            .limit(min(max(limit, 1), 200)).offset(max(offset, 0))
        ).all()
        return [
            MemberOut(
                membership_id=m.id, user_id=u.id, email=u.email, status=m.status,
                org_unit_id=m.org_unit_id, roles=_roles_for_membership(session, m.id),
            )
            for m, u in rows
        ]


@app.post("/memberships/{membership_id}/roles")
def assign_role(membership_id: uuid.UUID, body: AssignRoleRequest, claims: dict = Depends(require_tenant_admin)):
    """Assign a tenant role to a membership.

    Auth: tenant_admin, and the target membership must be in the caller's tenant
    (checked below — the membership_id is in the path, not the tenant). Also keeps
    the cross-tenant role guard (`role.tenant_id == membership.tenant_id`). Audited.
    """
    with identity_session() as session:
        membership = session.get(Membership, membership_id)
        if membership is None:
            raise HTTPException(status_code=404, detail="membership not found")
        _assert_tenant(claims, membership.tenant_id)
        role = session.get(Role, body.role_id)
        if role is None or role.tenant_id != membership.tenant_id:
            raise HTTPException(status_code=400, detail="role not found in this tenant")
        existing = session.execute(
            select(MembershipRole).where(
                MembershipRole.membership_id == membership_id,
                MembershipRole.role_id == body.role_id)
        ).scalar_one_or_none()
        if existing is None:
            session.add(MembershipRole(
                tenant_id=membership.tenant_id, membership_id=membership_id,
                role_id=body.role_id, scope_org_unit_id=body.scope_org_unit_id,
            ))
        _audit_admin(session, membership.tenant_id, claims["sub"], "admin:member.assign_role",
                     role.name, {"membership_id": str(membership_id), "role_id": str(body.role_id)})
        return {"status": "assigned", "roles": _roles_for_membership(session, membership_id)}


@app.delete("/memberships/{membership_id}/roles/{role_id}")
def unassign_role(membership_id: uuid.UUID, role_id: uuid.UUID, claims: dict = Depends(require_tenant_admin)):
    """Remove a role from a membership.

    Auth: tenant_admin, and the target membership must be in the caller's tenant
    (asserted below). Audited.
    """
    with identity_session() as session:
        membership = session.get(Membership, membership_id)
        if membership is None:
            raise HTTPException(status_code=404, detail="membership not found")
        _assert_tenant(claims, membership.tenant_id)
        link = session.execute(
            select(MembershipRole).where(
                MembershipRole.membership_id == membership_id,
                MembershipRole.role_id == role_id)
        ).scalar_one_or_none()
        if link is not None:
            session.delete(link)
        _audit_admin(session, membership.tenant_id, claims["sub"], "admin:member.unassign_role",
                     str(role_id), {"membership_id": str(membership_id), "role_id": str(role_id)})
        return {"status": "unassigned", "roles": _roles_for_membership(session, membership_id)}


@app.post("/tenants/{tenant_id}/org-units", response_model=OrgUnitOut)
def create_org_unit(tenant_id: uuid.UUID, body: CreateOrgUnitRequest, claims: dict = Depends(require_tenant_admin)):
    """Create an org-unit node in `tenant_id`'s org tree.

    Auth: tenant_admin of the path tenant (`_assert_tenant`).
    """
    _assert_tenant(claims, tenant_id)
    with identity_session() as session:
        ou = OrgUnit(tenant_id=tenant_id, name=body.name, parent_id=body.parent_id)
        session.add(ou)
        session.flush()
        return OrgUnitOut(id=ou.id, name=ou.name, parent_id=ou.parent_id)


@app.get("/tenants/{tenant_id}/org-units", response_model=list[OrgUnitOut])
def list_org_units(tenant_id: uuid.UUID, claims: dict = Depends(require_tenant_admin)):
    """List org units for `tenant_id`.

    Auth: tenant_admin of the path tenant (`_assert_tenant`).
    """
    _assert_tenant(claims, tenant_id)
    with identity_session() as session:
        units = session.execute(
            select(OrgUnit).where(OrgUnit.tenant_id == tenant_id).order_by(OrgUnit.name)
        ).scalars().all()
        return [OrgUnitOut(id=o.id, name=o.name, parent_id=o.parent_id) for o in units]
