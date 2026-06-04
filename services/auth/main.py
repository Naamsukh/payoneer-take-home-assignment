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
from services.common.models import (
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
    return {"status": "ok", "service": "auth"}


@app.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest):
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
        return LoginResponse(
            identity_token=issue_identity_token(str(user.id), user.email),
            user_id=user.id, email=user.email, memberships=memberships,
        )


@app.post("/auth/select-tenant", response_model=TokenResponse)
def select_tenant(body: SelectTenantRequest, claims: dict = Depends(require_token)):
    with identity_session() as session:
        return _issue_session(session, uuid.UUID(claims["sub"]), body.tenant_id)


@app.post("/auth/switch-tenant", response_model=TokenResponse)
def switch_tenant(body: SelectTenantRequest, claims: dict = Depends(require_token)):
    # Any valid user token (identity or access) identifies the principal.
    with identity_session() as session:
        return _issue_session(session, uuid.UUID(claims["sub"]), body.tenant_id)


@app.post("/auth/refresh", response_model=AccessTokenResponse)
def refresh(body: RefreshRequest):
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
    cache.revoke_refresh(body.refresh_token)
    return {"status": "logged out"}


@app.get("/auth/me")
def me(claims: dict = Depends(require_token)):
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
def create_tenant(body: CreateTenantRequest, _: dict = Depends(require_token)):
    with identity_session() as session:
        tenant = Tenant(name=body.name, tier=body.tier)
        session.add(tenant)
        session.flush()
        return TenantOut(id=tenant.id, name=tenant.name, status=tenant.status, tier=tenant.tier)


@app.get("/tenants", response_model=list[TenantOut])
def list_tenants(_: dict = Depends(require_token)):
    with identity_session() as session:
        tenants = session.execute(select(Tenant).order_by(Tenant.name)).scalars().all()
        return [TenantOut(id=t.id, name=t.name, status=t.status, tier=t.tier) for t in tenants]


@app.post("/users", response_model=UserOut)
def create_user(body: CreateUserRequest, _: dict = Depends(require_token)):
    with identity_session() as session:
        existing = session.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(status_code=409, detail="email already registered")
        user = User(email=body.email, password_hash=hash_password(body.password))
        session.add(user)
        session.flush()
        return UserOut(id=user.id, email=user.email, status=user.status)


@app.get("/users", response_model=list[UserOut])
def list_users(_: dict = Depends(require_token)):
    with identity_session() as session:
        users = session.execute(select(User).order_by(User.email)).scalars().all()
        return [UserOut(id=u.id, email=u.email, status=u.status) for u in users]


@app.post("/tenants/{tenant_id}/members", response_model=MemberOut)
def add_member(tenant_id: uuid.UUID, body: AddMemberRequest, _: dict = Depends(require_token)):
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
        return MemberOut(
            membership_id=membership.id, user_id=user.id, email=user.email,
            status=membership.status, org_unit_id=membership.org_unit_id, roles=[],
        )


@app.get("/tenants/{tenant_id}/members", response_model=list[MemberOut])
def list_members(tenant_id: uuid.UUID, _: dict = Depends(require_token)):
    with identity_session() as session:
        rows = session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.tenant_id == tenant_id)
        ).all()
        return [
            MemberOut(
                membership_id=m.id, user_id=u.id, email=u.email, status=m.status,
                org_unit_id=m.org_unit_id, roles=_roles_for_membership(session, m.id),
            )
            for m, u in rows
        ]


@app.post("/memberships/{membership_id}/roles")
def assign_role(membership_id: uuid.UUID, body: AssignRoleRequest, _: dict = Depends(require_token)):
    with identity_session() as session:
        membership = session.get(Membership, membership_id)
        if membership is None:
            raise HTTPException(status_code=404, detail="membership not found")
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
        return {"status": "assigned", "roles": _roles_for_membership(session, membership_id)}


@app.delete("/memberships/{membership_id}/roles/{role_id}")
def unassign_role(membership_id: uuid.UUID, role_id: uuid.UUID, _: dict = Depends(require_token)):
    with identity_session() as session:
        link = session.execute(
            select(MembershipRole).where(
                MembershipRole.membership_id == membership_id,
                MembershipRole.role_id == role_id)
        ).scalar_one_or_none()
        if link is not None:
            session.delete(link)
        return {"status": "unassigned", "roles": _roles_for_membership(session, membership_id)}


@app.post("/tenants/{tenant_id}/org-units", response_model=OrgUnitOut)
def create_org_unit(tenant_id: uuid.UUID, body: CreateOrgUnitRequest, _: dict = Depends(require_token)):
    with identity_session() as session:
        ou = OrgUnit(tenant_id=tenant_id, name=body.name, parent_id=body.parent_id)
        session.add(ou)
        session.flush()
        return OrgUnitOut(id=ou.id, name=ou.name, parent_id=ou.parent_id)


@app.get("/tenants/{tenant_id}/org-units", response_model=list[OrgUnitOut])
def list_org_units(tenant_id: uuid.UUID, _: dict = Depends(require_token)):
    with identity_session() as session:
        units = session.execute(
            select(OrgUnit).where(OrgUnit.tenant_id == tenant_id).order_by(OrgUnit.name)
        ).scalars().all()
        return [OrgUnitOut(id=o.id, name=o.name, parent_id=o.parent_id) for o in units]
