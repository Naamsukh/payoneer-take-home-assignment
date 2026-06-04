"""Authorization Service — Policy Decision Point (PDP) + Policy Admin Point (PAP).

* POST /check         -> the decision endpoint (RBAC + ABAC), with decision cache + audit.
* permissions / roles / policies CRUD -> the admin surface the Streamlit UI drives.

Tenant-scoped reads/writes use tenant_session() (RLS ENFORCED). The permission
catalog is global, so it uses app_session().
"""
from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy import select

from services.common import cache
from services.common.db import app_session, tenant_session
from services.common.models import (
    AuditLog,
    Permission,
    Policy,
    Role,
    RoleHierarchy,
    RolePermission,
)
from services.common.security import decode_service_token, decode_user_token

from . import engine
from .schemas import (
    AddChildRole,
    AuditOut,
    CheckRequest,
    CheckResponse,
    CreatePermission,
    CreatePolicy,
    CreateRole,
    GrantPermission,
    PermissionOut,
    PolicyOut,
    RoleDetail,
    RoleOut,
    UpdatePolicy,
)

app = FastAPI(title="Authorization Service (PDP/PAP)", version="1.0.0")


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization[7:]


def require_access(authorization: str | None = Header(default=None)) -> dict:
    """A tenant-scoped user access token is required for admin (PAP) endpoints."""
    try:
        claims = decode_user_token(_bearer(authorization))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    if claims.get("type") != "access" or not claims.get("tenant_id"):
        raise HTTPException(status_code=403, detail="tenant-scoped access token required")
    return claims


def require_caller(authorization: str | None = Header(default=None)) -> dict:
    """/check may be called by a service (PEP) or a user (UI simulator)."""
    token = _bearer(authorization)
    try:
        return decode_service_token(token)
    except Exception:
        pass
    try:
        return decode_user_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid caller token")


def _maybe_uuid(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------
# PDP — the decision endpoint
# --------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "authz"}


@app.post("/check", response_model=CheckResponse)
def check(body: CheckRequest, _: dict = Depends(require_caller)):
    subject = body.subject.model_dump()
    tenant_id = str(body.subject.tenant_id)
    subject["tenant_id"] = tenant_id

    version = cache.get_tenant_version(tenant_id)
    key = cache.decision_key(subject["user_id"], tenant_id, body.action, body.resource, version)

    hit = cache.get_decision(key)
    if hit:
        return CheckResponse(**hit, cached=True)

    with tenant_session(tenant_id) as session:
        decision, reason, policy_id = engine.decide(
            session, subject, body.action, body.resource, body.environment)
        decision_id = str(uuid.uuid4())
        # Audit the DECISION (computed on cache miss). Per-request access logging
        # is the PEP/gateway's job; the PDP records decision events.
        session.add(AuditLog(
            tenant_id=uuid.UUID(tenant_id),
            actor_user_id=_maybe_uuid(subject.get("user_id")),
            action=body.action, decision=decision, reason=reason,
            context={"resource": body.resource, "decision_id": decision_id},
        ))

    result = {"decision": decision, "reason": reason,
              "policy_id": policy_id, "decision_id": decision_id}
    cache.set_decision(key, result)
    return CheckResponse(**result, cached=False)


# --------------------------------------------------------------------------
# PAP — permission catalog (global)
# --------------------------------------------------------------------------
@app.post("/permissions", response_model=PermissionOut)
def create_permission(body: CreatePermission, _: dict = Depends(require_access)):
    with app_session() as session:
        perm = session.execute(
            select(Permission).where(
                Permission.service == body.service,
                Permission.resource == body.resource,
                Permission.action == body.action)
        ).scalar_one_or_none()
        if perm is None:
            perm = Permission(service=body.service, resource=body.resource,
                              action=body.action, description=body.description)
            session.add(perm)
            session.flush()
        return PermissionOut(id=perm.id, service=perm.service, resource=perm.resource,
                             action=perm.action, key=perm.key, description=perm.description)


@app.get("/permissions", response_model=list[PermissionOut])
def list_permissions(_: dict = Depends(require_access)):
    with app_session() as session:
        perms = session.execute(
            select(Permission).order_by(Permission.service, Permission.resource, Permission.action)
        ).scalars().all()
        return [PermissionOut(id=p.id, service=p.service, resource=p.resource,
                              action=p.action, key=p.key, description=p.description) for p in perms]


# --------------------------------------------------------------------------
# PAP — roles (tenant-scoped)
# --------------------------------------------------------------------------
@app.post("/roles", response_model=RoleOut)
def create_role(body: CreateRole, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    with tenant_session(tid) as session:
        role = Role(tenant_id=uuid.UUID(tid), name=body.name, description=body.description)
        session.add(role)
        session.flush()
        out = RoleOut(id=role.id, name=role.name, description=role.description, is_system=role.is_system)
    cache.bump_tenant_version(tid)
    return out


@app.get("/roles", response_model=list[RoleOut])
def list_roles(claims: dict = Depends(require_access)):
    with tenant_session(claims["tenant_id"]) as session:
        roles = session.execute(select(Role).order_by(Role.name)).scalars().all()
        return [RoleOut(id=r.id, name=r.name, description=r.description, is_system=r.is_system) for r in roles]


@app.get("/roles/{role_id}", response_model=RoleDetail)
def role_detail(role_id: uuid.UUID, claims: dict = Depends(require_access)):
    with tenant_session(claims["tenant_id"]) as session:
        role = session.get(Role, role_id)
        if role is None:
            raise HTTPException(status_code=404, detail="role not found")
        perm_keys = list(engine.effective_permission_keys(session, [role.name]))
        child_ids = session.execute(
            select(RoleHierarchy.child_role_id).where(RoleHierarchy.parent_role_id == role_id)
        ).scalars().all()
        inherits = []
        if child_ids:
            inherits = list(session.execute(
                select(Role.name).where(Role.id.in_(child_ids))
            ).scalars().all())
        return RoleDetail(id=role.id, name=role.name, description=role.description,
                          permissions=sorted(perm_keys), inherits=sorted(inherits))


@app.post("/roles/{role_id}/permissions")
def grant_permission(role_id: uuid.UUID, body: GrantPermission, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    with tenant_session(tid) as session:
        if session.get(Role, role_id) is None:
            raise HTTPException(status_code=404, detail="role not found")
        if session.get(Permission, body.permission_id) is None:
            raise HTTPException(status_code=400, detail="permission not found")
        existing = session.execute(
            select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == body.permission_id)
        ).scalar_one_or_none()
        if existing is None:
            session.add(RolePermission(tenant_id=uuid.UUID(tid), role_id=role_id,
                                       permission_id=body.permission_id))
    cache.bump_tenant_version(tid)
    return {"status": "granted"}


@app.delete("/roles/{role_id}/permissions/{permission_id}")
def revoke_permission(role_id: uuid.UUID, permission_id: uuid.UUID, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    with tenant_session(tid) as session:
        link = session.execute(
            select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id)
        ).scalar_one_or_none()
        if link is not None:
            session.delete(link)
    cache.bump_tenant_version(tid)
    return {"status": "revoked"}


@app.post("/roles/{role_id}/children")
def add_child_role(role_id: uuid.UUID, body: AddChildRole, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    if role_id == body.child_role_id:
        raise HTTPException(status_code=400, detail="a role cannot inherit itself")
    with tenant_session(tid) as session:
        if session.get(Role, role_id) is None or session.get(Role, body.child_role_id) is None:
            raise HTTPException(status_code=404, detail="role not found")
        existing = session.execute(
            select(RoleHierarchy).where(
                RoleHierarchy.parent_role_id == role_id,
                RoleHierarchy.child_role_id == body.child_role_id)
        ).scalar_one_or_none()
        if existing is None:
            session.add(RoleHierarchy(tenant_id=uuid.UUID(tid), parent_role_id=role_id,
                                      child_role_id=body.child_role_id))
    cache.bump_tenant_version(tid)
    return {"status": "linked"}


# --------------------------------------------------------------------------
# PAP — policies (ABAC, tenant-scoped)
# --------------------------------------------------------------------------
@app.post("/policies", response_model=PolicyOut)
def create_policy(body: CreatePolicy, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    if body.effect not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="effect must be allow|deny")
    try:  # structural validation of the condition DSL
        engine.evaluate(body.condition, {"subject": {}, "resource": {}, "environment": {}})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid condition: {exc}")
    with tenant_session(tid) as session:
        if session.get(Permission, body.permission_id) is None:
            raise HTTPException(status_code=400, detail="permission not found")
        policy = Policy(tenant_id=uuid.UUID(tid), permission_id=body.permission_id,
                        name=body.name, condition=body.condition, effect=body.effect)
        session.add(policy)
        session.flush()
        out = PolicyOut(id=policy.id, permission_id=policy.permission_id, name=policy.name,
                        condition=policy.condition, effect=policy.effect,
                        version=policy.version, enabled=policy.enabled)
    cache.bump_tenant_version(tid)
    return out


@app.get("/policies", response_model=list[PolicyOut])
def list_policies(claims: dict = Depends(require_access)):
    with tenant_session(claims["tenant_id"]) as session:
        policies = session.execute(select(Policy).order_by(Policy.name)).scalars().all()
        return [PolicyOut(id=p.id, permission_id=p.permission_id, name=p.name,
                          condition=p.condition, effect=p.effect, version=p.version,
                          enabled=p.enabled) for p in policies]


@app.put("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(policy_id: uuid.UUID, body: UpdatePolicy, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    with tenant_session(tid) as session:
        policy = session.get(Policy, policy_id)
        if policy is None:
            raise HTTPException(status_code=404, detail="policy not found")
        if body.condition is not None:
            try:
                engine.evaluate(body.condition, {"subject": {}, "resource": {}, "environment": {}})
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"invalid condition: {exc}")
            policy.condition = body.condition
        if body.effect is not None:
            if body.effect not in ("allow", "deny"):
                raise HTTPException(status_code=400, detail="effect must be allow|deny")
            policy.effect = body.effect
        if body.enabled is not None:
            policy.enabled = body.enabled
        policy.version += 1
        out = PolicyOut(id=policy.id, permission_id=policy.permission_id, name=policy.name,
                        condition=policy.condition, effect=policy.effect,
                        version=policy.version, enabled=policy.enabled)
    cache.bump_tenant_version(tid)
    return out


@app.delete("/policies/{policy_id}")
def delete_policy(policy_id: uuid.UUID, claims: dict = Depends(require_access)):
    tid = claims["tenant_id"]
    with tenant_session(tid) as session:
        policy = session.get(Policy, policy_id)
        if policy is not None:
            session.delete(policy)
    cache.bump_tenant_version(tid)
    return {"status": "deleted"}


# --------------------------------------------------------------------------
# Audit (tenant-scoped)
# --------------------------------------------------------------------------
@app.get("/audit", response_model=list[AuditOut])
def list_audit(limit: int = 100, claims: dict = Depends(require_access)):
    with tenant_session(claims["tenant_id"]) as session:
        rows = session.execute(
            select(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(limit, 500))
        ).scalars().all()
        return [AuditOut(id=r.id, actor_user_id=r.actor_user_id, action=r.action,
                         decision=r.decision, reason=r.reason, context=r.context,
                         created_at=r.created_at.isoformat()) for r in rows]
