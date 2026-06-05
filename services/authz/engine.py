"""The Policy Decision Point core: RBAC resolution + ABAC evaluation.

All DB reads happen inside an RLS-enforced ``tenant_session`` so the engine
physically cannot see another tenant's roles/permissions/policies.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.common.models import (
    Membership,
    MembershipPermission,
    Permission,
    Policy,
    Role,
    RoleHierarchy,
    RolePermission,
)

_ATTR_ROOTS = {"subject", "resource", "environment", "env"}


# =========================================================================
# ABAC condition evaluator  (safe JSON DSL — no eval/exec)
# =========================================================================
def _resolve(operand: Any, ctx: dict) -> Any:
    """A string whose first dotted segment is an attribute root is a path;
    everything else (numbers, bools, lists, other strings) is a literal."""
    if isinstance(operand, str):
        head = operand.split(".", 1)[0]
        if head in _ATTR_ROOTS:
            cur: Any = ctx
            for part in operand.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    return None
            return cur
    return operand


def evaluate(node: Any, ctx: dict) -> bool:
    """Evaluate a condition tree against {subject, resource, environment}."""
    if node in (None, {}, True):
        return True            # empty condition == unconditional
    if node is False:
        return False
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError(f"invalid condition node: {node!r}")

    op, args = next(iter(node.items()))

    if op == "all":
        return all(evaluate(a, ctx) for a in args)
    if op == "any":
        return any(evaluate(a, ctx) for a in args)
    if op == "not":
        inner = args[0] if isinstance(args, list) else args
        return not evaluate(inner, ctx)

    left, right = _resolve(args[0], ctx), _resolve(args[1], ctx)

    if op == "eq":
        return left == right
    if op == "neq":
        return left != right
    if op in ("lt", "lte", "gt", "gte"):
        if left is None or right is None:
            return False
        try:
            return {
                "lt": left < right, "lte": left <= right,
                "gt": left > right, "gte": left >= right,
            }[op]
        except TypeError:
            return False
    if op == "in":
        return left in right if right is not None else False
    if op == "contains":
        return right in left if left is not None else False

    raise ValueError(f"unknown operator: {op}")


# =========================================================================
# RBAC resolution
# =========================================================================
def effective_permission_keys(session: Session, role_names: list[str]) -> set[str]:
    """Transitive set of permission keys granted to the given roles.

    Role hierarchy edge parent->child means the parent inherits the child's
    permissions, so we walk the closure downward from the user's roles.
    """
    if not role_names:
        return set()

    roles = session.execute(select(Role).where(Role.name.in_(role_names))).scalars().all()
    closure: set[uuid.UUID] = {r.id for r in roles}

    edges = session.execute(select(RoleHierarchy)).scalars().all()  # RLS-scoped to tenant
    children: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for e in edges:
        children[e.parent_role_id].append(e.child_role_id)

    frontier = set(closure)
    while frontier:
        nxt: set[uuid.UUID] = set()
        for rid in frontier:
            for child in children.get(rid, []):
                if child not in closure:
                    closure.add(child)
                    nxt.add(child)
        frontier = nxt

    if not closure:
        return set()

    perm_ids = session.execute(
        select(RolePermission.permission_id).where(RolePermission.role_id.in_(closure))
    ).scalars().all()
    if not perm_ids:
        return set()

    perms = session.execute(select(Permission).where(Permission.id.in_(perm_ids))).scalars().all()
    return {p.key for p in perms}


def direct_permission_keys(session: Session, user_id) -> set[str]:
    """Permissions granted DIRECTLY to this user's membership (per-user grants).

    Resolved inside the tenant-scoped (RLS) session, so it only ever sees the
    caller's own tenant; the membership is located by user_id (unique per
    user+tenant). Returns an empty set if the user has no direct grants. The
    caller unions this with the role-derived set; ABAC deny still wins downstream.
    """
    if not user_id:
        return set()
    try:
        uid = uuid.UUID(str(user_id))
    except (ValueError, TypeError):
        return set()

    mem_ids = session.execute(
        select(Membership.id).where(Membership.user_id == uid)
    ).scalars().all()
    if not mem_ids:
        return set()

    perm_ids = session.execute(
        select(MembershipPermission.permission_id).where(
            MembershipPermission.membership_id.in_(mem_ids))
    ).scalars().all()
    if not perm_ids:
        return set()

    perms = session.execute(select(Permission).where(Permission.id.in_(perm_ids))).scalars().all()
    return {p.key for p in perms}


def _permission_for_action(session: Session, action: str) -> Permission | None:
    try:
        svc, res, act = action.split(":")
    except ValueError:
        return None
    return session.execute(
        select(Permission).where(
            Permission.service == svc, Permission.resource == res, Permission.action == act)
    ).scalar_one_or_none()


# =========================================================================
# Decision
# =========================================================================
def decide(session: Session, subject: dict, action: str,
           resource: dict, environment: dict | None) -> tuple[str, str, str | None]:
    """Return (decision, reason, policy_id). Deny by default; explicit deny wins.

    1. RBAC: action must be in the subject's effective permissions, else DENY.
       Effective = role-derived (incl. inheritance) UNION direct per-user grants.
    2. ABAC: deny-policy match -> DENY (explicit deny wins — overrides a direct grant).
    3. If allow-policies exist for this permission, one must match, else DENY.
    4. Otherwise ALLOW (RBAC baseline grant, no further ABAC constraints).
    """
    role_names = subject.get("roles", []) or []
    granted = effective_permission_keys(session, role_names)
    granted |= direct_permission_keys(session, subject.get("user_id"))  # per-user direct grants
    if action not in granted:
        return ("deny", "no_permission", None)

    perm = _permission_for_action(session, action)
    if perm is None:
        return ("deny", "unknown_permission", None)

    policies = session.execute(
        select(Policy).where(Policy.permission_id == perm.id, Policy.enabled.is_(True))
    ).scalars().all()

    ctx = {"subject": subject, "resource": resource or {}, "environment": environment or {}}

    deny_policies = [p for p in policies if p.effect == "deny"]
    allow_policies = [p for p in policies if p.effect == "allow"]

    for p in deny_policies:
        if evaluate(p.condition, ctx):
            return ("deny", f"policy:{p.name}", str(p.id))

    if allow_policies:
        for p in allow_policies:
            if evaluate(p.condition, ctx):
                return ("allow", f"policy:{p.name}", str(p.id))
        return ("deny", "no_allow_policy_matched", None)

    return ("allow", "rbac", None)
