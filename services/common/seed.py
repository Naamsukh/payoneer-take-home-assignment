"""Idempotent demo seed (run by the `seed` container after bootstrap, or `make seed`).

Creates a realistic, self-contained dataset that exercises every access-control
feature in the design:

  * a global **platform admin** (the bootstrap principal — see docs/DESIGN.md §8)
  * two tenants: **Acme** (enterprise) and **Globex** (pooled)
  * org-unit trees per tenant
  * the global **permission catalog** (expense:*, payroll:*)
  * roles with **inheritance** (employee → manager → tenant_admin), plus
    payroll_admin and viewer
  * **ABAC policies**: expense approval (amount threshold + same org-unit +
    separation-of-duties) and payslip self-access
  * **global users with memberships** — notably one user (alice) who is
    `tenant_admin` in Acme **and** `viewer` in Globex (multi-tenant identity)
  * a few demo expenses/payslips so the UI and tests have data to act on

Run with the identity (BYPASSRLS) connection so it can write global tables and
every tenant's scoped rows in one pass. Safe to run repeatedly: every entity is
get-or-created by its natural key.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import cache
from .db import identity_session
from .models import (
    Membership,
    MembershipPermission,
    MembershipRole,
    OrgUnit,
    Permission,
    Policy,
    Role,
    RoleHierarchy,
    RolePermission,
    Tenant,
    User,
)
from .security import hash_password

# Business-service models live in their own packages; import so inserts work.
from services.expense.models import Expense  # noqa: E402
from services.payroll.models import Payslip  # noqa: E402

DEMO_PASSWORD = "password"          # every demo user
ADMIN_PASSWORD = "admin"            # the platform admin


# =========================================================================
# get-or-create helpers (idempotent by natural key)
# =========================================================================
def _get_or_create(session: Session, model, defaults: dict | None = None, **keys):
    instance = session.execute(
        select(model).filter_by(**keys)
    ).scalar_one_or_none()
    if instance is not None:
        return instance, False
    params = {**keys, **(defaults or {})}
    instance = model(**params)
    session.add(instance)
    session.flush()
    return instance, True


def _permission(session: Session, service: str, resource: str, action: str, desc: str) -> Permission:
    perm, _ = _get_or_create(
        session, Permission,
        defaults={"description": desc},
        service=service, resource=resource, action=action,
    )
    return perm


def _grant(session: Session, tenant_id, role: Role, perm: Permission) -> None:
    _get_or_create(
        session, RolePermission,
        defaults={"tenant_id": tenant_id},
        role_id=role.id, permission_id=perm.id,
    )


def _inherit(session: Session, tenant_id, parent: Role, child: Role) -> None:
    """parent inherits child's permissions (edge parent->child)."""
    _get_or_create(
        session, RoleHierarchy,
        defaults={"tenant_id": tenant_id},
        parent_role_id=parent.id, child_role_id=child.id,
    )


def _user(session: Session, email: str, password: str) -> User:
    user, created = _get_or_create(
        session, User,
        defaults={"password_hash": hash_password(password)},
        email=email,
    )
    return user


def _member(session: Session, tenant_id, user: User, org_unit: OrgUnit | None,
            roles: list[Role]) -> Membership:
    membership, _ = _get_or_create(
        session, Membership,
        defaults={"org_unit_id": org_unit.id if org_unit else None, "status": "active"},
        tenant_id=tenant_id, user_id=user.id,
    )
    for role in roles:
        _get_or_create(
            session, MembershipRole,
            defaults={"tenant_id": tenant_id},
            membership_id=membership.id, role_id=role.id,
        )
    return membership


def _grant_membership_perm(session: Session, tenant_id, membership: Membership,
                           perm: Permission) -> None:
    """Grant a permission DIRECTLY to a membership (per-user grant, idempotent)."""
    _get_or_create(
        session, MembershipPermission,
        defaults={"tenant_id": tenant_id},
        membership_id=membership.id, permission_id=perm.id,
    )


def _policy(session: Session, tenant_id, perm: Permission, name: str,
            condition: dict, effect: str = "allow") -> Policy:
    policy = session.execute(
        select(Policy).where(Policy.tenant_id == tenant_id, Policy.name == name)
    ).scalar_one_or_none()
    if policy is None:
        policy = Policy(tenant_id=tenant_id, permission_id=perm.id, name=name,
                        condition=condition, effect=effect)
        session.add(policy)
        session.flush()
    else:  # keep the condition current if the seed definition changed
        policy.condition = condition
        policy.effect = effect
        policy.permission_id = perm.id
    return policy


# =========================================================================
# Per-tenant standard role/policy set
# =========================================================================
def _seed_tenant_rbac(session: Session, tenant: Tenant, perms: dict[str, Permission]) -> dict[str, Role]:
    tid = tenant.id

    employee, _ = _get_or_create(session, Role, defaults={
        "description": "Base role: submit & view own expenses, read own payslip"},
        tenant_id=tid, name="employee")
    manager, _ = _get_or_create(session, Role, defaults={
        "description": "Approve expenses within policy limits"},
        tenant_id=tid, name="manager")
    tenant_admin, _ = _get_or_create(session, Role, defaults={
        "description": "Full administrative role within the tenant", "is_system": True},
        tenant_id=tid, name="tenant_admin")
    payroll_admin, _ = _get_or_create(session, Role, defaults={
        "description": "Manage payslips for all employees"},
        tenant_id=tid, name="payroll_admin")
    viewer, _ = _get_or_create(session, Role, defaults={
        "description": "Read-only access to expenses"},
        tenant_id=tid, name="viewer")

    # --- grants ---
    _grant(session, tid, employee, perms["expense:create"])
    _grant(session, tid, employee, perms["expense:read"])
    _grant(session, tid, employee, perms["payslip:read"])
    _grant(session, tid, manager, perms["expense:approve"])
    _grant(session, tid, payroll_admin, perms["payslip:create"])
    _grant(session, tid, payroll_admin, perms["payslip:read"])
    _grant(session, tid, viewer, perms["expense:read"])

    # --- hierarchy: manager inherits employee; tenant_admin inherits manager ---
    _inherit(session, tid, manager, employee)
    _inherit(session, tid, tenant_admin, manager)

    # --- ABAC policies ---
    # Expense approval: amount < 10000 AND same org-unit AND approver != creator.
    _policy(session, tid, perms["expense:approve"], "expense_approval_limit", {
        "all": [
            {"lt": ["resource.amount", 10000]},
            {"eq": ["resource.org_unit_id", "subject.org_unit_id"]},
            {"neq": ["resource.created_by", "subject.user_id"]},
        ]
    }, effect="allow")

    # Payslip read: your own, OR you are a payroll_admin.
    _policy(session, tid, perms["payslip:read"], "payslip_self_or_admin", {
        "any": [
            {"eq": ["resource.employee_user_id", "subject.user_id"]},
            {"contains": ["subject.roles", "payroll_admin"]},
        ]
    }, effect="allow")

    return {"employee": employee, "manager": manager, "tenant_admin": tenant_admin,
            "payroll_admin": payroll_admin, "viewer": viewer}


# =========================================================================
# Main
# =========================================================================
def main() -> None:
    with identity_session() as session:
        # --- global permission catalog ---
        perms = {
            "expense:create": _permission(session, "expense", "expense", "create", "Submit an expense"),
            "expense:read": _permission(session, "expense", "expense", "read", "View expenses"),
            "expense:approve": _permission(session, "expense", "expense", "approve", "Approve an expense"),
            "payslip:create": _permission(session, "payroll", "payslip", "create", "Create a payslip"),
            "payslip:read": _permission(session, "payroll", "payslip", "read", "Read a payslip"),
        }

        # --- platform admin (global identity) ---
        _user(session, "admin@platform.com", ADMIN_PASSWORD)

        # --- tenants ---
        acme, _ = _get_or_create(session, Tenant, defaults={"tier": "enterprise"}, name="Acme Corp")
        globex, _ = _get_or_create(session, Tenant, defaults={"tier": "pooled"}, name="Globex Inc")

        # --- org units ---
        acme_eng, _ = _get_or_create(session, OrgUnit, tenant_id=acme.id, name="Engineering")
        acme_sales, _ = _get_or_create(session, OrgUnit, tenant_id=acme.id, name="Sales")
        globex_eng, _ = _get_or_create(session, OrgUnit, tenant_id=globex.id, name="Engineering")

        # --- RBAC + ABAC per tenant ---
        acme_roles = _seed_tenant_rbac(session, acme, perms)
        globex_roles = _seed_tenant_rbac(session, globex, perms)

        # --- users ---
        alice = _user(session, "alice@acme.com", DEMO_PASSWORD)   # multi-tenant
        bob = _user(session, "bob@acme.com", DEMO_PASSWORD)
        carol = _user(session, "carol@acme.com", DEMO_PASSWORD)
        dave = _user(session, "dave@acme.com", DEMO_PASSWORD)
        peggy = _user(session, "peggy@acme.com", DEMO_PASSWORD)
        frank = _user(session, "frank@globex.com", DEMO_PASSWORD)

        # --- memberships (Acme) ---
        _member(session, acme.id, alice, acme_eng, [acme_roles["tenant_admin"]])
        bob_m = _member(session, acme.id, bob, acme_eng, [acme_roles["manager"]])
        carol_m = _member(session, acme.id, carol, acme_eng, [acme_roles["employee"]])
        dave_m = _member(session, acme.id, dave, acme_sales, [acme_roles["employee"]])
        _member(session, acme.id, peggy, None, [acme_roles["payroll_admin"]])

        # --- direct per-user grant (demo of membership_permissions) ---
        # carol is only an `employee`, but we grant her expense:approve DIRECTLY.
        # She can now approve — yet the expense_approval_limit ABAC policy still
        # blocks her OWN expense and over-limit amounts: a direct grant widens the
        # RBAC gate, ABAC deny/narrowing still applies on top (deny wins).
        _grant_membership_perm(session, acme.id, carol_m, perms["expense:approve"])

        # --- memberships (Globex) ---
        # alice is tenant_admin in Acme but only a viewer in Globex.
        _member(session, globex.id, alice, globex_eng, [globex_roles["viewer"]])
        _member(session, globex.id, frank, globex_eng, [globex_roles["tenant_admin"]])

        # --- a little demo business data (created directly; BYPASSRLS) ---
        if session.execute(select(Expense).where(Expense.tenant_id == acme.id)).first() is None:
            session.add_all([
                Expense(tenant_id=acme.id, org_unit_id=acme_eng.id, created_by=carol.id,
                        amount=5000, description="Team offsite lunch", status="submitted"),
                Expense(tenant_id=acme.id, org_unit_id=acme_eng.id, created_by=carol.id,
                        amount=50000, description="New servers (over limit)", status="submitted"),
                Expense(tenant_id=acme.id, org_unit_id=acme_sales.id, created_by=dave.id,
                        amount=3000, description="Client dinner (Sales)", status="submitted"),
            ])
        if session.execute(select(Payslip).where(Payslip.tenant_id == acme.id)).first() is None:
            session.add_all([
                Payslip(tenant_id=acme.id, employee_user_id=carol.id, org_unit_id=acme_eng.id,
                        period="2026-05", gross_amount=8000, net_amount=6200),
                Payslip(tenant_id=acme.id, employee_user_id=bob.id, org_unit_id=acme_eng.id,
                        period="2026-05", gross_amount=12000, net_amount=9100),
            ])

    # Bump each tenant's authz epoch so the PDP cache reflects the fresh model.
    for tid in (str(acme.id), str(globex.id)):
        try:
            cache.bump_tenant_version(tid)
        except Exception:  # Redis optional for a bare seed run
            pass

    print("[seed] demo data ready.")
    print(f"[seed]   Acme Corp   = {acme.id}")
    print(f"[seed]   Globex Inc  = {globex.id}")
    print("[seed] login (password for all demo users = 'password'):")
    print("[seed]   alice@acme.com   tenant_admin @ Acme, viewer @ Globex  (multi-tenant)")
    print("[seed]   bob@acme.com     manager @ Acme/Engineering")
    print("[seed]   carol@acme.com   employee @ Acme/Engineering (+ DIRECT expense:approve grant)")
    print("[seed]   dave@acme.com    employee @ Acme/Sales")
    print("[seed]   peggy@acme.com   payroll_admin @ Acme")
    print("[seed]   frank@globex.com tenant_admin @ Globex")
    print("[seed]   admin@platform.com / admin  (platform admin)")


if __name__ == "__main__":
    main()
