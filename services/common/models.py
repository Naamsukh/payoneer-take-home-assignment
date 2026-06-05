"""SQLAlchemy ORM models for the Access Control Platform.

Tenancy model (docs/DESIGN.md §6.1, §7):
  * USER and PERMISSION are GLOBAL (no tenant_id, no RLS).
  * Everything else carries tenant_id and is protected by Postgres RLS.
  * MEMBERSHIP is the bridge: a user's participation in one tenant, carrying
    that tenant's roles (via membership_roles) and org-unit.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Tables whose rows are constrained by RLS to the active tenant are auto-detected
# at bootstrap time as "any table with a tenant_id column" (see bootstrap.py).


# =========================================================================
# Global (tenant-independent) entities
# =========================================================================
class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", server_default=text("'active'"))   # active|suspended
    tier: Mapped[str] = mapped_column(String(32), default="pooled", server_default=text("'pooled'"))      # pooled|enterprise
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())


class User(Base):
    """Global identity. Authentication is global; a user may belong to many tenants."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)  # GLOBALLY unique
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", server_default=text("'active'"))  # active|disabled
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())


class Permission(Base):
    """Global catalog of (service, resource, action). Tenants grant subsets via roles."""
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("service", "resource", "action", name="uq_permission_triple"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))

    @property
    def key(self) -> str:
        return f"{self.service}:{self.resource}:{self.action}"


# =========================================================================
# Tenant-scoped entities (RLS enforced)
# =========================================================================
class OrgUnit(Base):
    __tablename__ = "org_units"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("org_units.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)


class Membership(Base):
    """A user's participation in a tenant. Carries that tenant's org-unit + roles."""
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_membership_user_tenant"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    org_unit_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("org_units.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", server_default=text("'active'"))  # invited|active|suspended
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_role_tenant_name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class RolePermission(Base):
    """role -> permission grant (tenant_id duplicated for RLS)."""
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)


class RoleHierarchy(Base):
    """parent_role inherits child_role's permissions (DAG)."""
    __tablename__ = "role_hierarchy"
    __table_args__ = (UniqueConstraint("parent_role_id", "child_role_id", name="uq_role_hierarchy"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    parent_role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    child_role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)


class MembershipRole(Base):
    """role assigned to a membership (i.e. to a user within one tenant)."""
    __tablename__ = "membership_roles"
    __table_args__ = (UniqueConstraint("membership_id", "role_id", name="uq_membership_role"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    membership_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("memberships.id"), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    scope_org_unit_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class MembershipPermission(Base):
    """Permission granted DIRECTLY to a membership (a user within one tenant),
    in addition to whatever the membership's roles grant.

    This is the per-user grant path: the effective permission set at decision time
    is the UNION of role-derived permissions and these direct grants. ABAC deny
    policies still run afterwards and take priority, so a direct grant cannot
    override an explicit deny (docs/DESIGN.md §6).
    """
    __tablename__ = "membership_permissions"
    __table_args__ = (UniqueConstraint("membership_id", "permission_id", name="uq_membership_permission"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    membership_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("memberships.id"), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)


class Policy(Base):
    """ABAC policy: a JSON condition + effect attached to a permission."""
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    condition: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    effect: Mapped[str] = mapped_column(String(16), default="allow", server_default=text("'allow'"))  # allow|deny
    version: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())


class AuditLog(Base):
    """Append-only record of every authorization decision and admin change."""
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)   # service:resource:action or admin op
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # allow|deny|info
    reason: Mapped[str] = mapped_column(String(255), default="", server_default=text("''"))
    context: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now(), index=True)
