"""Request/response models for the Authorization (PDP/PAP) service."""
from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


# --- Decision (PDP) ---
class Subject(BaseModel):
    model_config = ConfigDict(extra="allow")  # allow arbitrary ABAC attributes (dept_id, ...)
    user_id: str
    tenant_id: uuid.UUID
    roles: list[str] = Field(default_factory=list)
    org_unit_id: str | None = None


class CheckRequest(BaseModel):
    subject: Subject
    action: str                                  # "service:resource:action"
    resource: dict = Field(default_factory=dict)
    environment: dict = Field(default_factory=dict)


class CheckResponse(BaseModel):
    decision: str                                # allow | deny
    reason: str
    policy_id: str | None = None
    decision_id: str
    cached: bool = False


# --- Permission catalog (global) ---
class CreatePermission(BaseModel):
    service: str
    resource: str
    action: str
    description: str = ""


class PermissionOut(BaseModel):
    id: uuid.UUID
    service: str
    resource: str
    action: str
    key: str
    description: str


# --- Roles (PAP, tenant-scoped) ---
class CreateRole(BaseModel):
    name: str
    description: str = ""


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    is_system: bool


class GrantPermission(BaseModel):
    permission_id: uuid.UUID


class AddChildRole(BaseModel):
    child_role_id: uuid.UUID


class RoleDetail(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    permissions: list[str]
    inherits: list[str]


# --- Policies (ABAC, tenant-scoped) ---
class CreatePolicy(BaseModel):
    permission_id: uuid.UUID
    name: str
    condition: dict = Field(default_factory=dict)
    effect: str = "allow"                         # allow | deny


class UpdatePolicy(BaseModel):
    condition: dict | None = None
    effect: str | None = None
    enabled: bool | None = None


class PolicyOut(BaseModel):
    id: uuid.UUID
    permission_id: uuid.UUID
    name: str
    condition: dict
    effect: str
    version: int
    enabled: bool


# --- Audit ---
class AuditOut(BaseModel):
    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    action: str
    decision: str
    reason: str
    context: dict
    created_at: str
