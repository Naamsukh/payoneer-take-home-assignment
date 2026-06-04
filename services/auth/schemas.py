"""Request/response models for the Auth service."""
from __future__ import annotations

import uuid

from pydantic import BaseModel, EmailStr, Field


# --- Auth flow ---
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class MembershipSummary(BaseModel):
    tenant_id: uuid.UUID
    tenant_name: str
    membership_id: uuid.UUID
    status: str


class LoginResponse(BaseModel):
    identity_token: str
    user_id: uuid.UUID
    email: EmailStr
    memberships: list[MembershipSummary]


class SelectTenantRequest(BaseModel):
    tenant_id: uuid.UUID


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    tenant_id: uuid.UUID
    roles: list[str]


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str


# --- Management ---
class CreateTenantRequest(BaseModel):
    name: str
    tier: str = "pooled"


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    tier: str


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: uuid.UUID
    email: EmailStr
    status: str


class AddMemberRequest(BaseModel):
    user_id: uuid.UUID
    org_unit_id: uuid.UUID | None = None


class MemberOut(BaseModel):
    membership_id: uuid.UUID
    user_id: uuid.UUID
    email: EmailStr
    status: str
    org_unit_id: uuid.UUID | None
    roles: list[str]


class AssignRoleRequest(BaseModel):
    role_id: uuid.UUID
    scope_org_unit_id: uuid.UUID | None = None


class CreateOrgUnitRequest(BaseModel):
    name: str
    parent_id: uuid.UUID | None = None


class OrgUnitOut(BaseModel):
    id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None = Field(default=None)
