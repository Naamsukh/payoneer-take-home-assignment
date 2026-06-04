"""Request/response models for the Payroll service."""
from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class PayslipCreate(BaseModel):
    employee_user_id: uuid.UUID
    period: str
    gross_amount: int = Field(gt=0)
    net_amount: int = Field(gt=0)
    org_unit_id: uuid.UUID | None = None


class PayslipOut(BaseModel):
    id: uuid.UUID
    employee_user_id: uuid.UUID
    period: str
    gross_amount: int
    net_amount: int
    org_unit_id: uuid.UUID | None
