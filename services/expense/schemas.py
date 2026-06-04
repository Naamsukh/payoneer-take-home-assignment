"""Request/response models for the Expense service."""
from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class ExpenseCreate(BaseModel):
    amount: int = Field(gt=0)
    description: str = ""


class ExpenseOut(BaseModel):
    id: uuid.UUID
    amount: int
    description: str
    status: str
    created_by: uuid.UUID
    org_unit_id: uuid.UUID | None
    approved_by: uuid.UUID | None
