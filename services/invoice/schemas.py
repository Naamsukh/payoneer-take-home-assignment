"""Request/response models for the Invoice service."""
from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class InvoiceCreate(BaseModel):
    customer: str = Field(min_length=1)
    amount: int = Field(gt=0)


class InvoiceOut(BaseModel):
    id: uuid.UUID
    customer: str
    amount: int
    status: str
    created_by: uuid.UUID
    org_unit_id: uuid.UUID | None
    issued_by: uuid.UUID | None
