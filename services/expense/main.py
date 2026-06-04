"""Expense Service — sample microservice showcasing ABAC enforcement.

Every access decision is delegated to the central PDP via the shared PEP.
Business data is read/written through tenant_session() (RLS enforced), so even
a bug here cannot cross tenants.

Interesting access patterns demonstrated:
  * create  -> plain RBAC (expense:expense:create)
  * approve -> RBAC + ABAC: amount threshold, same-org-unit, separation of duties
"""
from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select

from libs.pep import PEP, Principal, get_principal
from services.common.db import tenant_session

from .models import Expense
from .schemas import ExpenseCreate, ExpenseOut

app = FastAPI(title="Expense Service", version="1.0.0")
pep = PEP(service_name="expense")

ACTION = "expense:expense:{}".format


def _to_out(e: Expense) -> ExpenseOut:
    return ExpenseOut(
        id=e.id, amount=e.amount, description=e.description, status=e.status,
        created_by=e.created_by, org_unit_id=e.org_unit_id, approved_by=e.approved_by,
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "expense"}


@app.post("/expenses", response_model=ExpenseOut)
def create_expense(body: ExpenseCreate, principal: Principal = Depends(get_principal)):
    pep.enforce(principal, ACTION("create"))
    with tenant_session(principal.tenant_id) as session:
        expense = Expense(
            tenant_id=uuid.UUID(principal.tenant_id),
            org_unit_id=uuid.UUID(principal.org_unit_id) if principal.org_unit_id else None,
            created_by=uuid.UUID(principal.user_id),
            amount=body.amount, description=body.description,
        )
        session.add(expense)
        session.flush()
        return _to_out(expense)


@app.get("/expenses", response_model=list[ExpenseOut])
def list_expenses(principal: Principal = Depends(get_principal)):
    pep.enforce(principal, ACTION("read"))
    with tenant_session(principal.tenant_id) as session:
        rows = session.execute(select(Expense).order_by(Expense.created_at.desc())).scalars().all()
        return [_to_out(e) for e in rows]


@app.get("/expenses/{expense_id}", response_model=ExpenseOut)
def get_expense(expense_id: uuid.UUID, principal: Principal = Depends(get_principal)):
    pep.enforce(principal, ACTION("read"))
    with tenant_session(principal.tenant_id) as session:
        expense = session.get(Expense, expense_id)
        if expense is None:
            raise HTTPException(status_code=404, detail="expense not found")
        return _to_out(expense)


@app.post("/expenses/{expense_id}/approve", response_model=ExpenseOut)
def approve_expense(expense_id: uuid.UUID, principal: Principal = Depends(get_principal)):
    # 1) load resource attributes (RLS-scoped)
    with tenant_session(principal.tenant_id) as session:
        expense = session.get(Expense, expense_id)
        if expense is None:
            raise HTTPException(status_code=404, detail="expense not found")
        resource = {
            "amount": expense.amount,
            "org_unit_id": str(expense.org_unit_id) if expense.org_unit_id else None,
            "created_by": str(expense.created_by),
            "status": expense.status,
        }

    # 2) enforce RBAC + ABAC at the central PDP (amount / same-dept / separation-of-duties)
    pep.enforce(principal, ACTION("approve"), resource=resource)

    # 3) apply
    with tenant_session(principal.tenant_id) as session:
        expense = session.get(Expense, expense_id)
        expense.status = "approved"
        expense.approved_by = uuid.UUID(principal.user_id)
        return _to_out(expense)
