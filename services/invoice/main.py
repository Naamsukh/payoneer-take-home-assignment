"""Invoice Service — third sample microservice (RBAC + ABAC), proving the platform
generalises to new services with zero core changes.

Every access decision is delegated to the central PDP via the shared PEP, and all
business data is read/written through tenant_session() (RLS enforced) — identical
to expense/payroll. The only service-specific work is: register permissions
(`invoice:invoice:*`), import the PEP, and (optionally) attach ABAC policies.

Access patterns demonstrated:
  * create / read -> plain RBAC
  * issue         -> RBAC + ABAC: amount threshold, same org-unit, separation of
                     duties (issuer != creator)
"""
from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select

from libs.pep import PEP, Principal, get_principal
from services.common.db import tenant_session
from services.common.health import readiness

from .models import Invoice
from .schemas import InvoiceCreate, InvoiceOut

app = FastAPI(title="Invoice Service", version="1.0.0")
pep = PEP(service_name="invoice")

ACTION = "invoice:invoice:{}".format


def _to_out(i: Invoice) -> InvoiceOut:
    return InvoiceOut(
        id=i.id, customer=i.customer, amount=i.amount, status=i.status,
        created_by=i.created_by, org_unit_id=i.org_unit_id, issued_by=i.issued_by,
    )


@app.get("/healthz")
def healthz():
    """Liveness probe (process up). No auth, no I/O."""
    return {"status": "ok", "service": "invoice"}


@app.get("/readyz")
def readyz():
    """Readiness probe — verifies Postgres + Redis are reachable (503 if not)."""
    return readiness("invoice")


@app.post("/invoices", response_model=InvoiceOut)
def create_invoice(body: InvoiceCreate, principal: Principal = Depends(get_principal)):
    """Draft an invoice in the caller's tenant/org-unit.

    Plain RBAC (`invoice:invoice:create`) enforced at the PDP via the PEP; the row
    is written under tenant_session (RLS), stamped with the principal's tenant.
    Auth: a tenant-scoped access token granting the create permission.
    """
    pep.enforce(principal, ACTION("create"))
    with tenant_session(principal.tenant_id) as session:
        invoice = Invoice(
            tenant_id=uuid.UUID(principal.tenant_id),
            org_unit_id=uuid.UUID(principal.org_unit_id) if principal.org_unit_id else None,
            created_by=uuid.UUID(principal.user_id),
            customer=body.customer, amount=body.amount,
        )
        session.add(invoice)
        session.flush()
        return _to_out(invoice)


@app.get("/invoices", response_model=list[InvoiceOut])
def list_invoices(limit: int = 50, offset: int = 0,
                  principal: Principal = Depends(get_principal)):
    """List invoices in the caller's tenant (RBAC `invoice:invoice:read`).

    Results are physically limited to the tenant by RLS; `limit` is capped at 200.
    """
    pep.enforce(principal, ACTION("read"))
    with tenant_session(principal.tenant_id) as session:
        rows = session.execute(
            select(Invoice).order_by(Invoice.created_at.desc())
            .limit(min(max(limit, 1), 200)).offset(max(offset, 0))
        ).scalars().all()
        return [_to_out(i) for i in rows]


@app.get("/invoices/{invoice_id}", response_model=InvoiceOut)
def get_invoice(invoice_id: uuid.UUID, principal: Principal = Depends(get_principal)):
    """Fetch one invoice by id (404 if absent or in another tenant; RLS-scoped)."""
    pep.enforce(principal, ACTION("read"))
    with tenant_session(principal.tenant_id) as session:
        invoice = session.get(Invoice, invoice_id)
        if invoice is None:
            raise HTTPException(status_code=404, detail="invoice not found")
        return _to_out(invoice)


@app.post("/invoices/{invoice_id}/issue", response_model=InvoiceOut)
def issue_invoice(invoice_id: uuid.UUID, principal: Principal = Depends(get_principal)):
    """Issue an invoice — RBAC + ABAC.

    Loads the resource attributes (RLS-scoped), asks the PDP to enforce
    `invoice:invoice:issue` together with the attached ABAC policy (amount
    threshold, same org-unit, and separation of duties: issuer ≠ creator), then
    applies the state change.
    """
    with tenant_session(principal.tenant_id) as session:
        invoice = session.get(Invoice, invoice_id)
        if invoice is None:
            raise HTTPException(status_code=404, detail="invoice not found")
        resource = {
            "amount": invoice.amount,
            "org_unit_id": str(invoice.org_unit_id) if invoice.org_unit_id else None,
            "created_by": str(invoice.created_by),
            "status": invoice.status,
        }

    pep.enforce(principal, ACTION("issue"), resource=resource)

    with tenant_session(principal.tenant_id) as session:
        invoice = session.get(Invoice, invoice_id)
        invoice.status = "issued"
        invoice.issued_by = uuid.UUID(principal.user_id)
        return _to_out(invoice)
