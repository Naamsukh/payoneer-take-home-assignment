"""Payroll Service — sample microservice showcasing sensitive-data access control.

Demonstrates:
  * RBAC on a sensitive resource (only roles granted payroll:payslip:* get in)
  * Self-access ABAC: an employee may read their OWN payslip; payroll admins may
    read anyone's. Expressed as an allow-policy:
        any( eq[resource.employee_user_id, subject.user_id],
             contains[subject.roles, "payroll_admin"] )
  * Per-row authorization on list endpoints (filter via the PDP).
"""
from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select

from libs.pep import PEP, Principal, get_principal
from services.common.db import tenant_session

from .models import Payslip
from .schemas import PayslipCreate, PayslipOut

app = FastAPI(title="Payroll Service", version="1.0.0")
pep = PEP(service_name="payroll")

ACTION = "payroll:payslip:{}".format


def _to_out(p: Payslip) -> PayslipOut:
    return PayslipOut(
        id=p.id, employee_user_id=p.employee_user_id, period=p.period,
        gross_amount=p.gross_amount, net_amount=p.net_amount, org_unit_id=p.org_unit_id,
    )


def _resource(p: Payslip) -> dict:
    return {
        "employee_user_id": str(p.employee_user_id),
        "org_unit_id": str(p.org_unit_id) if p.org_unit_id else None,
        "period": p.period,
    }


@app.get("/healthz")
def healthz():
    """Liveness probe. No auth; returns the service identity."""
    return {"status": "ok", "service": "payroll"}


@app.post("/payslips", response_model=PayslipOut)
def create_payslip(body: PayslipCreate, principal: Principal = Depends(get_principal)):
    """Create a payslip for an employee in the caller's tenant.

    RBAC on a sensitive resource (`payroll:payslip:create`) at the PDP; written
    under tenant_session (RLS), stamped with the principal's tenant.
    Auth: a tenant-scoped access token granting the create permission.
    """
    pep.enforce(principal, ACTION("create"))
    with tenant_session(principal.tenant_id) as session:
        payslip = Payslip(
            tenant_id=uuid.UUID(principal.tenant_id),
            employee_user_id=body.employee_user_id,
            org_unit_id=body.org_unit_id,
            period=body.period, gross_amount=body.gross_amount, net_amount=body.net_amount,
        )
        session.add(payslip)
        session.flush()
        return _to_out(payslip)


@app.get("/payslips/{payslip_id}", response_model=PayslipOut)
def get_payslip(payslip_id: uuid.UUID, principal: Principal = Depends(get_principal)):
    """Read one payslip, enforcing self-access ABAC.

    Loads the payslip (RLS-scoped), then the PDP applies `payroll:payslip:read`
    plus the self-access policy: an employee may read only their OWN payslip, while
    a payroll_admin may read anyone's. Auth: a tenant-scoped access token.
    """
    with tenant_session(principal.tenant_id) as session:
        payslip = session.get(Payslip, payslip_id)
        if payslip is None:
            raise HTTPException(status_code=404, detail="payslip not found")
        resource = _resource(payslip)
        out = _to_out(payslip)
    # RBAC + self-access ABAC at the PDP
    pep.enforce(principal, ACTION("read"), resource=resource)
    return out


@app.get("/payslips", response_model=list[PayslipOut])
def list_payslips(principal: Principal = Depends(get_principal)):
    """List payslips with PER-ROW authorization.

    Loads the tenant's payslips (RLS-scoped), then asks the PDP for a decision per
    row and returns only those the principal may read (own payslip, or any for a
    payroll_admin). Auth: a tenant-scoped access token.
    """
    with tenant_session(principal.tenant_id) as session:
        rows = session.execute(select(Payslip).order_by(Payslip.period.desc())).scalars().all()
        payslips = [( _to_out(p), _resource(p)) for p in rows]
    visible = []
    for out, resource in payslips:
        decision = pep.decide(principal, ACTION("read"), resource=resource)
        if decision.get("decision") == "allow":
            visible.append(out)
    return visible
