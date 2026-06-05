"""End-to-end cross-service access-control test.

Drives the *real* running services (auth → expense/payroll → PDP) over HTTP and
asserts every access pattern in the design behaves correctly:

  RBAC      — granted action allowed; ungranted action denied (no_permission)
  ABAC      — expense approval gated by amount threshold, same org-unit, and
              separation-of-duties (creator != approver)
  Direct    — a per-user membership_permissions grant widens the RBAC gate, yet
              an ABAC deny (separation-of-duties) still overrides it
  Sensitive — payslip self-access; payroll_admin sees all; per-row list filter
  Isolation — a tenant-scoped token cannot see another tenant's rows
  Cache     — the PDP returns a cached decision on the second identical check

Run it after `make up` (which seeds demo data):  `make e2e`
or against localhost ports with the services up:  `python -m scripts.e2e`

Exits non-zero if any assertion fails.
"""
from __future__ import annotations

import os
import sys

import httpx

AUTH = os.environ.get("AUTH_URL", "http://localhost:8001")
AUTHZ = os.environ.get("AUTHZ_URL", "http://localhost:8002")
EXPENSE = os.environ.get("EXPENSE_URL", "http://localhost:8003")
PAYROLL = os.environ.get("PAYROLL_URL", "http://localhost:8004")

PASSWORD = "password"

_passed = 0
_failed = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global _passed, _failed
    mark = "PASS" if ok else "FAIL"
    line = f"  [{mark}] {label}"
    if detail:
        line += f"  — {detail}"
    print(line)
    if ok:
        _passed += 1
    else:
        _failed += 1


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def login(email: str, password: str = PASSWORD) -> dict:
    r = httpx.post(f"{AUTH}/auth/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()


def access_token(email: str, tenant_name: str) -> tuple[str, str]:
    """Return (access_token, tenant_id) for `email` acting in `tenant_name`."""
    data = login(email)
    membership = next(m for m in data["memberships"] if m["tenant_name"] == tenant_name)
    tenant_id = membership["tenant_id"]
    r = httpx.post(
        f"{AUTH}/auth/select-tenant",
        json={"tenant_id": tenant_id},
        headers={"Authorization": f"Bearer {data['identity_token']}"},
    )
    r.raise_for_status()
    return r.json()["access_token"], tenant_id


def H(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# Domain helpers
# --------------------------------------------------------------------------
def create_expense(token: str, amount: int, desc: str) -> dict:
    r = httpx.post(f"{EXPENSE}/expenses",
                   json={"amount": amount, "description": desc}, headers=H(token))
    r.raise_for_status()
    return r.json()


def approve_expense(token: str, expense_id: str) -> httpx.Response:
    return httpx.post(f"{EXPENSE}/expenses/{expense_id}/approve", headers=H(token))


def create_payslip(token: str, employee_user_id: str, org_unit_id: str | None,
                   period: str, gross: int, net: int) -> dict:
    r = httpx.post(f"{PAYROLL}/payslips", json={
        "employee_user_id": employee_user_id, "org_unit_id": org_unit_id,
        "period": period, "gross_amount": gross, "net_amount": net,
    }, headers=H(token))
    r.raise_for_status()
    return r.json()


def reason_of(resp: httpx.Response) -> str:
    try:
        detail = resp.json().get("detail")
        if isinstance(detail, dict):
            return detail.get("reason", "")
        return str(detail)
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------
def scenario_rbac_abac_expense() -> None:
    print("\nExpense — RBAC + ABAC (amount / org-unit / separation-of-duties)")
    bob, _ = access_token("bob@acme.com", "Acme Corp")        # manager, Engineering
    carol, _ = access_token("carol@acme.com", "Acme Corp")    # employee, Engineering
    dave, _ = access_token("dave@acme.com", "Acme Corp")      # employee, Sales

    # RBAC: employee can create
    exp = create_expense(carol, 4000, "e2e small expense")
    check("employee creates expense (RBAC allow)", exp["status"] == "submitted")

    # RBAC: a pure employee (dave — no role grant, no direct grant) cannot approve.
    # (carol is NOT used here: she carries a direct expense:approve grant — see
    # scenario_direct_grant — so the no_permission case must use dave.)
    dave_own = create_expense(dave, 1500, "e2e dave own expense")
    r = approve_expense(dave, dave_own["id"])
    check("employee approve denied (RBAC no_permission)",
          r.status_code == 403 and reason_of(r) == "no_permission", reason_of(r))

    # ABAC allow: manager approves a small, same-dept, someone-else's expense
    r = approve_expense(bob, exp["id"])
    check("manager approves $4k same-dept (ABAC allow)",
          r.status_code == 200, f"http {r.status_code}")

    # ABAC deny — amount over threshold
    big = create_expense(carol, 50000, "e2e over-limit expense")
    r = approve_expense(bob, big["id"])
    check("manager approve $50k denied (ABAC amount)",
          r.status_code == 403, reason_of(r))

    # ABAC deny — different org-unit (dave is Sales, bob is Engineering)
    sales_exp = create_expense(dave, 3000, "e2e cross-dept expense")
    r = approve_expense(bob, sales_exp["id"])
    check("manager approve other-dept denied (ABAC org-unit)",
          r.status_code == 403, reason_of(r))

    # ABAC deny — separation of duties (bob approves his own)
    own = create_expense(bob, 2000, "e2e own expense")
    r = approve_expense(bob, own["id"])
    check("manager approve own expense denied (ABAC SoD)",
          r.status_code == 403, reason_of(r))


def scenario_direct_grant() -> None:
    print("\nDirect per-user grant — membership_permissions (∪ roles; ABAC deny still wins)")
    carol, _ = access_token("carol@acme.com", "Acme Corp")    # employee + DIRECT expense:approve
    bob, _ = access_token("bob@acme.com", "Acme Corp")        # manager, Engineering

    # carol holds expense:approve via a DIRECT grant (not a role). She approves a
    # same-dept colleague's small expense -> ALLOW (the grant widens the RBAC gate,
    # and the ABAC expense_approval_limit policy is satisfied).
    colleague_exp = create_expense(bob, 2500, "e2e colleague expense (Engineering)")
    r = approve_expense(carol, colleague_exp["id"])
    check("employee w/ direct grant approves colleague's $2.5k (grant + ABAC allow)",
          r.status_code == 200, f"http {r.status_code} {reason_of(r)}")

    # Deny still wins: approving her OWN expense fails separation-of-duties, even
    # though she now holds the permission directly (deny overrides the direct grant).
    own = create_expense(carol, 1000, "e2e own expense (direct-grant holder)")
    r = approve_expense(carol, own["id"])
    check("direct grant cannot override ABAC deny (SoD)",
          r.status_code == 403, reason_of(r))


def scenario_payroll_sensitive() -> None:
    print("\nPayroll — sensitive-data RBAC + self-access ABAC + per-row list")
    peggy, _ = access_token("peggy@acme.com", "Acme Corp")    # payroll_admin
    carol, _ = access_token("carol@acme.com", "Acme Corp")    # employee

    carol_id = login("carol@acme.com")["user_id"]
    bob_id = login("bob@acme.com")["user_id"]

    carol_slip = create_payslip(peggy, carol_id, None, "2026-06", 8000, 6200)
    bob_slip = create_payslip(peggy, bob_id, None, "2026-06", 12000, 9100)

    # self-access allow
    r = httpx.get(f"{PAYROLL}/payslips/{carol_slip['id']}", headers=H(carol))
    check("employee reads OWN payslip (ABAC self allow)", r.status_code == 200, f"http {r.status_code}")

    # other's payslip denied
    r = httpx.get(f"{PAYROLL}/payslips/{bob_slip['id']}", headers=H(carol))
    check("employee reads OTHER payslip denied (ABAC)", r.status_code == 403, reason_of(r))

    # payroll_admin reads anyone's
    r = httpx.get(f"{PAYROLL}/payslips/{carol_slip['id']}", headers=H(peggy))
    check("payroll_admin reads any payslip (ABAC admin allow)", r.status_code == 200, f"http {r.status_code}")

    # per-row list filtering
    carol_list = httpx.get(f"{PAYROLL}/payslips", headers=H(carol)).json()
    carol_emps = {p["employee_user_id"] for p in carol_list}
    check("list filtered for employee (only own rows)",
          carol_emps <= {carol_id}, f"sees {len(carol_emps)} employees")
    peggy_list = httpx.get(f"{PAYROLL}/payslips", headers=H(peggy)).json()
    check("list unfiltered for payroll_admin (sees others)",
          any(p["employee_user_id"] == bob_id for p in peggy_list))


def scenario_tenant_isolation() -> None:
    print("\nMulti-tenant — isolation + same user, different roles per tenant")
    alice_acme, acme_id = access_token("alice@acme.com", "Acme Corp")    # tenant_admin
    alice_globex, globex_id = access_token("alice@acme.com", "Globex Inc")  # viewer
    check("same identity gets distinct tenant tokens", acme_id != globex_id)

    # In Acme, alice (admin → inherits create) can create an expense.
    acme_exp = create_expense(alice_acme, 1000, "acme-only expense")

    # That Acme expense id is invisible under a Globex-scoped token (RLS).
    r = httpx.get(f"{EXPENSE}/expenses/{acme_exp['id']}", headers=H(alice_globex))
    check("cross-tenant row read denied/absent (isolation)",
          r.status_code in (403, 404), f"http {r.status_code}")

    # alice is only a viewer in Globex → cannot create there.
    r = httpx.post(f"{EXPENSE}/expenses", json={"amount": 100, "description": "x"},
                   headers=H(alice_globex))
    check("viewer role in other tenant cannot create (RBAC per-tenant)",
          r.status_code == 403, reason_of(r))


def scenario_cache() -> None:
    print("\nPDP — decision cache")
    alice_acme, tenant_id = access_token("alice@acme.com", "Acme Corp")
    user_id = login("alice@acme.com")["user_id"]
    # The PDP /check accepts a user access token (UI simulator path).
    body = {
        "subject": {"user_id": user_id, "tenant_id": tenant_id,
                    "roles": ["tenant_admin"], "org_unit_id": None},
        "action": "expense:expense:read",
        "resource": {}, "environment": {},
    }
    r1 = httpx.post(f"{AUTHZ}/check", json=body, headers=H(alice_acme)).json()
    r2 = httpx.post(f"{AUTHZ}/check", json=body, headers=H(alice_acme)).json()
    check("first check computed, second cached",
          r1.get("cached") is False and r2.get("cached") is True,
          f"{r1.get('cached')} -> {r2.get('cached')}")
    check("cached decision matches", r1["decision"] == r2["decision"] == "allow")


def main() -> int:
    print("=== End-to-end access-control test ===")
    scenario_rbac_abac_expense()
    scenario_direct_grant()
    scenario_payroll_sensitive()
    scenario_tenant_isolation()
    scenario_cache()
    print(f"\n=== {_passed} passed, {_failed} failed ===")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
