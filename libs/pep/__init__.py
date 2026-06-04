"""Policy Enforcement Point (PEP) — the thin enforcement layer each microservice imports.

Responsibilities (docs/DESIGN.md §5, §8):
  1. Validate the user's access JWT and enforce it is tenant-scoped.
  2. Expose the caller as a ``Principal`` (FastAPI dependency).
  3. ``enforce(...)`` -> call the central PDP ``/check`` with a SERVICE token,
     forwarding the user subject + the resource's attributes, and translate the
     decision into allow (return) / deny (HTTP 403).

Enforcement is distributed (here, per service); decision-making is centralized
(the PDP). The PDP owns the shared Redis decision cache, so this layer stays thin.
On PDP failure we **fail safe = deny** (secure default).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import Header, HTTPException

from services.common.config import settings
from services.common.security import decode_user_token, issue_service_token


@dataclass
class Principal:
    """The authenticated, tenant-scoped caller, derived from the access token."""
    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)
    org_unit_id: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)

    def as_subject(self) -> dict[str, Any]:
        """The subject block sent to the PDP (attributes available to ABAC)."""
        return {
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "roles": self.roles,
            "org_unit_id": self.org_unit_id,
        }


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization[7:]


def get_principal(authorization: str | None = Header(default=None)) -> Principal:
    """FastAPI dependency: validate the access token and return the Principal."""
    try:
        claims = decode_user_token(_bearer(authorization))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    if claims.get("type") != "access" or not claims.get("tenant_id"):
        raise HTTPException(status_code=403, detail="tenant-scoped access token required")
    return Principal(
        user_id=claims["sub"],
        tenant_id=claims["tenant_id"],
        roles=claims.get("roles", []) or [],
        org_unit_id=claims.get("org_unit_id"),
        claims=claims,
    )


class PEP:
    """Per-service enforcement client. Instantiate once with the service name."""

    def __init__(self, service_name: str, authz_url: str | None = None, timeout: float = 3.0):
        self.service_name = service_name
        self.authz_url = (authz_url or settings.AUTHZ_URL).rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def decide(self, principal: Principal, action: str,
               resource: dict | None = None, environment: dict | None = None) -> dict:
        """Ask the PDP for a decision. Returns the decision dict (does not raise on deny)."""
        body = {
            "subject": principal.as_subject(),
            "action": action,
            "resource": resource or {},
            "environment": environment or {},
        }
        headers = {"Authorization": f"Bearer {issue_service_token(self.service_name)}"}
        try:
            resp = self._client.post(f"{self.authz_url}/check", json=body, headers=headers)
        except httpx.HTTPError:
            # PDP unreachable -> fail safe = deny.
            raise HTTPException(status_code=503, detail="authorization service unavailable")
        if resp.status_code != 200:
            raise HTTPException(status_code=503, detail="authorization check failed")
        return resp.json()

    def enforce(self, principal: Principal, action: str,
                resource: dict | None = None, environment: dict | None = None) -> dict:
        """Enforce a permission: allow -> return decision; deny -> raise HTTP 403."""
        decision = self.decide(principal, action, resource, environment)
        if decision.get("decision") != "allow":
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "forbidden",
                    "action": action,
                    "reason": decision.get("reason"),
                    "decision_id": decision.get("decision_id"),
                },
            )
        return decision
