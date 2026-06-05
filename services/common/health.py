"""Shared health helpers.

Two distinct probes (the standard liveness/readiness split):

* ``/healthz`` (liveness)  — "is the process up?" Cheap, no I/O. Each service
  returns its own static payload; used to decide whether to RESTART a pod.
* ``/readyz`` (readiness)  — "can it actually serve?" Probes Postgres + Redis and
  returns 503 if a hard dependency is unreachable; used to decide whether to send
  TRAFFIC. This closes the gap where a service with a dead DB still reported OK.
"""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import text

from . import cache
from .db import app_engine


def _probe_dependencies() -> dict[str, str]:
    """Return {dependency: "ok"|"down"} for Postgres and Redis (never raises)."""
    deps: dict[str, str] = {}
    try:
        with app_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        deps["postgres"] = "ok"
    except Exception:
        deps["postgres"] = "down"
    try:
        cache.client().ping()
        deps["redis"] = "ok"
    except Exception:
        deps["redis"] = "down"
    return deps


def readiness(service: str) -> dict:
    """Readiness payload; raises HTTP 503 (with the per-dependency detail) if any
    hard dependency is unreachable, so load balancers stop routing to this pod."""
    deps = _probe_dependencies()
    healthy = all(v == "ok" for v in deps.values())
    payload = {"status": "ready" if healthy else "not_ready",
               "service": service, "dependencies": deps}
    if not healthy:
        raise HTTPException(status_code=503, detail=payload)
    return payload
