"""Redis helpers: PDP decision cache + refresh-session store."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import redis

from .config import settings

_client: redis.Redis | None = None


def client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _client


# --- Decision cache (docs/DESIGN.md §8, §12) ---
def decision_key(subject_id: str, tenant_id: str, action: str,
                 resource: dict[str, Any], policy_version: int) -> str:
    """Cache key includes policy_version so a policy edit invalidates instantly."""
    raw = json.dumps(
        {"s": subject_id, "t": tenant_id, "a": action, "r": resource, "v": policy_version},
        sort_keys=True, default=str,
    )
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"decision:{tenant_id}:{digest}"


def get_decision(key: str) -> dict[str, Any] | None:
    raw = client().get(key)
    return json.loads(raw) if raw else None


def set_decision(key: str, value: dict[str, Any], ttl: int | None = None) -> None:
    client().setex(key, ttl or settings.DECISION_CACHE_TTL, json.dumps(value, default=str))


# --- Tenant authz epoch ---
# Bumped on any role/permission/policy change in a tenant. Included in the
# decision cache key, so a single change invalidates ALL cached decisions for
# that tenant instantly (covers RBAC and ABAC changes, not just policy edits).
def get_tenant_version(tenant_id: str) -> int:
    raw = client().get(f"authzver:{tenant_id}")
    return int(raw) if raw else 0


def bump_tenant_version(tenant_id: str) -> int:
    return int(client().incr(f"authzver:{tenant_id}"))


# --- Refresh sessions ---
# The token handed to the client is a high-entropy secret; we store it HASHED at
# rest (the Redis key is sha256(token)), so a dump of Redis never exposes a usable
# refresh token. Lookup re-hashes the presented token — same pattern as a password
# hash. (docs/DESIGN.md §13)
def _refresh_key(session_id: str) -> str:
    return "refresh:" + hashlib.sha256(session_id.encode()).hexdigest()


def store_refresh(session_id: str, payload: dict[str, Any], ttl: int | None = None) -> None:
    client().setex(_refresh_key(session_id), ttl or settings.REFRESH_TTL_SECONDS,
                   json.dumps(payload, default=str))


def get_refresh(session_id: str) -> dict[str, Any] | None:
    raw = client().get(_refresh_key(session_id))
    return json.loads(raw) if raw else None


def revoke_refresh(session_id: str) -> None:
    client().delete(_refresh_key(session_id))
