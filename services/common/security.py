"""Password hashing and JWT helpers.

Three token types (docs/DESIGN.md §8):
  * identity : issued at login, carries only the global user; authorizes
               only /auth/select-tenant, /auth/switch-tenant, /auth/me.
  * access   : tenant-scoped; carries user + ONE active tenant + roles.
  * service  : service-to-service identity (claim ``svc``); signed with a
               separate secret so business services can call the PDP.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from passlib.context import CryptContext

from .config import settings

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- Passwords ---
def hash_password(plain: str) -> str:
    # bcrypt has a 72-byte input limit; truncate defensively.
    return _pwd.hash(plain[:72])


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd.verify(plain[:72], hashed)
    except ValueError:
        return False


# --- JWTs ---
def _encode(claims: dict[str, Any], ttl: int, secret: str) -> str:
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + ttl, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, secret, algorithm=settings.JWT_ALG)


def _decode(token: str, secret: str) -> dict[str, Any]:
    return jwt.decode(token, secret, algorithms=[settings.JWT_ALG])


def issue_identity_token(user_id: str, email: str) -> str:
    return _encode({"sub": str(user_id), "email": email, "type": "identity"},
                   settings.IDENTITY_TTL_SECONDS, settings.JWT_SECRET)


def issue_access_token(user_id: str, tenant_id: str, membership_id: str,
                       roles: list[str], org_unit_id: str | None) -> str:
    return _encode(
        {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "membership_id": str(membership_id),
            "roles": roles,
            "org_unit_id": str(org_unit_id) if org_unit_id else None,
            "type": "access",
        },
        settings.ACCESS_TTL_SECONDS,
        settings.JWT_SECRET,
    )


def issue_service_token(service_name: str, audience: str = "authz") -> str:
    """Mint a service-to-service token.

    ``audience`` scopes the token to ONE intended recipient (default: the PDP).
    A token minted for the PDP cannot be replayed against a different service —
    a small but real hardening over a bare shared-secret JWT (the full upgrade is
    mTLS / SPIFFE workload identity, see docs/DESIGN.md §10).
    """
    return _encode({"svc": service_name, "type": "service", "aud": audience},
                   settings.ACCESS_TTL_SECONDS, settings.SERVICE_JWT_SECRET)


def decode_user_token(token: str) -> dict[str, Any]:
    """Decode an identity/access token (raises jwt exceptions on failure)."""
    return _decode(token, settings.JWT_SECRET)


def decode_service_token(token: str, audience: str = "authz") -> dict[str, Any]:
    """Decode + verify a service token, INCLUDING its intended audience.

    A service token whose ``aud`` is not ``audience`` is rejected, so the PDP only
    accepts tokens that were minted to call it.
    """
    return jwt.decode(token, settings.SERVICE_JWT_SECRET,
                      algorithms=[settings.JWT_ALG], audience=audience)
