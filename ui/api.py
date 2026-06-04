"""Thin HTTP client the Streamlit admin UI uses to drive the Auth + Authz APIs.

The UI process makes *server-side* calls, so it targets the in-cluster service
hostnames (``http://auth:8000`` / ``http://authz:8000`` from docker-compose),
overridable via AUTH_URL / AUTHZ_URL for local runs.
"""
from __future__ import annotations

import os

import requests

AUTH_URL = os.environ.get("AUTH_URL", "http://localhost:8001")
AUTHZ_URL = os.environ.get("AUTHZ_URL", "http://localhost:8002")

TIMEOUT = 10


class ApiError(Exception):
    """A non-2xx response, carrying the server's status + detail."""

    def __init__(self, status: int, detail):
        self.status = status
        self.detail = detail
        super().__init__(f"HTTP {status}: {detail}")


def _request(method: str, base: str, path: str, token: str | None = None, **kw):
    headers = kw.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.request(method, f"{base}{path}", headers=headers, timeout=TIMEOUT, **kw)
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise ApiError(resp.status_code, detail)
    if resp.content:
        return resp.json()
    return None


# --- Auth service ---
def auth_get(path: str, token: str | None = None, **kw):
    return _request("GET", AUTH_URL, path, token, **kw)


def auth_post(path: str, token: str | None = None, **kw):
    return _request("POST", AUTH_URL, path, token, **kw)


def auth_delete(path: str, token: str | None = None, **kw):
    return _request("DELETE", AUTH_URL, path, token, **kw)


# --- Authz service (PDP/PAP) ---
def authz_get(path: str, token: str | None = None, **kw):
    return _request("GET", AUTHZ_URL, path, token, **kw)


def authz_post(path: str, token: str | None = None, **kw):
    return _request("POST", AUTHZ_URL, path, token, **kw)


def authz_put(path: str, token: str | None = None, **kw):
    return _request("PUT", AUTHZ_URL, path, token, **kw)


def authz_delete(path: str, token: str | None = None, **kw):
    return _request("DELETE", AUTHZ_URL, path, token, **kw)
