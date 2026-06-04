"""Database engines and RLS-aware sessions.

Two logical connections back the application (see docs/DESIGN.md §9):

* ``tenant_session(tenant_id)`` — uses the ``app_user`` role for which Postgres
  Row-Level Security is ENFORCED. It sets ``app.current_tenant`` (transaction-local)
  so every query is physically constrained to one tenant. Used by the
  Authorization (PDP) service and the business services.

* ``identity_session()`` — uses the ``identity_user`` role which has BYPASSRLS.
  The Auth service is the identity authority and legitimately operates above
  tenant scope (global users, a user's memberships spanning many tenants).

Postgres ``SET`` cannot take bind parameters, so we use ``set_config(key, val, is_local=true)``
which is transaction-scoped and safely parameterised.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


_app_engine: Engine | None = None
_identity_engine: Engine | None = None


def app_engine() -> Engine:
    global _app_engine
    if _app_engine is None:
        _app_engine = create_engine(settings.APP_DATABASE_URL, pool_pre_ping=True, future=True)
    return _app_engine


def identity_engine() -> Engine:
    global _identity_engine
    if _identity_engine is None:
        _identity_engine = create_engine(settings.IDENTITY_DATABASE_URL, pool_pre_ping=True, future=True)
    return _identity_engine


@contextmanager
def tenant_session(tenant_id) -> Iterator[Session]:
    """RLS-enforced session bound to a single tenant.

    Sets ``app.current_tenant`` transaction-locally; RLS policies compare every
    row's ``tenant_id`` against it. Any query that would touch another tenant
    returns zero rows / is rejected at the database layer.
    """
    maker = sessionmaker(bind=app_engine(), expire_on_commit=False, future=True)
    session = maker()
    try:
        session.execute(
            text("SELECT set_config('app.current_tenant', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def app_session() -> Iterator[Session]:
    """app_user session with NO tenant context.

    Use only for GLOBAL (non-RLS) tables such as the ``permissions`` catalog.
    Any tenant-scoped table accessed here returns zero rows (secure default),
    which is intentional.
    """
    maker = sessionmaker(bind=app_engine(), expire_on_commit=False, future=True)
    session = maker()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def identity_session() -> Iterator[Session]:
    """BYPASSRLS session for the Auth service's cross-tenant identity operations."""
    maker = sessionmaker(bind=identity_engine(), expire_on_commit=False, future=True)
    session = maker()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
