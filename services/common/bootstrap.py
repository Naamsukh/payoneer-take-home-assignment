"""One-shot database bootstrap (run by the `bootstrap` container before services start).

Runs as the Postgres superuser and:
  1. creates the two application roles:
       - app_user      (RLS ENFORCED)  -> authz / expense / payroll
       - identity_user (BYPASSRLS)      -> auth (identity authority)
  2. creates all tables (CREATE ... IF NOT EXISTS via SQLAlchemy metadata)
  3. grants privileges (audit_logs is append-only: SELECT/INSERT only)
  4. enables + FORCEs Row-Level Security and installs the tenant-isolation
     policy on every tenant-scoped table.

Idempotent: safe to run repeatedly.
"""
from __future__ import annotations

from sqlalchemy import create_engine, text

from .config import settings
from .db import Base


def _register_all_models() -> None:
    """Import every model module so all tables land on Base.metadata."""
    from . import models  # noqa: F401  (common: tenants, users, roles, policies, ...)
    try:
        from services.expense import models as _exp  # noqa: F401
        from services.payroll import models as _pay  # noqa: F401
        from services.invoice import models as _inv  # noqa: F401
    except ModuleNotFoundError:
        pass  # business services may not exist yet in early phases


def _tenant_scoped_tables() -> list[str]:
    """Any table carrying a tenant_id column is isolated by RLS (auto-detected)."""
    return [t.name for t in Base.metadata.sorted_tables if "tenant_id" in t.columns]


def _create_roles(conn) -> None:
    app_pw = settings.APP_DB_PASSWORD.replace("'", "''")
    id_pw = settings.IDENTITY_DB_PASSWORD.replace("'", "''")

    conn.execute(text(f"""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
                CREATE ROLE app_user LOGIN PASSWORD '{app_pw}';
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_user') THEN
                CREATE ROLE identity_user LOGIN PASSWORD '{id_pw}';
            END IF;
        END $$;
    """))
    # identity_user operates above tenant scope (global users, cross-tenant memberships).
    conn.execute(text("ALTER ROLE identity_user BYPASSRLS;"))
    # app_user must NOT bypass RLS — it is the whole point of tenant isolation.
    conn.execute(text("ALTER ROLE app_user NOBYPASSRLS;"))


def _grant_privileges(conn) -> None:
    conn.execute(text("GRANT USAGE ON SCHEMA public TO app_user, identity_user;"))
    conn.execute(text(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        "TO app_user, identity_user;"
    ))
    conn.execute(text(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user, identity_user;"
    ))
    # audit_logs is append-only — strip mutation rights.
    conn.execute(text("REVOKE UPDATE, DELETE ON audit_logs FROM app_user, identity_user;"))


def _install_rls(conn, tables: list[str]) -> None:
    for table in tables:
        conn.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"))
        conn.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {table};"))
        conn.execute(text(f"""
            CREATE POLICY tenant_isolation ON {table}
                USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
        """))


def main() -> None:
    _register_all_models()
    engine = create_engine(settings.ADMIN_DATABASE_URL, future=True)

    # Roles must exist before grants; run in their own autocommit block.
    with engine.connect() as conn:
        conn.execution_options(isolation_level="AUTOCOMMIT")
        _create_roles(conn)

    # Tables (idempotent).
    Base.metadata.create_all(engine)

    tenant_tables = _tenant_scoped_tables()
    with engine.begin() as conn:
        _grant_privileges(conn)
        _install_rls(conn, tenant_tables)

    print("[bootstrap] roles, schema, grants and RLS policies are in place.")
    print(f"[bootstrap] RLS enforced on: {', '.join(tenant_tables)}")


if __name__ == "__main__":
    main()
