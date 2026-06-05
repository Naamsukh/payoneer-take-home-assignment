"""Central configuration, read from environment with sensible local defaults."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database connections (three roles — see docs/DESIGN.md §9)
    #   admin    : superuser, bootstrap only (schema, roles, RLS policies)
    #   app      : RLS ENFORCED, used by tenant-scoped services
    #   identity : BYPASSRLS, used only by the Auth service (identity authority)
    ADMIN_DATABASE_URL: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/acp"
    APP_DATABASE_URL: str = "postgresql+psycopg2://app_user:app_pass@localhost:5432/acp"
    IDENTITY_DATABASE_URL: str = "postgresql+psycopg2://identity_user:identity_pass@localhost:5432/acp"
    APP_DB_PASSWORD: str = "app_pass"
    IDENTITY_DB_PASSWORD: str = "identity_pass"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    JWT_SECRET: str = "dev-secret-change-me"
    JWT_ALG: str = "HS256"
    SERVICE_JWT_SECRET: str = "dev-service-secret-change-me"
    ACCESS_TTL_SECONDS: int = 900       # 15 min  — tenant-scoped access token
    IDENTITY_TTL_SECONDS: int = 600     # 10 min  — pre-tenant-selection identity token
    REFRESH_TTL_SECONDS: int = 604800   # 7 days

    # Authorization
    DECISION_CACHE_TTL: int = 15        # seconds — PDP decision cache TTL

    # Service discovery
    AUTH_URL: str = "http://localhost:8001"
    AUTHZ_URL: str = "http://localhost:8002"
    EXPENSE_URL: str = "http://localhost:8003"
    PAYROLL_URL: str = "http://localhost:8004"
    INVOICE_URL: str = "http://localhost:8005"


settings = Settings()
