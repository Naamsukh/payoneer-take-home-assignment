# Code Walkthrough & Deep Dive — Access Control Across Microservices

> A single document that explains **every file, every design decision, and every tradeoff** in this
> project. If you read this end-to-end you should be able to answer essentially any question about
> the service — what it does, why it's built this way, what was deliberately *not* done, and how it
> would evolve. It is the companion to [`DESIGN.md`](./DESIGN.md): `DESIGN.md` is the "what we
> propose"; this is the "what the code actually does, line by line, and why."

---

## Table of Contents

1. [The 60-second mental model](#1-the-60-second-mental-model)
2. [Where the architecture comes from (the inspirations)](#2-where-the-architecture-comes-from-the-inspirations)
3. [The vocabulary: PEP / PDP / PAP / PIP](#3-the-vocabulary-pep--pdp--pap--pip)
4. [A request, end to end](#4-a-request-end-to-end)
5. [The repository map](#5-the-repository-map)
6. [Shared foundation — `services/common`](#6-shared-foundation--servicescommon)
7. [The enforcement layer — `libs/pep`](#7-the-enforcement-layer--libspep)
8. [The brain — `services/authz` (PDP + PAP)](#8-the-brain--servicesauthz-pdp--pap)
9. [The identity authority — `services/auth`](#9-the-identity-authority--servicesauth)
10. [The business services — `expense` & `payroll`](#10-the-business-services--expense--payroll)
11. [The admin UI — `ui/`](#11-the-admin-ui--ui)
12. [Seeding, bootstrapping, and the test harness](#12-seeding-bootstrapping-and-the-test-harness)
13. [Infrastructure: Docker, Make, packaging](#13-infrastructure-docker-make-packaging)
14. [Deep dive: the decision algorithm](#14-deep-dive-the-decision-algorithm)
15. [Deep dive: multi-tenant isolation & RLS](#15-deep-dive-multi-tenant-isolation--rls)
16. [Deep dive: caching & invalidation](#16-deep-dive-caching--invalidation)
17. [Deep dive: the token & trust model](#17-deep-dive-the-token--trust-model)
18. [Why NOT these patterns — Zanzibar, OPA, and friends](#18-why-not-these-patterns--zanzibar-opa-and-friends)
19. [Known simplifications & honest gaps](#19-known-simplifications--honest-gaps)
20. [Quick reference tables](#20-quick-reference-tables)
21. [Likely interview questions & crisp answers](#21-likely-interview-questions--crisp-answers)

---

## 1. The 60-second mental model

The system answers one question, consistently, for every microservice:

> **"Can subject `S`, acting in tenant `T`, do action `A` on resource `R`, in environment `E`?"**

It does so by splitting the problem into two halves that are deliberately kept separate:

- **Authentication** (*who are you?*) — handled once, by the **Auth service**, encoded into a signed
  **JWT**. Slow-changing identity. Zero network calls on the hot path because it's in the token.
- **Authorization** (*are you allowed?*) — handled per request, by a central **Authorization service
  (PDP)**, because the answer depends on live resource attributes, dynamic policies, and must be
  revocable. It is made fast by a **Redis decision cache**.

Every business service stays "dumb": it imports a thin **PEP library**, which calls the PDP and
turns the verdict into `allow` (continue) or `deny` (HTTP 403). The decision logic lives in exactly
one place. A Postgres **Row-Level Security** layer underneath guarantees that even a bug can't leak
another tenant's data.

```
            ┌─────────── Auth service ──────────┐         identity, tokens, memberships
 login ───► │  global user → tenant-scoped JWT  │
            └───────────────────────────────────┘
                          │ JWT
                          ▼
   ┌──── Expense / Payroll service ────┐   POST /check   ┌──── Authz service (PDP) ────┐
   │  endpoint → PEP.enforce(...)  ────┼────────────────►│  RBAC + ABAC engine         │
   │  business logic (tenant_session)  │◄────────────────┤  decision cache + audit     │
   └──────────────┬────────────────────┘   allow/deny    └─────────────┬───────────────┘
                  │                                                     │
                  ▼                                                     ▼
         Postgres (RLS, tenant_id)  ◄───────────────────────────  Redis (cache, epoch, sessions)
```

---

## 2. Where the architecture comes from (the inspirations)

This is not an invented design — it is an assembly of four well-established industry patterns. Naming
them is the fastest way to understand *why* the pieces are shaped the way they are.

### 2.1 XACML's PEP/PDP/PAP/PIP separation (the backbone)
The split of **enforcement** (at each service) from **decision** (central) comes straight from the
**XACML** reference architecture (OASIS). We don't use XACML's XML policy language — we use a small
JSON DSL — but the *topology* is XACML's: a Policy Enforcement Point asks a Policy Decision Point,
which reads from a Policy Administration Point. This is the single most important inspiration; §3
defines the terms.

### 2.2 NIST RBAC + NIST ABAC (the access model)
- **RBAC** (NIST RBAC / ANSI INCITS 359) gives us roles, role→permission grants, and **role
  hierarchy** (inheritance). Coarse, cacheable, easy to administer.
- **ABAC** (NIST SP 800-162) gives us attribute-based policies: "allow approve *only if*
  `amount < 10000` AND same department AND approver ≠ creator." Fine-grained and dynamic.

We use them as a **hybrid**: *RBAC grants the capability; ABAC narrows it.* This is the standard
enterprise answer because pure RBAC suffers "role explosion" (you'd need a role per amount-threshold)
and pure ABAC is hard to audit ("who can do what?" becomes a policy-evaluation question).

### 2.3 The Slack / Atlassian / Google multi-tenant identity model
A **user is a global identity** that can belong to **many tenants**, with **different roles in each**.
This is exactly how Slack (one email, many workspaces), Atlassian, and Google Workspace work. The
implementation expresses it with a **`USER` ↔ `MEMBERSHIP` ↔ `TENANT`** triple: identity is global,
*participation* is per-tenant, and **roles attach to the membership, not the user**.

### 2.4 Google Zanzibar (the deliberately-not-chosen future)
**Zanzibar** (Google's global authorization system, and its OSS descendants OpenFGA / SpiceDB /
Ory Keto) is the state-of-the-art for **relationship-based access control (ReBAC)**. We explicitly
*did not* build it — §18 explains why in depth — but we name it as the documented scale-up path
because the permission catalog maps cleanly onto Zanzibar "relations."

---

## 3. The vocabulary: PEP / PDP / PAP / PIP

You will see these four acronyms everywhere. They are XACML terms:

| Term | Full name | In this codebase | One-line job |
|------|-----------|------------------|--------------|
| **PEP** | Policy **Enforcement** Point | `libs/pep` (imported by each service) | *Intercept* the request, ask the PDP, enforce the verdict (allow / 403). Thin. |
| **PDP** | Policy **Decision** Point | `services/authz` `POST /check` | *Compute* the decision: resolve RBAC, evaluate ABAC, return `{decision, reason}`. |
| **PAP** | Policy **Administration** Point | `services/authz` CRUD endpoints | *Manage* the rules: roles, permissions, policies (driven by the UI). |
| **PIP** | Policy **Information** Point | the calling service + the JWT | *Supply* attributes: the service loads the resource's attributes; the token supplies the subject's. |

The mental hook: **the PEP is the bouncer, the PDP is the rulebook-reader, the PAP is who edits the
rulebook, and the PIP is whoever hands over the IDs.** Enforcement is **distributed** (one bouncer
per door); decision-making is **centralized** (one rulebook). That's the sentence in
`libs/pep/__init__.py` you highlighted.

---

## 4. A request, end to end

Trace `POST /expenses/{id}/approve` — the richest path (RBAC **and** ABAC) — to see how all the
pieces interlock. (Code: `services/expense/main.py:75`.)

1. **Login (once).** Client `POST /auth/login` → Auth verifies the password (bcrypt) and returns an
   **identity token** plus the list of tenants the user belongs to. (`auth/main.py:132`)
2. **Select tenant (once).** Client `POST /auth/select-tenant {tenant_id}` → Auth re-verifies an
   **active membership**, loads that membership's roles, and issues a tenant-scoped **access token**
   `{sub, tenant_id, roles, org_unit_id, type:"access"}` + a refresh token. (`auth/main.py:159`,
   `_issue_session` at `:100`)
3. **Call the business endpoint.** Client `POST /expenses/{id}/approve` with `Authorization: Bearer
   <access token>`.
4. **Authenticate (PEP, declarative).** FastAPI runs `Depends(get_principal)` *before* the handler
   body. `get_principal` (`libs/pep/__init__.py:51`) validates the JWT, asserts `type=="access"` and
   a `tenant_id` is present, and builds a `Principal`. No token → 401; wrong token type → 403.
5. **Load resource attributes (PIP).** The handler opens a `tenant_session` (RLS-scoped) and reads
   the expense's `amount`, `org_unit_id`, `created_by`, `status` into a `resource` dict.
6. **Authorize (PEP → PDP).** `pep.enforce(principal, "expense:expense:approve", resource=resource)`.
   Internally (`PEP.decide`, `:78`) this mints a **service token** (`svc=expense`, separate secret),
   and `POST /check` to the Authz service with `{subject, action, resource, environment}`.
7. **Decide (PDP).** Authz `/check` (`authz/main.py:133`):
   - Computes a cache key from `(user, tenant, action, resource, tenant_epoch)` and checks Redis.
   - On a **hit**, returns the cached decision (`cached: true`).
   - On a **miss**, opens a `tenant_session` and runs `engine.decide(...)`: RBAC gate → ABAC deny →
     ABAC allow → default. Writes an **audit row**. Caches the result (TTL 15s). Returns it.
8. **Enforce the verdict (PEP).** Back in `enforce`: if `decision != "allow"`, raise **HTTP 403**
   with `{reason, decision_id}`. If the PDP was unreachable, raise **HTTP 503** — *fail-safe = deny*.
9. **Apply (business logic).** Only now does the handler set `status="approved"` and `approved_by`,
   inside another `tenant_session`.
10. **Audit & trace.** The decision is already persisted with a `decision_id`; the response carries
    the reason on a deny.

The sequence diagram in [`DESIGN.md` §8](./DESIGN.md#8-authentication--authorization-flow) renders
this visually.

---

## 5. The repository map

```
.
├── docker-compose.yml          # 8 services: postgres, redis, bootstrap, seed, auth, authz, expense, payroll, ui
├── Dockerfile                  # ONE image for all Python services; compose overrides `command`
├── Makefile                    # make up / down / e2e / seed / diagrams / ...
├── pyproject.toml              # deps (uv-managed); our code runs via PYTHONPATH, not installed
│
├── libs/
│   └── pep/__init__.py         # ★ the shared Policy Enforcement Point (Principal, get_principal, PEP)
│
├── services/
│   ├── common/                 # ★ the shared foundation every service imports
│   │   ├── config.py           #   pydantic-settings: all env-driven config
│   │   ├── db.py               #   3 session factories (tenant_session / app_session / identity_session)
│   │   ├── models.py           #   all SQLAlchemy ORM models (the data model)
│   │   ├── security.py         #   password hashing + 3 JWT token types
│   │   ├── cache.py            #   Redis: decision cache, tenant epoch, refresh sessions
│   │   ├── bootstrap.py        #   one-shot: roles, schema, grants, RLS policies
│   │   └── seed.py             #   one-shot: demo tenants/users/roles/policies/data
│   │
│   ├── auth/                   # Auth service — identity authority (NO authz decisions)
│   │   ├── main.py             #   login, select/switch-tenant, refresh, user/tenant/member/role mgmt
│   │   └── schemas.py          #   pydantic request/response models
│   │
│   ├── authz/                  # Authorization service — the PDP + PAP
│   │   ├── main.py             #   POST /check (PDP) + roles/permissions/policies/audit CRUD (PAP)
│   │   ├── engine.py           #   ★ RBAC resolution + ABAC DSL evaluator + the decide() algorithm
│   │   └── schemas.py          #   CheckRequest/Response, Create*/...Out models
│   │
│   ├── expense/                # Sample service — demonstrates ABAC (amount / dept / SoD)
│   │   ├── main.py             #   /expenses CRUD + approve, each guarded by pep.enforce
│   │   ├── models.py           #   Expense ORM model
│   │   └── schemas.py
│   │
│   └── payroll/                # Sample service — demonstrates sensitive-data + self-access + per-row
│       ├── main.py             #   /payslips, with per-row PDP filtering on list
│       ├── models.py           #   Payslip ORM model
│       └── schemas.py
│
├── ui/
│   ├── app.py                  # Streamlit admin console (7 pages incl. decision simulator)
│   └── api.py                  # thin HTTP client the UI uses to drive Auth + Authz
│
├── scripts/
│   └── e2e.py                  # end-to-end cross-service test (drives the real running services)
│
└── docs/
    ├── DESIGN.md               # the design document (what we propose + tradeoffs)
    ├── api-examples.md         # curl-able request/response examples
    ├── CODE-WALKTHROUGH.md     # ← you are here
    └── diagrams/               # rendered mermaid (architecture, sequence, ERD, ...)
```

**Two structural choices worth noting up front:**
- **One Docker image, many services.** The `Dockerfile` builds a single image; `docker-compose.yml`
  just changes the `command:` (`uvicorn services.auth.main:app`, `...authz.main:app`, …). Simpler to
  build/cache; in production you might split these.
- **Code is imported, not installed.** There is no build backend; `PYTHONPATH=/app` (set in the
  Dockerfile) makes `services.*`, `libs.*`, and `ui.*` importable. This is why `from libs.pep import
  PEP` and `from services.common.db import tenant_session` resolve everywhere.

---

## 6. Shared foundation — `services/common`

Everything depends on this package. Read it first.

### 6.1 `config.py` — one settings object
A single `pydantic-settings` `Settings` class reads from environment (with `.env` fallback and local
defaults). Key fields:
- **Three database URLs** (`ADMIN_`, `APP_`, `IDENTITY_DATABASE_URL`) — the heart of the isolation
  model (§15). `admin` = superuser (bootstrap only), `app` = RLS-enforced, `identity` = BYPASSRLS.
- **Two JWT secrets** (`JWT_SECRET` for user tokens, `SERVICE_JWT_SECRET` for service tokens) — so a
  leaked user token cannot forge a service identity (§17).
- **TTLs**: access 15 min, identity 10 min, refresh 7 days, **decision cache 15 s**.
- **Service-discovery URLs** (`AUTH_URL`, `AUTHZ_URL`, …) — defaults point at `localhost:800x`;
  compose overrides them with in-network hostnames (`http://authz:8000`).

Instantiated once as the module-level singleton `settings`.

### 6.2 `db.py` — three sessions, one RLS trick
Defines the SQLAlchemy `Base` and **two engines** (`app_engine`, `identity_engine`, lazily created,
`pool_pre_ping=True`). Then three context-manager sessions — this is the isolation model in code:

| Factory | DB role | RLS | Used by | Purpose |
|---------|---------|-----|---------|---------|
| `tenant_session(tenant_id)` | `app_user` | **ENFORCED** | authz, expense, payroll | Sets `app.current_tenant` → every query physically scoped to one tenant. |
| `app_session()` | `app_user` | enforced, but **no** tenant set | authz (permission catalog) | For **global** tables (`permissions`). Tenant tables return **zero rows** here — intentional secure default. |
| `identity_session()` | `identity_user` | **BYPASSRLS** | auth | The identity authority legitimately works across tenants (a user's memberships span many). |

The critical line is in `tenant_session`:
```python
session.execute(text("SELECT set_config('app.current_tenant', :tid, true)"), {"tid": str(tenant_id)})
```
Postgres `SET` can't take a bind parameter (SQL-injection-unsafe to interpolate), so it uses
`set_config(key, value, is_local=true)` — **transaction-local** and **safely parameterized**. RLS
policies then compare each row's `tenant_id` to this setting. The `is_local=true` ties the setting to
the transaction, so it never leaks across pooled connections.

### 6.3 `models.py` — the data model
All ORM models in one file. The tenancy split is the thing to internalize:

- **Global (no `tenant_id`, no RLS):** `Tenant`, `User`, `Permission`.
  - `User.email` is **globally unique** — one identity across all tenants.
  - `Permission` has a unique `(service, resource, action)` triple and a `key` property
    (`"expense:expense:approve"`). It's a **global catalog** so semantics are uniform across tenants.
- **Tenant-scoped (carry `tenant_id`, RLS-enforced):** `OrgUnit`, `Membership`, `Role`,
  `RolePermission`, `RoleHierarchy`, `MembershipRole`, `MembershipPermission`, `Policy`, `AuditLog`,
  plus the business tables `Expense`, `Payslip`.
- **The bridge:** `Membership` = `(user_id, tenant_id, org_unit_id, status)`, **unique per
  `(user, tenant)`**. Roles attach to the membership via `MembershipRole` — so the *same user* is
  `tenant_admin` in Acme and `viewer` in Globex. `status` (`invited|active|suspended`) is independent
  per tenant.
- **Role hierarchy:** `RoleHierarchy(parent_role_id, child_role_id)` — **parent inherits child's
  permissions**. Forms a DAG (`tenant_admin → manager → employee`).
- **Direct per-user grants:** `MembershipPermission(membership_id, permission_id)` — a permission
  attached **straight to a membership**, on top of its roles. The effective permission set at decision
  time is *role-derived (incl. inheritance) **∪** direct grants* (§14). It lets you give one user one
  extra permission **without minting a single-member role**; an ABAC **deny** policy still overrides it
  (deny wins), so a direct grant can only *widen* the RBAC gate, never escape a deny.
- **Note the duplicated `tenant_id`** on join tables (`role_permissions`, `membership_roles`, …):
  it's denormalized onto every tenant-scoped row precisely so the **single, uniform RLS policy**
  (`tenant_id = current_setting(...)`) applies to *every* table without special cases.
- `AuditLog` is **append-only** (enforced at the DB-grant level in bootstrap, not just by convention).

### 6.4 `security.py` — passwords and three token types
- **Passwords:** bcrypt via `passlib`. Defensive 72-byte truncation (bcrypt's hard limit).
- **JWTs:** HS256. `_encode` stamps `iat`, `exp`, and a random `jti`. Three issuers:
  - `issue_identity_token` — `{sub, email, type:"identity"}`, 10 min, `JWT_SECRET`. Only good for
    `/auth/select-tenant`, `/auth/switch-tenant`, `/auth/me`.
  - `issue_access_token` — `{sub, tenant_id, membership_id, roles, org_unit_id, type:"access"}`,
    15 min, `JWT_SECRET`. The workhorse.
  - `issue_service_token` — `{svc, type:"service"}`, `SERVICE_JWT_SECRET`. Service-to-service.
  - Decoders: `decode_user_token` (JWT_SECRET) and `decode_service_token` (SERVICE_JWT_SECRET).

  **Permissions are deliberately NOT in the token** — only stable identity + roles. Fine-grained
  permission/policy resolution happens at the PDP so it stays dynamic and revocable (§17, §18).

### 6.5 `cache.py` — Redis: decision cache, epoch, sessions
- **Decision cache.** `decision_key(...)` builds a deterministic `sha256` over
  `{subject, tenant, action, resource, version}` (canonical JSON, `sort_keys`). Stored at
  `decision:{tenant}:{digest}` with a 15 s TTL.
- **Tenant authz epoch.** `get_tenant_version` / `bump_tenant_version` maintain a per-tenant counter
  at `authzver:{tenant}`. This counter is part of the cache key. **Bumping it instantly invalidates
  *all* cached decisions for that tenant** — this is how a role/permission/policy edit takes effect
  immediately regardless of TTL (§16). Every PAP write in `authz/main.py` calls `bump_tenant_version`.
- **Refresh sessions.** `store/get/revoke_refresh` keep refresh tokens in Redis with a 7-day TTL;
  `revoke` is logout.

### 6.6 `bootstrap.py` — one-shot DB setup (idempotent)
Runs as the **superuser** before any service starts (the `bootstrap` compose container):
1. Creates the two app roles — `app_user` (`NOBYPASSRLS`, the whole point) and `identity_user`
   (`BYPASSRLS`). Idempotent via a `DO $$ ... pg_roles` guard.
2. `Base.metadata.create_all` — creates all tables (it imports the business models so their tables
   register too).
3. Grants privileges, then **`REVOKE UPDATE, DELETE ON audit_logs`** — making the audit log
   physically append-only.
4. **Installs RLS** on every tenant-scoped table — auto-detected as *"any table with a `tenant_id`
   column."* For each: `ENABLE` + **`FORCE`** Row-Level Security, then a `tenant_isolation` policy
   with both `USING` (reads) and `WITH CHECK` (writes):
   ```sql
   CREATE POLICY tenant_isolation ON <table>
     USING       (tenant_id = current_setting('app.current_tenant', true)::uuid)
     WITH CHECK  (tenant_id = current_setting('app.current_tenant', true)::uuid);
   ```
   `FORCE` matters: without it, the table *owner* bypasses RLS. The `, true` second arg to
   `current_setting` means "return NULL if unset" rather than erroring — so a session with no tenant
   context (e.g. `app_session`) simply sees **zero rows**, the secure default.

### 6.7 `seed.py` — the demo world (idempotent)
Builds a realistic dataset so the UI/tests have something to act on. Everything is get-or-created by
natural key, so it's safe to re-run. It creates:
- **Two tenants:** `Acme Corp` (enterprise) and `Globex Inc` (pooled).
- **The global permission catalog:** `expense:expense:{create,read,approve}`,
  `payroll:payslip:{create,read}`.
- **Roles with inheritance** per tenant: `employee` → `manager` → `tenant_admin`, plus
  `payroll_admin` and `viewer`.
- **Two ABAC policies** per tenant:
  - `expense_approval_limit` (allow): `amount < 10000` AND same org-unit AND `created_by ≠ user_id`.
  - `payslip_self_or_admin` (allow): own payslip OR you hold `payroll_admin`.
- **Users**, notably **`alice@acme.com`** who is `tenant_admin` in Acme **and** `viewer` in Globex —
  the multi-tenant identity proof.
- A few demo expenses/payslips (including a deliberately over-limit $50k expense to demo a deny).
- Finally bumps each tenant's authz epoch so the cache reflects the fresh model.

Demo logins (password `password`, admin `admin`): `alice/bob/carol/dave/peggy@acme.com`,
`frank@globex.com`, `admin@platform.com`.

---

## 7. The enforcement layer — `libs/pep`

The whole file is ~110 lines and exports three things. It's a *library*, shared by import (see §5).

- **`Principal`** — a dataclass: the authenticated, tenant-scoped caller (`user_id`, `tenant_id`,
  `roles`, `org_unit_id`, raw `claims`). `as_subject()` shapes the block sent to the PDP.
- **`get_principal(authorization)`** — a FastAPI **dependency**. It pulls the bearer token, calls
  `decode_user_token`, and asserts `type=="access"` and a `tenant_id` (else 401/403). Because it's a
  function parameter (`Depends(get_principal)`), a protected handler **physically cannot run** without
  a validated, tenant-scoped principal. That's how authentication is enforced *uniformly* — you can't
  forget it.
- **`PEP`** — the enforcement client, instantiated once per service with its `service_name`:
  - `decide(principal, action, resource, environment)` → mints a **service token**, `POST`s to the
    PDP's `/check`, returns the decision dict. **Does not raise on deny** — used for filtering.
  - `enforce(...)` → calls `decide`, and raises **HTTP 403** if the verdict isn't `allow`.
  - **Fail-safe:** if the PDP is unreachable or non-200, it raises **HTTP 503** — i.e. it *denies*.
    There is no code path where a PDP failure results in `allow`.

`decide` vs `enforce` is a real distinction: `approve` uses `enforce` (one resource, deny → 403);
`payroll` list uses `decide` per row to **filter** (deny → just omit the row).

---

## 8. The brain — `services/authz` (PDP + PAP)

`authz` is both the **PDP** (the `/check` decision endpoint) and the **PAP** (CRUD for roles,
permissions, policies — what the UI drives). `engine.py` is the pure logic; `main.py` is the HTTP/DB
wiring.

### 8.1 `main.py` — the endpoints
Auth dependencies model three trust levels:
- `require_access` — a tenant-scoped **user** access token (the building block).
- **`require_tenant_admin`** — `require_access` **plus** a `tenant_admin` role check. **Every PAP
  endpoint uses this** (create/edit roles, permissions, policies, direct grants, and even the reads).
  This closes the privilege-escalation gap: a *regular* member can no longer mutate the access model
  or self-grant a permission (`DESIGN.md` §13.1).
- `require_caller` — accepts **either** a service token (a PEP) **or** a user token (the UI
  simulator). Used by `/check`, so both real services and the UI can ask for decisions.
- `_bearer` — the shared "extract `Bearer <token>`" helper.
- `_audit_admin(...)` — writes every PAP/admin change to `audit_logs` with `decision="info"` (a
  forensic trail of *model changes*, distinct from authorization *decisions*).

Endpoints:
- **`POST /check`** (the PDP) — `authz/main.py:133`. Cache-key → Redis lookup → on miss
  `engine.decide` inside a `tenant_session` → write `AuditLog` → cache → return
  `{decision, reason, policy_id, decision_id, cached}`.
- **PAP — permission catalog** (`/permissions`, global, via `app_session`): get-or-create by triple.
- **PAP — roles** (`/roles`, `/roles/{id}`, `/roles/{id}/permissions`, `/roles/{id}/children`): create
  roles, grant/revoke permissions, add inheritance edges. Every write `bump_tenant_version`s + audits.
- **PAP — direct per-user grants** (`POST`/`GET`/`DELETE` `/memberships/{id}/permissions`): attach a
  catalog permission straight to a membership, on top of its roles. Idempotent, RLS-scoped (a
  membership in another tenant → 404), epoch-bumped, audited. Wired into `engine.decide` via
  `direct_permission_keys` (§8.2, §14).
- **PAP — policies** (`/policies`): create/update/delete ABAC policies. On create/update it
  **structurally validates** the condition by dry-running `engine.evaluate` against empty context —
  so a malformed DSL is a 400, not a runtime surprise. `version` increments on update.
- **`GET /audit`** — tenant-scoped audit query.

Two details worth knowing:
- The **`/check` audit row is written on the cache-miss path only** — i.e. it logs *decision
  computations*, not every request. Per-request volume logging is the PEP/gateway's job. (PAP changes
  are audited separately via `_audit_admin`.) This keeps the cache valuable without drowning the table.
- **`/check` scopes the tenant from the *token*, not blindly from the body** — and it constrains the
  subject by caller type: a **service** caller's subject is trusted as-is; a **`tenant_admin`** (UI
  simulator) may test an *arbitrary* subject but pinned to their own tenant (they already hold full
  power there, so it grants nothing new); a **regular user** has `user_id`/`roles`/`org_unit_id`
  **overwritten from their verified token**, so a member cannot fabricate a subject to probe or shape
  others' decisions (`authz/main.py:151-163`).

### 8.2 `engine.py` — RBAC + ABAC, no `eval`
Four parts:

1. **`evaluate(node, ctx)`** — the **safe JSON DSL** interpreter. A condition is a one-key dict.
   Operators: `all` (AND), `any` (OR), `not`, `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`, `contains`.
   `_resolve` decides operand types: a string whose first dotted segment is `subject` / `resource` /
   `environment` / `env` is an **attribute path** (walked out of `ctx`); anything else is a **literal**.
   An empty/`True` condition is unconditionally true. **No `eval`, no code execution** — policies are
   *data*, which is what makes them UI-editable, versioned, auditable, and injection-safe.
2. **`effective_permission_keys(session, role_names)`** — RBAC resolution. Loads the named roles, then
   walks the `role_hierarchy` DAG **downward** (parent → child closure) to gather all inherited roles,
   then returns the set of permission `key`s those roles grant. (Runs inside the RLS-scoped session,
   so it only ever sees this tenant's roles.)
3. **`direct_permission_keys(session, user_id)`** — resolves the subject's **direct per-user grants**
   (`membership_permissions`), located by `user_id` inside the RLS-scoped session. Returns an empty set
   if there are none. `decide` **unions** this with the role-derived set.
4. **`decide(...)`** — the algorithm (detailed in §14). Effective set = roles **∪** direct grants;
   then deny-by-default, explicit-deny-wins, allow-policies as additive constraints.

### 8.3 `schemas.py`
Pydantic models for the API. Note `Subject` has `model_config = ConfigDict(extra="allow")` — so
arbitrary ABAC attributes (e.g. `dept_id`) can ride along on the subject without a schema change.

---

## 9. The identity authority — `services/auth`

Owns identity and issues tokens; **makes no authorization decisions**. Runs entirely on
`identity_session()` (BYPASSRLS) because it legitimately operates above tenant scope.

- **`/auth/login`** — verify global credentials (bcrypt), return identity token + the user's
  memberships (so the client can pick a tenant).
- **`/auth/select-tenant` / `/auth/switch-tenant`** — both call `_issue_session`, which re-verifies an
  **active** membership for `(user, tenant)`, loads that membership's roles, mints an access token +
  refresh session. This is *the* security gate: a token is only ever issued for a tenant where the
  user has an active membership, re-checked every time.
- **`/auth/refresh`** — exchange a refresh token (looked up in Redis) for a new access token, after
  re-checking the membership is still active. **`/auth/logout`** revokes the refresh session.
- **`/auth/me`** — current identity + memberships.
- **Management** — `/tenants`, `/users` (global), `/tenants/{id}/members` (add member),
  `/memberships/{id}/roles` (assign/unassign), `/tenants/{id}/org-units`. These require
  **`require_tenant_admin`** (a tenant-scoped access token whose holder is a `tenant_admin`), and for
  endpoints that name a tenant in the path they additionally call **`_assert_tenant(claims, path_tid)`**
  so an admin of one tenant cannot act on another. Every change is written to the audit log via
  `_audit_admin`. (Remaining caveat: a true cross-tenant **platform admin** for global tenant/user
  *creation* is still future work — these are gated to `tenant_admin` for now to remove the
  any-member hole; see §19.)

The contrast to internalize: **Auth uses BYPASSRLS and enforces tenant correctness in application
code; the business services use RLS-enforced sessions and let Postgres be the backstop.** Auth has to,
because identity is inherently cross-tenant.

---

## 10. The business services — `expense` & `payroll`

Both are deliberately thin and near-identical in shape — proving the pattern generalizes. Each:
imports the PEP, instantiates `pep = PEP(service_name=...)`, defines an `ACTION` namespace, guards
every endpoint with `pep.enforce`/`pep.decide`, and reads/writes through `tenant_session`.

### 10.1 `expense` — demonstrates ABAC
- `create` → plain **RBAC** (`pep.enforce(principal, "expense:expense:create")`).
- `read` (list/get) → RBAC.
- **`approve`** → RBAC **+ ABAC**, the showcase. It loads the resource attributes first (PIP), then
  `enforce`s with that resource so the PDP can evaluate **amount threshold**, **same org-unit**, and
  **separation-of-duties** (`created_by ≠ user_id`). The handler is a clean three phases: *load → 
  enforce → apply*.

### 10.2 `payroll` — demonstrates sensitive-data + per-row authorization
- `create` → RBAC (`payroll_admin`).
- `get` → RBAC + **self-access ABAC**: an employee may read their *own* payslip; `payroll_admin` reads
  anyone's. Expressed as the `payslip_self_or_admin` allow-policy.
- **`list`** → **per-row authorization**: it loads all rows (RLS already scoped to the tenant), then
  calls `pep.decide` *per payslip* and returns only those that come back `allow`. So an employee's
  list shows only their own slip; a `payroll_admin`'s shows everyone's. This is the "filter by the
  PDP" pattern — correct, and made affordable by the decision cache (the N calls are cache hits after
  the first). A production system would push this down into a query for large N (§19).

`models.py`/`schemas.py` in each are unremarkable: an ORM table with `tenant_id` + domain columns, and
pydantic in/out models. The `tenant_id` column is what makes bootstrap auto-apply RLS to them.

---

## 11. The admin UI — `ui/`

A **Streamlit** console (`ui/app.py`, ~520 lines) that drives the whole system **through the public
APIs only** — it holds no business logic, behaves like any other client. `ui/api.py` is a thin
`requests` wrapper (`auth_*` / `authz_*` helpers, `ApiError` on non-2xx).

Seven pages: **Overview**, **Tenants & Users**, **Members & Roles** (org-units, add member, assign
roles), **Permissions** (the global catalog), **Roles & Policies** (grants, inheritance, ABAC policy
CRUD with a JSON editor), the **Decision Simulator**, and the **Audit Log** viewer.

The **Decision Simulator** is the highlight for an interview demo: it replays a `POST /check` for a
chosen member + action + resource and **explains the verdict** (`ALLOW`/`DENY` + reason) — letting an
admin test a policy *before* enabling it. This is the "explainable, change-safe authorization" story.

Served on host port **`:8510`** (container `:8000`).

---

## 12. Seeding, bootstrapping, and the test harness

- **`bootstrap.py`** (§6.6) and **`seed.py`** (§6.7) run as one-shot compose containers, gated by
  `depends_on` so `bootstrap` → `seed` → services come up in order.
- **`scripts/e2e.py`** is the proof. It drives the *real running services* over HTTP and asserts every
  access pattern: RBAC allow/deny, the three ABAC denies (amount / org-unit / SoD), payslip
  self-access + per-row filtering, **cross-tenant isolation** (an Acme expense id is invisible under a
  Globex token), the **same identity getting distinct per-tenant tokens/roles**, and the **decision
  cache** (second identical `/check` returns `cached: true`). Run with `make e2e`; exits non-zero on
  any failure. This is the single best file to read to confirm the system actually behaves as designed.

---

## 13. Infrastructure: Docker, Make, packaging

- **`Dockerfile`** — `python:3.12-slim`, uses **`uv`** for fast, locked installs
  (`uv sync --frozen --no-install-project`). One image, `PYTHONPATH=/app`. Deps install in a cached
  layer before app code is copied.
- **`docker-compose.yml`** — `postgres:16` and `redis:7` (with healthchecks), the one-shot
  `bootstrap`/`seed`, then `auth`/`authz`/`expense`/`payroll`/`ui`. A YAML anchor (`x-app-env`) shares
  the env block; `depends_on` enforces healthy-DB-then-bootstrap-then-service ordering. **Host ports:
  auth 8001, authz 8002, expense 8003, payroll 8004, ui 8510** (all container-internal `:8000`).
- **`Makefile`** — ergonomic targets: `up`, `down`, `reset` (wipe volumes), `e2e`, `seed`,
  `bootstrap`, `logs-<svc>`, `shell-<svc>`, `db-shell`, `redis-cli`, `diagrams`.
- **`pyproject.toml`** — pinned deps; **no build backend** (code runs via `PYTHONPATH`, hence
  `--no-install-project` in Docker). `make up` is the one command to run everything.

---

## 14. Deep dive: the decision algorithm

The full logic in `engine.decide` (`services/authz/engine.py`), in order. **Default is DENY.**

```
decide(subject, action, resource, env):
  1. granted = effective_permission_keys(subject.roles)      # RBAC closure over the role DAG
     if action not in granted:        return DENY("no_permission")          # ← RBAC gate
  2. perm = permission_for(action)
     if perm is None:                 return DENY("unknown_permission")
  3. policies = enabled policies attached to `perm` (this tenant)
  4. for p in deny_policies:                                                # ← explicit deny wins
        if evaluate(p.condition): return DENY(f"policy:{p.name}")
  5. if allow_policies exist:                                               # ← additive constraint
        for p in allow_policies:
            if evaluate(p.condition): return ALLOW(f"policy:{p.name}")
        return DENY("no_allow_policy_matched")
  6. return ALLOW("rbac")                                                   # RBAC baseline, no ABAC attached
```

**The semantics, stated precisely:**
- **RBAC grants the capability; ABAC narrows it.** If a permission has *no* policies, the RBAC grant
  alone allows (step 6).
- **ALLOW-policies are additive constraints:** if *any* allow-policy is attached to a permission, then
  *at least one* must match, otherwise deny (step 5). This avoids the trap where a single
  non-matching policy silently revokes a valid RBAC grant.
- **DENY-policies are subtractive and always win** (step 4) — checked before allow-policies.
- **Default deny** is the outer envelope; nothing is implicitly allowed.

**Why this order is the right one:** deny-overrides is the safe combining algorithm (a deny can never
be "out-voted"); checking RBAC first is cheap and short-circuits the common "you simply don't have
this permission" case before touching policies; and treating allow-policies as "at least one must
match" makes the model compose predictably as you add policies.

**Worked examples** (from the seed + e2e):
- *Carol (employee) submits an expense* → has `expense:create` → **ALLOW (rbac)**.
- *Dave (employee, no grant) tries to approve* → lacks `expense:approve` → **DENY (no_permission)**.
- *Bob (manager) approves Carol's $4k same-dept expense* → has the permission; policy
  `amount<10000 ∧ same-dept ∧ approver≠creator` matches → **ALLOW (policy:expense_approval_limit)**.
- *Bob approves a $50k expense* → policy fails on amount → **DENY**.
- *Bob approves a Sales expense* (he's Engineering) → fails same-dept → **DENY**.
- *Bob approves his own expense* → fails SoD → **DENY**.
- *Carol approves a colleague's $2.5k same-dept expense* → she's an `employee`, but holds
  `expense:approve` via a **direct grant** (`membership_permissions`, not a role); policy matches →
  **ALLOW**. *Carol approves her **own** expense* → still **DENY (SoD)**: a direct grant widens the
  RBAC gate but an ABAC **deny** overrides it.

---

## 15. Deep dive: multi-tenant isolation & RLS

**Strategy: shared database, shared schema, `tenant_id` discriminator + Postgres Row-Level Security.**
Defense in depth across three layers, so no single bug breaches the boundary:

1. **Token layer** — `tenant_id` is a *signed* JWT claim; `get_principal` binds every request to one
   tenant. A token is only ever issued for a tenant where the user has an active membership.
2. **Application layer** — every request runs inside `tenant_session(tenant_id)`, which sets
   `app.current_tenant`. Queries are written normally; the context does the scoping.
3. **Database layer (the backstop)** — RLS policies (`tenant_isolation`, installed by bootstrap with
   both `USING` and `WITH CHECK`, under `FORCE ROW LEVEL SECURITY`) make a forgotten `WHERE tenant_id`
   *physically* unable to return or write another tenant's rows.

**The three DB roles make this airtight:**
- `app_user` is **`NOBYPASSRLS`** — the business + PDP services can never see across tenants, by
  construction.
- `identity_user` is **`BYPASSRLS`** — *only* the Auth service, which must work cross-tenant for
  identity, and which enforces tenant correctness in code instead.
- `admin` (superuser) is used *only* by bootstrap to create roles/schema/RLS, never at runtime.

**Why not schema-per-tenant or DB-per-tenant?** Stronger *physical* isolation, but they don't scale
operationally to thousands of tenants (migrations across thousands of schemas, connection-pool
fan-out). RLS gives strong *logical* isolation at the right cost. And the design keeps a **tiered
upgrade path**: the `tenant.tier` field (`pooled` / `enterprise`) lets you silo a premium tenant onto
a dedicated DB later by just pointing its tenant context at a different connection — **no application
code change**.

**Multi-tenant users don't weaken any of this:** a user with memberships in many tenants still acts
under a token scoped to exactly one active tenant, and the RLS context is derived from that token.
Switching tenants requires a fresh token and a fresh membership check.

---

## 16. Deep dive: caching & invalidation

The cache is what turns a "network hop per authorization" into "p99 < 10 ms on hit."

- **Key:** `decision:{tenant}:sha256({subject, tenant, action, resource, epoch})`. Because the *full
  resource dict* is in the key, two checks differ if the resource attributes differ — correct for
  ABAC.
- **Value/TTL:** the decision JSON, 15 s TTL (`DECISION_CACHE_TTL`).
- **Invalidation via epoch, not eviction.** Each tenant has a counter `authzver:{tenant}`. It's part
  of every key. Any PAP write — grant a permission, add inheritance, create/edit/disable a policy,
  create a role — calls `bump_tenant_version`. Incrementing it changes the key namespace, so **every
  prior cached decision for that tenant is instantly orphaned** (and TTLs out). One `INCR` invalidates
  the whole tenant's cache — covering **RBAC changes too**, not just policy edits.

> **Implementation note / doc drift:** some prose in `DESIGN.md` describes the cache key as including
> `policy.version`. The *code* uses the stronger **per-tenant epoch** (`authzver:{tenant}`); the
> per-policy `version` column is kept only for history/optimistic-update. The epoch approach is
> strictly better because it also catches role/permission changes, not just edits to one policy.

**The revocation knob:** the 15 s TTL bounds how long a *role-assignment* change (which doesn't go
through the PAP `bump`) could be stale — a deliberate latency-vs-throughput tradeoff. Policy/role
*model* edits are effective immediately via the epoch. For emergencies, an explicit cache-bust is the
escape hatch.

---

## 17. Deep dive: the token & trust model

**Three token types, two secrets** (`security.py`, §6.4):

| Token | Signed with | TTL | Carries | Decoded by |
|-------|-------------|-----|---------|------------|
| identity | `JWT_SECRET` | 10 m | `sub`, `email` | `decode_user_token` |
| **access** | `JWT_SECRET` | 15 m | `sub`, `tenant_id`, `membership_id`, `roles`, `org_unit_id` | `decode_user_token` |
| **service** | `SERVICE_JWT_SECRET` | 15 m | `svc` | `decode_service_token` |

**Why two secrets:** user tokens and service tokens are signed with *different* keys, so a leaked
**user** token can't be replayed as a **service** identity calling `/check`, and vice-versa. On every
`/check`, there are **two identities**: the *service* (the caller, authenticated via the service
token) and the *user* (the subject, being authorized).

**Why permissions aren't in the token:** baking permissions into the JWT would be fast but **stale**
(can't revoke before expiry), **resource-blind** (ABAC needs the live resource attributes, unknown at
login), and **bloated**. So the token carries only slow-changing identity (`sub`, `tenant_id`,
`roles`); everything fine-grained is resolved at the PDP, where it stays dynamic, revocable, and
auditable.

**Production upgrades (documented, not built):** asymmetric signing with a JWKS endpoint + key
rotation (instead of a shared HS256 secret); **mTLS via a service mesh** (Istio/Linkerd) with
**SPIFFE/SPIRE** workload identities replacing service JWTs; network policies restricting who may call
the PDP.

---

## 18. Why NOT these patterns — Zanzibar, OPA, and friends

This is the section interviewers probe hardest. Each "no" is deliberate and defensible.

> 📄 For the long-form **Zanzibar vs XACML** comparison and the full rationale for choosing the
> XACML topology, see [`ZANZIBAR-VS-XACML.md`](./ZANZIBAR-VS-XACML.md).

### 18.1 Why not Google Zanzibar / ReBAC (OpenFGA, SpiceDB)?
**Zanzibar** models authorization as a graph of **relationship tuples** (`document:readme#viewer@user:anne`)
and answers "is there a path?" It's the gold standard for **deeply relational** authorization —
nested groups, resource sharing, "members of the parent folder can read the child," org charts.

We didn't use it because:
- **The problem doesn't need it (yet).** The assignment's own vocabulary is *roles, permissions,
  policies* — that's RBAC+ABAC, not relationship graphs. Our deepest relationship is **role
  inheritance**, which a small DAG walk handles cleanly. Modeling this as Zanzibar tuples would be
  using a distributed graph database to answer a question a `JOIN` already answers.
- **Operational cost vs a 2-day budget.** Running Zanzibar well means standing up a tuple store, a
  consistency protocol (Zanzibar's "zookies" / snapshot reads), and reverse-index maintenance.
  Self-hosting SpiceDB/OpenFGA is a service in its own right. That dwarfs the timebox and adds a hard
  new dependency on the hot path.
- **Auditability & admin UX.** Our "policies are data" model is directly **UI-manageable, versioned,
  and explainable** (the simulator shows *which* policy decided). A tuple graph is powerful but harder
  for an admin to reason about ("why can Anne see this?" becomes a graph-traversal explanation).
- **ABAC is awkward in pure ReBAC.** "amount < 10000" is an *attribute* predicate, not a
  *relationship*. Zanzibar-style systems bolt on caveats/conditions (OpenFGA conditions, SpiceDB
  caveats) to handle this — i.e. they reach back toward ABAC. We just *are* ABAC where ABAC fits.

**So Zanzibar is named as the explicit scale-up path** (`DESIGN.md` §17): when org graphs and
resource-sharing grow deep, migrate — the permission catalog maps cleanly onto relations. It's a
"right tool, wrong scale" decision, not a rejection.

### 18.2 Why not OPA / Rego (policy-as-code)?
**OPA** (Open Policy Agent) with **Rego** is battle-tested and flexible. But:
- It pushes authorization logic into **Rego files (code)**, while the assignment wants **dynamic,
  admin-managed** roles/policies. Our **JSON DSL keeps policies as *data*** — editable in the UI,
  versioned in the DB, audited, and changeable without a redeploy or a Rego bundle push.
- Rego is a full language → a **larger evaluation/attack surface** and a steeper operator learning
  curve. Our DSL is intentionally tiny (11 operators, no `eval`), which is *injection-safe by
  construction* and trivially explainable.
- The tradeoff is honest: OPA is more *expressive*. We chose *manageability + auditability* for this
  domain. (If expressiveness became the constraint, OPA's data API or a Rego escape hatch is a clean
  add.)

### 18.3 Why not permissions baked into the JWT?
Fast (no PDP call) but **stale** (no revocation before expiry), **resource-blind** (ABAC impossible),
and **bloated**. Disqualifying for an *access-control product* whose whole job is correct, revocable,
fine-grained decisions. We keep identity in the token and decisions at the PDP — then add a cache to
win back the latency (§16). (Detail in §17.)

### 18.4 Why not a pure central PDP (call it every time, no cache)?
Correct, but a network hop on *every* request and a hot-path **SPOF**. We keep its correctness and add
the **decision cache** + **fail-safe-deny** to remove the latency and the availability cliff.

### 18.5 Why not fully-distributed sidecars (OPA bundles per pod)?
Lowest latency, but **policy-propagation lag** (bundles ship on an interval → weaker revocation) and
heavier ops (a sidecar per pod). Our central-PDP-plus-15s-cache gets most of the latency win with
simpler, stronger consistency and one place to audit.

### 18.6 Why not schema-/DB-per-tenant?
Covered in §15: stronger physical isolation, but doesn't scale operationally to thousands of tenants.
RLS gives strong logical isolation now, with a `tier`-gated physical-silo upgrade for premium tenants
later — no code change.

---

## 19. Known simplifications & honest gaps

Being upfront about these is part of the design (most are called out in `DESIGN.md` §2 / §17). Good to
know before someone asks.

> **Recently hardened (no longer gaps):** (a) PAP and management endpoints are no longer authn-only —
> they require **`require_tenant_admin`** (+ `_assert_tenant` on path-tenant routes), so a regular
> member can't mutate the access model or self-grant a permission (`DESIGN.md` §13.1). (b) `/check`
> no longer trusts an arbitrary `subject` from a regular user — identity fields are **overwritten from
> the verified token**; only a same-tenant `tenant_admin` (the simulator) may test an arbitrary
> subject, and a service caller is trusted by design. (c) Admin/PAP changes are now **audited**
> (`_audit_admin`, `decision="info"`), not just authorization decisions.

The honest remaining gaps:

1. **No cross-tenant platform admin yet.** Global `POST /tenants` and `POST /users` are currently
   gated to `tenant_admin` (a pragmatic stop-gap to remove the any-member hole). A proper
   platform-level principal for cross-tenant create/list is future work (`DESIGN.md` §17).
2. **No API gateway in the repo.** The design assumes a gateway terminates TLS and pre-validates the
   JWT; here each service re-validates via the PEP. Fine for a reference impl; the gateway is "thin."
3. **Symmetric HS256 with a shared dev secret.** Production wants asymmetric signing + JWKS + rotation
   (§17). The secrets in compose are obviously `dev-secret-change-me`.
4. **Access tokens aren't individually revocable.** Only *refresh* sessions live in Redis; an access
   token is valid until its 15 min `exp`. Decision freshness (not token validity) is what the cache
   TTL governs. A real-time revocation bus (Redis pub/sub) is listed as future work.
5. **Payroll `list` does per-row PDP calls (N+1).** Correct and cache-amortized, but for large N you'd
   push the predicate into the query or batch the check. It's coded this way to *demonstrate* per-row
   authorization clearly.
6. **Four of seven services are designed, not coded.** Reporting/Workflow/Notification/Invoice are
   structurally identical (import the PEP, register permissions, attach policies). Two samples prove
   the cross-service story within the timebox.
7. **Org-unit ABAC is exact-match, not subtree.** `resource.org_unit_id == subject.org_unit_id`
   doesn't yet walk the org tree (a manager of a parent dept over a child dept). The `org_units`
   self-reference and `scope_org_unit_id` exist to support it; the policy DSL would need a `descendant`
   operator or the PIP would resolve the subtree.

---

## 20. Quick reference tables

### Services & ports
| Service | Host port | Container | Command |
|---------|-----------|-----------|---------|
| auth | 8001 | 8000 | `uvicorn services.auth.main:app` |
| authz (PDP/PAP) | 8002 | 8000 | `uvicorn services.authz.main:app` |
| expense | 8003 | 8000 | `uvicorn services.expense.main:app` |
| payroll | 8004 | 8000 | `uvicorn services.payroll.main:app` |
| ui (Streamlit) | 8510 | 8000 | `streamlit run ui/app.py` |
| postgres | 5432 | 5432 | — |
| redis | 6379 | 6379 | — |

### Key endpoints
| Service | Endpoint | Purpose |
|---------|----------|---------|
| auth | `POST /auth/login` | global identity → identity token + memberships |
| auth | `POST /auth/select-tenant` | active tenant → access + refresh token |
| authz | `POST /check` | **the decision** (RBAC + ABAC) — `require_caller` |
| authz | `/permissions` `/roles` `/policies` `/audit` | PAP CRUD + audit — `require_tenant_admin` |
| authz | `/memberships/{id}/permissions` (POST/GET/DELETE) | direct per-user grants — `require_tenant_admin` |
| expense | `POST /expenses`, `/expenses/{id}/approve` | RBAC, RBAC+ABAC |
| payroll | `/payslips`, `/payslips/{id}` | RBAC + self-access ABAC + per-row list |
| all | `GET /healthz` | liveness probe |

### Demo logins (password `password`; admin `admin`)
| User | Roles |
|------|-------|
| alice@acme.com | `tenant_admin` @ Acme **and** `viewer` @ Globex (multi-tenant) |
| bob@acme.com | `manager` @ Acme/Engineering |
| carol@acme.com | `employee` @ Acme/Engineering **+ direct `expense:approve` grant** |
| dave@acme.com | `employee` @ Acme/Sales |
| peggy@acme.com | `payroll_admin` @ Acme |
| frank@globex.com | `tenant_admin` @ Globex |
| admin@platform.com | platform admin |

### The ABAC DSL operators
`all` (AND) · `any` (OR) · `not` · `eq` · `neq` · `lt` · `lte` · `gt` · `gte` · `in` · `contains`.
Operands: a string starting `subject.`/`resource.`/`environment.`/`env.` is an attribute path; else a
literal.

### The three DB roles
| Role | RLS | Used by |
|------|-----|---------|
| `admin` (superuser) | n/a | bootstrap only |
| `app_user` | **enforced** (`NOBYPASSRLS`) | authz, expense, payroll |
| `identity_user` | **`BYPASSRLS`** | auth |

### Run it
```bash
make up      # build + start everything (bootstrap → seed → services)
make e2e     # run the cross-service access-control test
make logs    # tail logs ;  make reset  # wipe volumes + rebuild
# UI: http://localhost:8510   ·   docs: PDP on :8002, auth on :8001
```

---

## 21. Likely interview questions & crisp answers

**Q: Walk me through what happens when a manager approves an expense.**
→ §4. Login → select-tenant (access token) → `POST /approve` → PEP `get_principal` authenticates →
handler loads resource attrs → PEP mints a service token, `POST /check` → PDP: cache lookup, else
RBAC gate + ABAC (amount/dept/SoD) + audit + cache → 403 on deny, else apply.

**Q: How do you guarantee tenant isolation?**
→ Three layers (§15): signed `tenant_id` claim, `tenant_session` setting `app.current_tenant`, and
Postgres RLS with `FORCE` + `NOBYPASSRLS app_user`. A forgotten `WHERE` clause still returns zero
foreign rows. Auth is the one exception (BYPASSRLS) because identity is cross-tenant — and it enforces
correctness in code.

**Q: A user is in two tenants with different roles — how?**
→ Roles attach to the **membership**, not the user (§6.3). The token is scoped to one active tenant;
switching re-issues a token after re-checking an active membership. Proven by `alice` in the e2e test.

**Q: How is revocation handled? Isn't the cache stale?**
→ §16. Per-tenant epoch in the cache key → any role/permission/policy edit bumps it → instant
invalidation of the whole tenant's cached decisions. Role-*assignment* changes ride the 15 s TTL (the
latency/throughput knob); emergencies use an explicit cache-bust.

**Q: Why not Zanzibar / OPA?**
→ §18. Zanzibar is right for deep relationship graphs at scale — overkill for a roles+policies model
and too heavy for the timebox; named as the scale-up path. OPA pushes policy into Rego *code*; we keep
policy as *data* so it's UI-managed, versioned, auditable, and injection-safe.

**Q: What stops a service from making the wrong decision?**
→ It can't decide at all — decisions are centralized in the PDP (§3). Services only *enforce*. One
engine = identical semantics everywhere. And RLS is a second, independent backstop.

**Q: What happens if the PDP is down?**
→ Fail-safe = deny (§7). The PEP raises 503; no path yields `allow` on PDP failure. Cache hits still
serve, so a PDP blip doesn't take down the read path for already-seen decisions.

**Q: How does a new service onboard?**
→ Import the PEP, instantiate `PEP(service_name=...)`, register its permissions in the catalog, attach
policies. Zero changes to the core. That's the whole point of the PEP/PDP split.

**Q: Who can edit roles/policies — and what stops a member from granting themselves a permission?**
→ Every PAP and management endpoint requires **`require_tenant_admin`** (a tenant-scoped access token
*plus* the `tenant_admin` role), and path-tenant routes also assert the token's tenant matches the path
(`_assert_tenant`). So a regular member can't mutate the model or self-grant — that closed the
one-call self-escalation hole (`DESIGN.md` §13.1). Every admin change is audited (`decision="info"`).

**Q: How do you give one user one extra permission without a new role?**
→ A **direct per-user grant** (`membership_permissions`): `POST /memberships/{id}/permissions`. The
effective set at decision time is *roles ∪ direct grants* (`engine.direct_permission_keys`), so it only
**widens** the RBAC gate — an ABAC **deny** still overrides it (deny wins). The e2e `scenario_direct_grant`
proves both: Carol (an `employee`) can approve a colleague's expense via a direct grant, but still can't
approve her *own* (separation-of-duties deny).

**Q: Can a user spoof the `/check` subject to probe others' access?**
→ No. For a regular user, `/check` overwrites `user_id`/`roles`/`org_unit_id` from the verified token.
Only a same-tenant `tenant_admin` (the UI simulator) may test an arbitrary subject — and they already
hold full power in their tenant, so it grants nothing new. Service callers are trusted by design.

**Q: Where's the audit trail?**
→ `audit_logs`, append-only (UPDATE/DELETE revoked at the grant level). Two streams land here: the PDP
writes a row per decision *computation* (cache miss) with `decision_id`/reason/context; PAP/admin
changes write an `info` row via `_audit_admin`. The UI has a viewer.

---

*This document reflects the code as committed. If you change the decision algorithm (`engine.py`), the
cache key (`cache.py`), the token model (`security.py`), or the RLS setup (`bootstrap.py`), update the
corresponding deep-dive section here.*
