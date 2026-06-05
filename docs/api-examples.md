# API Examples

End-to-end `curl` walkthrough of the running stack. Assumes `make up` has started
the services with seeded demo data. Ports are the host mappings from
`docker-compose.yml` (Auth `8001`, Authz `8002`, Expense `8003`, Payroll `8004`).

Each interactive Swagger UI is also at `http://localhost:<port>/docs`.

Conventions below:
- `$ID` — the identity token (post-login, pre-tenant).
- `$TOK` — the tenant-scoped access token (after select-tenant).

---

## 1. Authentication & tenant selection

### Log in (global identity)
```bash
curl -s localhost:8001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@acme.com","password":"password"}'
```
```json
{
  "identity_token": "eyJhbGciOiJIUzI1NiIs...",
  "user_id": "0d6f...",
  "email": "alice@acme.com",
  "memberships": [
    {"tenant_id": "9a22...", "tenant_name": "Acme Corp",  "membership_id": "...", "status": "active"},
    {"tenant_id": "a920...", "tenant_name": "Globex Inc", "membership_id": "...", "status": "active"}
  ],

  // Login also AUTO-SCOPES to the primary (first-joined) active membership, so you
  // get a usable tenant-scoped token in one call — no select-tenant step needed.
  // For alice that is Acme Corp. (null only if the user has no active membership.)
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "xqf...",
  "active_tenant_id": "9a22...",
  "roles": ["tenant_admin"]
}
```

Use `access_token` directly. The `identity_token` still authorizes the pre-tenant
endpoints (`/auth/select-tenant`, `/auth/switch-tenant`, `/auth/me`); call
`/auth/switch-tenant` to act in a different tenant.

### (Optional) Select / switch to a specific tenant → tenant-scoped access token
```bash
curl -s localhost:8001/auth/select-tenant \
  -H "Authorization: Bearer $ID" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"9a22..."}'           # Acme Corp
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",   // carries user + ONE tenant_id + roles
  "refresh_token": "xqf...",
  "tenant_id": "9a22...",
  "roles": ["tenant_admin"]
}
```

### Switch tenant (same identity, different roles)
```bash
curl -s localhost:8001/auth/switch-tenant \
  -H "Authorization: Bearer $ID" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"a920..."}'           # Globex Inc → alice is only a "viewer" here
```

### Who am I
```bash
curl -s localhost:8001/auth/me -H "Authorization: Bearer $TOK"
```

### Refresh / logout
```bash
curl -s localhost:8001/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"xqf..."}'
curl -s localhost:8001/auth/logout  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"xqf..."}'
```

---

## 2. Identity & tenant management (Auth service)

```bash
# Create a tenant
curl -s localhost:8001/tenants -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"name":"Initech","tier":"pooled"}'

# Create a global user
curl -s localhost:8001/users -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"email":"grace@acme.com","password":"password"}'

# Add the user to a tenant (creates an active membership)
curl -s localhost:8001/tenants/$TENANT/members -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"user_id":"<user-uuid>","org_unit_id":"<ou-uuid>"}'

# Create an org unit
curl -s localhost:8001/tenants/$TENANT/org-units -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"name":"Finance"}'

# Assign a role to a membership (optionally scoped to an org unit)
curl -s localhost:8001/memberships/$MEMBERSHIP/roles -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"role_id":"<role-uuid>"}'

# List members of a tenant (with their roles)
curl -s localhost:8001/tenants/$TENANT/members -H "Authorization: Bearer $TOK"
```

---

## 3. The decision endpoint (Authz / PDP)

`POST /check` is what the PEP calls on every guarded request. It accepts either a
**service token** (from a microservice) or a **user access token** (the UI
simulator). Deny by default; explicit deny wins.

```bash
curl -s localhost:8002/check \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{
        "subject":  {"user_id":"<bob>","tenant_id":"9a22...","roles":["manager"],"org_unit_id":"<eng>"},
        "action":   "expense:expense:approve",
        "resource": {"amount":5000,"org_unit_id":"<eng>","created_by":"<carol>"},
        "environment": {}
      }'
```
```json
{ "decision":"allow", "reason":"policy:expense_approval_limit",
  "policy_id":"...", "decision_id":"dec-...", "cached":false }
```

Change `amount` to `50000`, or `org_unit_id` to a different unit, or set
`created_by` to the approver — each makes the ALLOW policy stop matching:
```json
{ "decision":"deny", "reason":"no_allow_policy_matched", "decision_id":"...", "cached":false }
```

A second identical call within the TTL returns `"cached": true`.

---

## 4. Policy administration (Authz / PAP)

```bash
# Permission catalog (global)
curl -s localhost:8002/permissions -H "Authorization: Bearer $TOK"
curl -s localhost:8002/permissions -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"service":"invoice","resource":"invoice","action":"void","description":"Void an invoice"}'

# Roles (tenant-scoped)
curl -s localhost:8002/roles -H "Authorization: Bearer $TOK"
curl -s localhost:8002/roles -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"name":"auditor","description":"read-only audit"}'
curl -s localhost:8002/roles/<role-uuid> -H "Authorization: Bearer $TOK"   # detail: effective perms + inheritance

# Grant a permission to a role
curl -s localhost:8002/roles/<role-uuid>/permissions -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"permission_id":"<perm-uuid>"}'

# Role inheritance: parent inherits child's permissions
curl -s localhost:8002/roles/<manager-uuid>/children -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"child_role_id":"<employee-uuid>"}'

# Direct per-user grant: attach a permission straight to a membership (on top of
# its roles). Effective set = roles ∪ direct grants; an ABAC deny still overrides.
curl -s localhost:8002/memberships/<membership-uuid>/permissions -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"permission_id":"<perm-uuid>"}'
curl -s localhost:8002/memberships/<membership-uuid>/permissions -H "Authorization: Bearer $TOK"   # list
curl -s -X DELETE localhost:8002/memberships/<membership-uuid>/permissions/<perm-uuid> \
  -H "Authorization: Bearer $TOK"   # revoke

# ABAC policies
curl -s localhost:8002/policies -H "Authorization: Bearer $TOK"
curl -s localhost:8002/policies -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{
        "permission_id":"<expense-approve-uuid>",
        "name":"expense_approval_limit",
        "effect":"allow",
        "condition":{"all":[
          {"lt":["resource.amount",10000]},
          {"eq":["resource.org_unit_id","subject.org_unit_id"]},
          {"neq":["resource.created_by","subject.user_id"]}
        ]}
      }'
curl -s -X PUT    localhost:8002/policies/<id> -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"enabled":false}'
curl -s -X DELETE localhost:8002/policies/<id> -H "Authorization: Bearer $TOK"
```

### Condition DSL
A safe, serializable boolean tree over `subject.*`, `resource.*`,
`environment.*` (no code execution):

| Operator | Form | Meaning |
|---|---|---|
| `all` / `any` / `not` | `{"all":[...]}` | AND / OR / NOT |
| `eq` / `neq` | `{"eq":[a,b]}` | equality |
| `lt`/`lte`/`gt`/`gte` | `{"lt":[a,b]}` | ordering (false if non-comparable) |
| `in` | `{"in":[a, b]}` | `a in b` |
| `contains` | `{"contains":[a, b]}` | `b in a` |

A string whose first dotted segment is `subject`/`resource`/`environment`/`env`
is resolved as an attribute path; anything else is a literal.

---

## 5. Business services (enforcement via the PEP)

### Expense — ABAC
```bash
# Employee submits an expense → RBAC allow
curl -s localhost:8003/expenses -H "Authorization: Bearer $CAROL" \
  -H 'Content-Type: application/json' -d '{"amount":4000,"description":"offsite lunch"}'

# Manager approves it → RBAC + ABAC (amount<10k, same dept, approver≠creator)
curl -s -X POST localhost:8003/expenses/<expense-id>/approve -H "Authorization: Bearer $BOB"

# A denied approval returns 403 with the reason:
# {"detail":{"error":"forbidden","action":"expense:expense:approve",
#            "reason":"no_allow_policy_matched","decision_id":"..."}}
```

### Payroll — sensitive-data RBAC + self-access
```bash
# payroll_admin creates a payslip
curl -s localhost:8004/payslips -H "Authorization: Bearer $PEGGY" \
  -H 'Content-Type: application/json' \
  -d '{"employee_user_id":"<carol>","period":"2026-06","gross_amount":8000,"net_amount":6200}'

# Employee reads their OWN payslip → allow; someone else's → 403
curl -s localhost:8004/payslips/<id> -H "Authorization: Bearer $CAROL"

# List is authorized per-row: an employee sees only their own payslips,
# a payroll_admin sees all.
curl -s localhost:8004/payslips -H "Authorization: Bearer $CAROL"
```

---

## 6. Audit log

Every decision computed by the PDP (on a cache miss) is recorded, tenant-scoped:

```bash
curl -s "localhost:8002/audit?limit=50" -H "Authorization: Bearer $TOK"
```
```json
[
  {"id":"...","actor_user_id":"<bob>","action":"expense:expense:approve",
   "decision":"allow","reason":"policy:expense_approval_limit",
   "context":{"resource":{...},"decision_id":"dec-..."},"created_at":"2026-06-04T..."}
]
```
