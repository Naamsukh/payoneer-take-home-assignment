# Zanzibar vs XACML — and why this system follows XACML

> A focused design note comparing the two dominant authorization architectures —
> Google **Zanzibar** (ReBAC) and **XACML** (PDP/PEP + ABAC) — and explaining,
> concretely against this codebase, why we adopted the **XACML** topology.
>
> Companion reading: [`DESIGN.md §6`](./DESIGN.md#6-access-control-model-rbac--abac)
> (the access model), [`DESIGN.md §15.1`](./DESIGN.md#15-key-tradeoffs--alternatives-considered)
> (alternatives), and [`CODE-WALKTHROUGH.md §2 & §18`](./CODE-WALKTHROUGH.md) (inspirations and
> the "why not" section). This doc is the long-form version of that decision.

---

## 0. TL;DR

| | **XACML** (what we built) | **Zanzibar** (what we didn't) |
|---|---|---|
| Core question | *"Do the **attributes** of this subject/resource/environment satisfy the policy?"* | *"Is there a **relationship path** from this subject to this object?"* |
| Model | RBAC + **ABAC** (attributes & predicates) | **ReBAC** (relationship tuples in a graph) |
| Rule shape | Roles → permissions, + policy `{condition, effect}` as **data** | Tuples `object#relation@subject`, + a relation rewrite schema |
| Architecture | **PEP / PDP / PAP / PIP** separation | Centralized tuple store + check API (Leopard index, zookies) |
| Best at | Attribute predicates: `amount < 10000`, same-dept, separation-of-duties | Deep relationship graphs: nested groups, folder→file inheritance, sharing |
| Consistency | Read-your-writes via cache epoch (our `authzver` bump) | Snapshot tokens ("zookies") for global external consistency |
| Operational cost | A service + Postgres + Redis (already in the stack) | A new distributed system (tuple store, reverse indexes, consistency protocol) |
| **Our verdict** | **Chosen** — fits the problem's *roles/permissions/policies* vocabulary | **Deferred** — named as the explicit scale-up path |

**One sentence:** the assignment's own vocabulary is *roles, permissions, and policies* — that is
RBAC + ABAC, which is precisely what XACML's architecture is built to serve; Zanzibar solves a harder
problem (deep relationship graphs) that this system does not have **yet**.

> ⚠️ Precision note: we adopt XACML's **reference architecture and ABAC model**, *not* its verbose
> XML policy language. Policies here are a small, safe **JSON DSL** (see
> [`services/authz/engine.py`](../services/authz/engine.py)). When this doc says "XACML," it means
> *the PEP/PDP/PAP/PIP topology + attribute-based decisioning* — the part that is industry canon —
> not OASIS XML syntax.

---

## 1. The two models, properly

### 1.1 XACML — attribute-based, decision-as-a-function

XACML (OASIS) frames authorization as a **pure function of attributes**:

```
decision = f(subject_attrs, action, resource_attrs, environment_attrs)  ->  allow | deny
```

Its lasting contribution is an **architectural decomposition** — the four roles you see throughout
this codebase:

| Role | Job | In this repo |
|---|---|---|
| **PEP** — Policy Enforcement Point | Intercept the request, ask, enforce the verdict | `libs/pep` (imported by each service) |
| **PDP** — Policy Decision Point | Compute the decision (RBAC + ABAC) | `services/authz` `POST /check` ([`main.py:98`](../services/authz/main.py)) |
| **PAP** — Policy Administration Point | Manage roles/permissions/policies | `services/authz` CRUD (driven by the Streamlit UI) |
| **PIP** — Policy Information Point | Supply attributes | the calling service (resource attrs) + the JWT (subject attrs) |

The decision logic lives in [`services/authz/engine.py`](../services/authz/engine.py) `decide()`:
RBAC first (is the action in the subject's effective permissions?), then ABAC (do the attached
policy conditions hold?), with **explicit-deny-wins** and **default-deny**.

### 1.2 Zanzibar — relationship-based, decision-as-graph-reachability

Zanzibar (Google's planet-scale authZ system; OSS descendants **OpenFGA**, **SpiceDB**, **Ory Keto**)
frames authorization as **graph reachability over relationship tuples**:

```
tuple:   object#relation@subject          e.g.  document:readme#viewer@user:anne
check:   "is there a path from <subject> to <object> via <relation>?"
```

Power comes from **relation rewrites**: `viewer` of a document can be defined as *"anyone who is a
`viewer` of its parent folder, OR a member of a group that is a viewer, OR …"* — so a single check
can traverse nested groups and inherited permissions across an arbitrarily deep graph. To make this
fast and consistent at scale, Zanzibar adds a **reverse index** (Leopard) and **snapshot tokens**
("zookies") for external consistency.

---

## 2. Side-by-side on the axes that decided it

### 2.1 Does the rule express an *attribute* or a *relationship*?

This is the crux. Look at a real rule this system must enforce
([`DESIGN.md §6`](./DESIGN.md#6-access-control-model-rbac--abac), and the Expense service):

```json
{ "all": [
    { "lt":  ["resource.amount", 10000] },
    { "eq":  ["resource.dept_id", "subject.dept_id"] },
    { "neq": ["resource.created_by", "subject.user_id"] }
]}
```

- `amount < 10000` is an **attribute predicate**. There is no "relationship" between a user and the
  number 10,000. In ABAC/XACML this is the *native* shape. In Zanzibar it is foreign — pure ReBAC has
  no notion of a numeric comparison, so the implementations **bolt on** "caveats" (SpiceDB) or
  "conditions" (OpenFGA) — i.e. they reach back toward ABAC to express exactly this.
- "approver ≠ creator" (separation of duties) and "same department" are likewise attribute
  comparisons, not graph edges.

**Our deepest *relationship* is role inheritance** (`manager` inherits `employee`) — a DAG. That is
handled by a small transitive-closure walk in
[`engine.py:effective_permission_keys`](../services/authz/engine.py) (a `JOIN` + BFS over
`role_hierarchy`). Modeling this as Zanzibar tuples would be standing up a distributed graph database
to answer a question a single `JOIN` already answers.

> **Rule of thumb:** if your hardest rules read like *"X relates to Y through a chain of groups/
> folders/shares,"* you want Zanzibar. If they read like *"X is allowed when these field values
> hold,"* you want XACML/ABAC. Ours are overwhelmingly the latter.

### 2.2 Policies as **data** vs the rule-engine surface

Our policies are **rows in Postgres**, edited live in the admin UI, versioned, and **explainable**:
the decision simulator shows *which* policy decided (`reason = "policy:<name>"`, see
[`engine.py:174`](../services/authz/engine.py)). The condition language is an intentionally tiny,
serializable JSON DSL — **11 operators, no `eval`/`exec`** — so it is *injection-safe by construction*
and trivially auditable.

Zanzibar's schema + tuples are also data, but answering *"why can Anne see this?"* becomes a
**graph-traversal explanation** rather than "this one policy row, this one role grant." For an
enterprise admin reasoning about access, "which policy fired" is a much easier mental model than
"trace the path through the tuple graph."

### 2.3 Multi-tenant fit

This platform pins **exactly one tenant per request** — the access token is tenant-scoped, and
Postgres **Row-Level Security** physically constrains every query to that tenant
([`DESIGN.md §9`](./DESIGN.md#9-multi-tenant-isolation-strategy)). The XACML model slots into this
perfectly: the PDP runs inside an RLS-enforced `tenant_session`, so it *cannot* see another tenant's
roles/permissions/policies. Tenant isolation is a database invariant, independent of the policy logic.

A global Zanzibar tuple store cuts *across* this grain — isolation would have to be re-expressed and
re-enforced inside the tuple namespace/relation design, duplicating an invariant Postgres already
gives us for free.

### 2.4 Consistency & caching

Zanzibar's headline feature is **external consistency via zookies** — snapshot tokens that prevent
the "new-enemy" problem (seeing stale ACLs after a revoke) at global scale.

We solve the analogous problem far more cheaply because our scope is one tenant: a per-tenant
**version epoch** (`authzver:{tenant_id}`) is folded into the decision-cache key, so any
role/permission/policy change **`INCR`s the epoch and invalidates the whole tenant's cached decisions
instantly**, with a 15s TTL backstop (see [`services/common/cache.py`](../services/common/cache.py)).
That is read-your-writes consistency without a distributed snapshot protocol — appropriate to the
scale, and impossible to justify replacing with zookies on a 2-day budget.

### 2.5 Operational cost

| | XACML-style (ours) | Zanzibar-style |
|---|---|---|
| New infra | None — reuses Postgres + Redis already in the stack | A tuple store, reverse-index (Leopard), consistency protocol |
| Hot-path dependency | Same DB as the rest of the app | A new distributed system on the critical path |
| Self-hosting | n/a | Running SpiceDB/OpenFGA well is a service in its own right |
| Fit to timebox | Built in the 2-day budget | Dwarfs the timebox |

---

## 3. Why we chose XACML — the decision, condensed

1. **The problem is RBAC + ABAC, by its own vocabulary.** The assignment speaks in *roles,
   permissions, policies, conditions, effects* — the exact nouns XACML's architecture and the
   ABAC model are built around. We matched the model to the problem statement, not the other way round.
2. **Our hardest rules are attribute predicates** (`amount < 10000`, same-dept, separation of duties),
   which are native to ABAC and awkward in pure ReBAC (where they require bolted-on caveats/conditions).
3. **The one real relationship — role inheritance — is shallow** and handled by a DAG walk; it does
   not justify a relationship-graph engine.
4. **Auditability & admin UX:** policies-as-data are UI-manageable, versioned, and the simulator
   names the deciding policy. "Which policy fired" beats "trace the tuple graph" for enterprise admins.
5. **Multi-tenant isolation is already a Postgres-RLS invariant**, and the XACML/PDP model composes
   with it cleanly (one tenant per decision) rather than cutting across it.
6. **Operational reality:** XACML's topology needs nothing beyond the Postgres + Redis we already run;
   Zanzibar adds a new distributed system on the hot path, which is wrong for the scale **and** the
   timebox.

This is a **"right tool, right scale"** decision, not a rejection of Zanzibar on the merits.

---

## 4. When this decision should flip (the migration trigger)

Revisit — and migrate toward **ReBAC (OpenFGA / SpiceDB)** — when authorization stops being about
attributes and starts being about **deep, dynamic relationships**:

- **Resource sharing** ("Anne shared this expense report with Bob and his whole team").
- **Nested group / folder inheritance** ("members of the parent org unit can read every child unit's
  payslips," many levels deep).
- **Per-object ACLs at scale** where the answer is genuinely "is there a path," not "do the fields match."
- **Cross-tenant or cross-graph reachability** that RLS's one-tenant-per-request model can't express.

The path is smooth by design: our **permission catalog maps cleanly onto Zanzibar "relations,"** and
the PEP/PDP boundary means we can **swap the PDP's decision core** for a tuple-check call **without
touching the enforcement points** in each service. That clean seam is itself a benefit of having
chosen the XACML architecture first. See [`DESIGN.md §17`](./DESIGN.md#17-future-evolution).

---

## 5. Footnote — and OPA/Rego?

A common third option is **OPA/Rego** (policy-as-code). We declined it for an orthogonal reason: Rego
puts authorization logic in **code files** requiring a bundle push/redeploy, whereas the assignment
wants **dynamic, admin-managed** policies. Our JSON DSL keeps policies as **data** — editable in the
UI, versioned in the DB, audited, injection-safe — at the cost of some expressiveness. The full
treatment is in [`CODE-WALKTHROUGH.md §18.2`](./CODE-WALKTHROUGH.md).
