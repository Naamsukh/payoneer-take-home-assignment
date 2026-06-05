# Submission Index — Access Control Across Microservices in a Multi-Tenant Architecture

This folder contains every required submission artifact. The table below maps each item the
assignment asks for to where it lives.

| # | Required deliverable | Where it is | Format |
|---|----------------------|-------------|--------|
| 1 | **Executable codebase** | The repository root (`make up` boots the whole system; `make e2e` runs the cross-service test). See the top-level [`README.md`](../README.md) for run instructions. | Code + Docker Compose |
| 2 | **Design document** | [`DESIGN.md`](./DESIGN.md) — assumptions, requirements, architecture, access model, data model, flows, isolation, service-to-service security, APIs, scalability, security/compliance, tradeoffs, traceability, future work. | Markdown (PDF-ready) |
| 3 | **Architecture diagrams** | [`diagrams/01-high-level-architecture`](./diagrams/01-high-level-architecture.svg) (system context). Plus [`diagrams/06-tenant-isolation`](./diagrams/06-tenant-isolation.svg) and [`diagrams/07-service-to-service`](./diagrams/07-service-to-service.svg). | Mermaid → SVG + PNG |
| 4 | **Flow / sequence diagrams** | [`diagrams/05-auth-authz-sequence`](./diagrams/05-auth-authz-sequence.svg) (login → tenant-scoped JWT → guarded request → PEP → cache → PDP). Plus the access-control decision pipeline in [`diagrams/03-access-control-model`](./diagrams/03-access-control-model.svg). | Mermaid → SVG + PNG |
| 5 | **API examples** | [`api-examples.md`](./api-examples.md) — copy-pasteable `curl` for every endpoint, with sample requests/responses. | Markdown |
| 6 | **Schema diagrams** | [`diagrams/04-data-model-erd`](./diagrams/04-data-model-erd.svg) — the full relational ERD (global vs tenant-scoped, RLS). | Mermaid → SVG + PNG |

> **Codebase link:** add the GitHub URL to the top-level [`README.md`](../README.md) before submitting.

---

## Reading order (recommended)

1. **[`../README.md`](../README.md)** — what it is, how to run it (`make up`, `make e2e`), demo logins.
2. **[`DESIGN.md`](./DESIGN.md)** — the design document (read this end-to-end; it covers every prompt
   requirement and is cross-linked to the diagrams).
3. **[`diagrams/`](./diagrams/README.md)** — the seven rendered diagrams, each linked back to its
   `DESIGN.md` section.
4. **[`api-examples.md`](./api-examples.md)** — try the system through its APIs.

### Supplementary (depth, not required by the prompt)

- **[`CODE-WALKTHROUGH.md`](./CODE-WALKTHROUGH.md)** — a file-by-file deep dive of the implementation:
  every module, the decision algorithm, RLS, caching, the token/trust model, known gaps, and an
  interview-style Q&A. Read this to be able to answer anything about the running code.
- **[`ZANZIBAR-VS-XACML.md`](./ZANZIBAR-VS-XACML.md)** — long-form rationale for choosing the
  XACML-style PEP/PDP topology over a Zanzibar/ReBAC system (the headline "why not X" tradeoff).

---

## The diagram set (all in [`diagrams/`](./diagrams/README.md))

Each diagram is a Mermaid source (`.mmd`, the source of truth) rendered to **`.svg`** (crisp/scalable,
best for a PDF) and **`.png`** (universally embeddable). They also render natively on GitHub from the
fenced ` ```mermaid ` blocks embedded in `DESIGN.md`.

| File | Diagram | Type | DESIGN §|
|------|---------|------|---------|
| `01-high-level-architecture` | System context: UI, Auth, Authz/PDP, sample services + PEP, Postgres+RLS, Redis | Architecture | §5 |
| `02-membership-model` | Identity vs participation (global `User` ↔ `Membership` ↔ `Tenant`) | Data/relationship | §6.1 |
| `03-access-control-model` | Users → roles (inheritance) → permissions, narrowed by ABAC; deny-by-default pipeline | Flow | §6 |
| `04-data-model-erd` | Full relational schema (global vs tenant-scoped, RLS, direct grants) | **Schema** | §7 |
| `05-auth-authz-sequence` | Login → select-tenant → guarded request → PEP → cache → PDP | **Sequence** | §8 |
| `06-tenant-isolation` | Defense in depth: token → application → Postgres RLS | Architecture | §9 |
| `07-service-to-service` | Services authenticate to the PDP with signed service tokens (mTLS/SPIFFE upgrade) | Architecture | §10 |

Regenerate after editing any `.mmd`:

```bash
make diagrams        # renders every docs/diagrams/*.mmd to .svg + .png
```

---

## Producing a PDF of the design document (optional)

The prompt accepts **PDF / Markdown / Slides** — the Markdown above is a valid submission as-is, and
renders with diagrams directly on GitHub. To also produce a self-contained PDF:

```bash
# Requires pandoc + a LaTeX engine (e.g. `brew install pandoc basictex`).
# Diagrams are embedded as the pre-rendered SVG/PNG, so no browser is needed at PDF time.
pandoc docs/DESIGN.md -o docs/DESIGN.pdf \
  --toc --resource-path=docs --pdf-engine=xelatex
```

If `pandoc`/LaTeX isn't installed, the simplest path is **GitHub → Print → Save as PDF** on the
rendered `DESIGN.md`, which captures the Mermaid diagrams inline.
