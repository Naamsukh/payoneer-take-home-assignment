# Submission — Access Control Across Microservices in a Multi-Tenant Architecture

Self-contained submission package. Every required deliverable is in this folder.

| # | Required deliverable | File |
|---|----------------------|------|
| 1 | **Executable codebase** | GitHub: _<add repository URL>_ — run with `make up`, test with `make e2e` |
| 2 | **Design document** | [`DESIGN.pdf`](./DESIGN.pdf) (rendered, with diagrams inline) · source: [`DESIGN.md`](./DESIGN.md) |
| 3 | **Architecture diagrams** | [`diagrams/01-high-level-architecture.png`](./diagrams/01-high-level-architecture.png), [`diagrams/06-tenant-isolation.png`](./diagrams/06-tenant-isolation.png), [`diagrams/07-service-to-service.png`](./diagrams/07-service-to-service.png) |
| 4 | **Flow / sequence diagrams** | [`diagrams/05-auth-authz-sequence.png`](./diagrams/05-auth-authz-sequence.png) (sequence), [`diagrams/03-access-control-model.png`](./diagrams/03-access-control-model.png) (decision flow) |
| 5 | **API examples** | [`api-examples.md`](./api-examples.md) |
| 6 | **Schema diagrams** | [`diagrams/04-data-model-erd.png`](./diagrams/04-data-model-erd.png) |

## All diagrams (PNG)

| File | What it shows | Type |
|------|---------------|------|
| `diagrams/01-high-level-architecture.png` | System context: UI, Auth, Authz/PDP, sample services + PEP, Postgres+RLS, Redis | Architecture |
| `diagrams/02-membership-model.png` | Identity vs participation (global `User` ↔ `Membership` ↔ `Tenant`) | Data/relationship |
| `diagrams/03-access-control-model.png` | Users → roles (inheritance) → permissions, narrowed by ABAC; deny-by-default pipeline | Flow |
| `diagrams/04-data-model-erd.png` | Full relational schema (global vs tenant-scoped, RLS, direct grants) | **Schema** |
| `diagrams/05-auth-authz-sequence.png` | Login → select-tenant → guarded request → PEP → cache → PDP | **Sequence** |
| `diagrams/06-tenant-isolation.png` | Defense in depth: token → application → Postgres RLS | Architecture |
| `diagrams/07-service-to-service.png` | Services authenticate to the PDP with signed service tokens | Architecture |

> **Note:** `DESIGN.md` also embeds these diagrams inline (they render on GitHub). Editable Mermaid
> sources (`.mmd`) and scalable SVGs live in the repo at [`../diagrams/`](../diagrams/README.md).
