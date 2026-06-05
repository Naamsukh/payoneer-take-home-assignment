.PHONY: up down restart build logs ps shell-auth shell-authz shell-expense shell-payroll \
        db-shell redis-cli bootstrap seed e2e diagrams design-pdf clean reset help

COMPOSE = docker compose

# ── Lifecycle ────────────────────────────────────────────────────────────────

up: ## Start all services (build if needed)
	$(COMPOSE) up --build -d

down: ## Stop and remove containers
	$(COMPOSE) down

restart: ## Restart all services
	$(COMPOSE) restart

build: ## Rebuild images without starting
	$(COMPOSE) build

# ── Observability ─────────────────────────────────────────────────────────────

logs: ## Tail logs for all services (Ctrl-C to stop)
	$(COMPOSE) logs -f

logs-%: ## Tail logs for a specific service, e.g. make logs-auth
	$(COMPOSE) logs -f $*

ps: ## Show running containers and their status
	$(COMPOSE) ps

# ── Shells ────────────────────────────────────────────────────────────────────

shell-%: ## Open a shell in a service container, e.g. make shell-auth
	$(COMPOSE) exec $* /bin/sh

db-shell: ## Open a psql session as the postgres superuser
	$(COMPOSE) exec postgres psql -U postgres -d acp

redis-cli: ## Open a redis-cli session
	$(COMPOSE) exec redis redis-cli

# ── Maintenance ───────────────────────────────────────────────────────────────

bootstrap: ## Re-run the database bootstrap (schema + RLS setup)
	$(COMPOSE) run --rm bootstrap

seed: ## (Re)load the demo tenants/users/roles/policies
	$(COMPOSE) run --rm seed

e2e: ## Run the end-to-end cross-service access-control test
	$(COMPOSE) run --rm --no-deps -e RUN_E2E=1 auth python -m scripts.e2e

# ── Diagrams ──────────────────────────────────────────────────────────────────

diagrams: ## Render docs/diagrams/*.mmd to .svg + .png (needs Node/npx)
	@for f in docs/diagrams/*.mmd; do \
		base=$${f%.mmd}; \
		echo "rendering $$base"; \
		npx -y @mermaid-js/mermaid-cli@11 -i "$$f" -o "$$base.svg" -b white >/dev/null 2>&1; \
		npx -y @mermaid-js/mermaid-cli@11 -i "$$f" -o "$$base.png" -b white -s 2 >/dev/null 2>&1; \
	done
	@echo "done -> docs/diagrams/*.svg, *.png"

design-pdf: ## Render docs/DESIGN.md -> docs/submission/DESIGN.pdf (Python: markdown + weasyprint)
	@python3 -m venv .venv-pdf
	@. .venv-pdf/bin/activate && pip install --quiet --upgrade pip && pip install --quiet markdown weasyprint pypdf
	@. .venv-pdf/bin/activate && DYLD_FALLBACK_LIBRARY_PATH="$$(brew --prefix 2>/dev/null)/lib" \
		python scripts/build_design_pdf.py
	@echo "note: WeasyPrint needs the Pango/Cairo system libs (macOS: 'brew install pango')."

clean: ## Stop containers and remove images built from this project
	$(COMPOSE) down --rmi local

reset: ## Full reset: stop containers, delete volumes, rebuild from scratch
	$(COMPOSE) down -v
	$(COMPOSE) up --build -d

# ── Help ──────────────────────────────────────────────────────────────────────

help: ## Show this help message
	@grep -E '^[a-zA-Z_%-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
