# ─────────────────────────────────────────────────────────────
# Circuit Card Simulator – Makefile
#
# All targets run inside Docker.  No local Python required.
# ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
COMPOSE       := docker compose

.PHONY: help build up down test dev logs clean \
        pqc-build pqc-up pqc-test pqc-logs test-all

help: ## Show this help
	@grep -E '^[a-z][a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ── Classical ──────────────────────────────────────────────

build: ## Build all Docker images (no cache)
	$(COMPOSE) build --no-cache

up: .env ## Start production server + PQC sidecar
	$(COMPOSE) up app pqc --build -d
	@echo "\n  ✔  App running at http://localhost:$${PORT:-5000}"
	@echo "  ✔  PQC running at http://localhost:$${PQC_PORT:-5001}\n"

down: ## Stop all running containers
	$(COMPOSE) down

test: .env ## Run classical unit tests in Docker
	$(COMPOSE) run --rm --build test

dev: .env ## Start Flask dev server + PQC with hot-reload
	$(COMPOSE) --profile dev up dev pqc --build

logs: ## Tail production logs (app + pqc)
	$(COMPOSE) logs -f app pqc

clean: ## Remove containers, images, and volumes
	$(COMPOSE) down --rmi local --volumes --remove-orphans

# ── Post-Quantum ──────────────────────────────────────────

pqc-build: ## Build PQC image (liboqs, ~3 min first time)
	$(COMPOSE) build pqc --no-cache

pqc-up: .env ## Start PQC service only on :5001
	$(COMPOSE) up pqc --build -d
	@echo "\n  ✔  PQC running at http://localhost:$${PQC_PORT:-5001}\n"

pqc-test: ## Run PQC pytest suite in Docker
	$(COMPOSE) run --rm --build pqc-test

pqc-logs: ## Tail PQC server logs
	$(COMPOSE) logs -f pqc

# ── Combined ──────────────────────────────────────────────

test-all: .env ## Run classical + PQC tests
	$(COMPOSE) run --rm --build test
	$(COMPOSE) run --rm --build pqc-test

# ── Auto-create .env from template if missing ──────────────
.env:
	@echo "Creating .env from .env.example..."
	@cp .env.example .env
	@echo "  ✔  Edit .env before deploying to production.\n"
