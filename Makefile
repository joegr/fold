# ─────────────────────────────────────────────────────────────
# Circuit Card Simulator – Makefile
#
# All targets run inside Docker.  No local Python required.
# ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
COMPOSE       := docker compose

.PHONY: help build up down test dev logs clean

help: ## Show this help
	@grep -E '^[a-z][a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build all Docker images (no cache)
	$(COMPOSE) build --no-cache

up: .env ## Start production server (gunicorn)
	$(COMPOSE) up app --build -d
	@echo "\n  ✔  Server running at http://localhost:$${PORT:-5000}\n"

down: ## Stop all running containers
	$(COMPOSE) down

test: .env ## Run unit tests in Docker
	$(COMPOSE) run --rm --build test

dev: .env ## Start Flask dev server with hot-reload
	$(COMPOSE) up dev --build

logs: ## Tail production logs
	$(COMPOSE) logs -f app

clean: ## Remove containers, images, and volumes
	$(COMPOSE) down --rmi local --volumes --remove-orphans

# ── Auto-create .env from template if missing ──────────────
.env:
	@echo "Creating .env from .env.example..."
	@cp .env.example .env
	@echo "  ✔  Edit .env before deploying to production.\n"
