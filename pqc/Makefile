.DEFAULT_GOAL := help
COMPOSE       := docker compose

help:
	@grep -E '^[a-z][a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build images (note: liboqs compile takes ~3 min first time)
	$(COMPOSE) build

test: ## Run pytest suite inside Docker
	$(COMPOSE) run --rm --build test

up: ## Start PQC server on :5001
	$(COMPOSE) up pqc --build -d

down: ## Stop
	$(COMPOSE) down

logs: ## Tail PQC server logs
	$(COMPOSE) logs -f pqc

clean: ## Remove containers + images
	$(COMPOSE) down --rmi local --volumes --remove-orphans
