COMPOSE ?= docker compose
PYTHON ?= python

.PHONY: up down logs test migrate lint

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --tail=100 -f backend worker beat frontend

test:
	cd backend && $(PYTHON) -m pytest -q
	cd frontend && npm run build

migrate:
	$(COMPOSE) run --rm backend alembic upgrade head

lint:
	cd backend && $(PYTHON) -m ruff check app tests alembic
	cd frontend && npm run typecheck
