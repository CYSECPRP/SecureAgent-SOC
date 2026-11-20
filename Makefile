.PHONY: help up down test dev sim clean prod-up prod-down prod-logs backup

PROD = docker compose -f docker-compose.prod.yml

help:
	@echo "SecureAgent-SOC Build & Run Automation"
	@echo "  make up        - Start Docker infrastructure (Postgres, Redis, Qdrant, OPA)"
	@echo "  make down      - Stop Docker infrastructure"
	@echo "  make test      - Run backend pytest test suite"
	@echo "  make dev       - Run backend FastAPI dev server on :8000"
	@echo "  make sim       - Run Streamlit Red-Team Attack Simulation Lab on :8501"
	@echo "  make clean     - Remove cache files and temporary test artifacts"
	@echo "  make prod-up   - Build and start the production stack (needs .env, see deploy/)"
	@echo "  make prod-down - Stop the production stack"
	@echo "  make prod-logs - Follow the production logs"
	@echo "  make backup    - Dump the production database to backups/"

up:
	docker compose up -d

down:
	docker compose down

test:
	cd backend && ../.venv/bin/pytest -v

dev:
	cd backend && ../.venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

sim:
	.venv/bin/streamlit run attack_simulator/app.py --server.port 8501

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +

prod-up:
	$(PROD) up -d --build

prod-down:
	$(PROD) down

prod-logs:
	$(PROD) logs -f --tail=100

backup:
	./deploy/backup.sh
