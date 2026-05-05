.PHONY: setup test frontend-build frontend-e2e compose-config security-scan validate clean-artifacts audit-verify audit-export evidence-cleanup-dry-run

PYTHON ?= python3
PIP ?= pip

setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PIP) install -r backend/requirements.lock pytest
	cd frontend && npm ci

test:
	pytest -q

frontend-build:
	cd frontend && npm run build

frontend-e2e:
	cd frontend && npx playwright install --with-deps chromium && npm run e2e

compose-config:
	RAPTOR_API_KEY=ci_raptor_api_key_with_enough_entropy \
	RAPTOR_BOOTSTRAP_ADMIN_PASSWORD=ci_bootstrap_admin_password_with_enough_entropy \
	EVIDENCE_ENCRYPTION_KEY=ci_evidence_key_with_enough_entropy_32_bytes \
	NEO4J_PASSWORD=ci_neo4j_password_with_enough_entropy \
	WEAVIATE_API_KEY=ci_weaviate_api_key_with_enough_entropy \
	ELASTIC_PASSWORD=ci_elastic_password_with_enough_entropy \
	POSTGRES_PASSWORD=ci_postgres_password_with_enough_entropy \
	RAPTOR_FRONTEND_ORIGIN=https://raptor.example.invalid \
	docker compose -f docker-compose.yml -f docker-compose.prod.yml config >/dev/null

security-scan:
	pip-audit -r backend/requirements.lock --progress-spinner off
	cd frontend && npm audit --audit-level=high

validate: test frontend-build compose-config

clean-artifacts:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache frontend/dist frontend/.vite

audit-verify:
	$(PYTHON) scripts/ops/verify_audit_chain.py --db data/raptor.db

audit-export:
	$(PYTHON) scripts/ops/export_audit_log.py --db data/raptor.db --out exports/audit-log.jsonl

evidence-cleanup-dry-run:
	$(PYTHON) scripts/ops/cleanup_expired_evidence.py --db data/raptor.db
