import unittest

from helpers import ROOT_DIR


class RepositoryContractTests(unittest.TestCase):
    def read_text(self, relative_path: str) -> str:
        return (ROOT_DIR / relative_path).read_text(encoding="utf-8")

    def test_env_example_uses_safe_local_defaults(self):
        env = self.read_text(".env.example")

        self.assertIn("NEO4J_PASSWORD=change_me_neo4j_password", env)
        self.assertIn("LOCAL_BIND_ADDRESS=127.0.0.1", env)
        self.assertIn("RAPTOR_API_KEY=change_me_raptor_api_key", env)
        self.assertIn("RAPTOR_ENV=development", env)
        self.assertIn("RAPTOR_PROCESS_ROLE=all", env)
        self.assertIn("RAPTOR_ALLOW_AUTH_DISABLED=false", env)
        self.assertIn("RAPTOR_DB_ENGINE=sqlite", env)
        self.assertIn("RAPTOR_DATABASE_URL=", env)
        self.assertIn("RAPTOR_DB_PATH=./data/raptor.db", env)
        self.assertIn("RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS=false", env)
        self.assertIn("CSRF_TRUSTED_ORIGINS=http://localhost:3100,http://127.0.0.1:3100", env)
        self.assertIn("RAG_AUTO_INDEX=false", env)
        self.assertNotIn("VITE_RAPTOR_API_KEY", env)
        self.assertIn("ELASTIC_POLL_ENABLED=false", env)
        self.assertIn("CISA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", env)
        self.assertNotIn("raptor_secret_2024", env)

    def test_docker_compose_binds_published_ports_to_localhost_by_default(self):
        compose = self.read_text("docker-compose.yml")

        for published_port in ("7474", "7687", "8080", "50051", "9200", "6379"):
            self.assertIn(f"${{LOCAL_BIND_ADDRESS:-127.0.0.1}}:{published_port}:{published_port}", compose)
        self.assertIn("${LOCAL_BIND_ADDRESS:-127.0.0.1}:${API_PORT:-8000}:8000", compose)
        self.assertIn("${LOCAL_BIND_ADDRESS:-127.0.0.1}:${FRONTEND_PORT:-3100}:3100", compose)
        self.assertIn("./data:/app/data", compose)
        self.assertNotIn("./backend/raptor.db:/app/backend/raptor.db", compose)
        self.assertNotIn("raptor_secret_2024", compose)

    def test_production_overlay_splits_api_and_worker(self):
        overlay = self.read_text("docker-compose.prod.yml")

        self.assertIn("RAPTOR_ENV=production", overlay)
        self.assertIn("RAPTOR_PROCESS_ROLE=api", overlay)
        self.assertIn("RAPTOR_PROCESS_ROLE=worker", overlay)
        self.assertIn("postgres:", overlay)
        self.assertIn("RAPTOR_DB_ENGINE=postgresql", overlay)
        self.assertIn("RAPTOR_DATABASE_URL=postgresql://raptor:${POSTGRES_PASSWORD:?set_POSTGRES_PASSWORD}@postgres:5432/raptor", overlay)
        self.assertIn("command: [\"python\", \"worker.py\"]", overlay)
        self.assertIn("RAPTOR_SESSION_COOKIE_SECURE=true", overlay)
        self.assertIn("CSRF_TRUSTED_ORIGINS=${RAPTOR_FRONTEND_ORIGIN:?set_RAPTOR_FRONTEND_ORIGIN}", overlay)

    def test_ci_pipeline_exists_for_tests_build_and_compose_validation(self):
        ci = self.read_text(".github/workflows/ci.yml")

        self.assertIn("pytest -q", ci)
        self.assertIn("pip check", ci)
        self.assertIn("postgres-integration", ci)
        self.assertIn("RAPTOR_DB_ENGINE: postgresql", ci)
        self.assertIn("npm run build", ci)
        self.assertIn("docker compose -f docker-compose.yml -f docker-compose.prod.yml config", ci)

    def test_backend_lock_avoids_unbounded_torch_cuda_payload(self):
        lock = self.read_text("backend/requirements.lock")

        self.assertIn("--extra-index-url https://download.pytorch.org/whl/cpu", lock)
        self.assertIn("torch==2.2.2+cpu", lock)
        self.assertIn("transformers==4.40.2", lock)

    def test_frontend_api_client_sends_configured_api_key(self):
        api_client = self.read_text("frontend/src/api/raptorApi.js")

        self.assertIn("credentials: 'include'", api_client)
        self.assertIn("createAuthSession", api_client)
        self.assertIn("getInvestigationEvidence", api_client)
        self.assertIn("listAuditEntries", api_client)
        self.assertIn("listCisaKev", api_client)
        self.assertIn("getElasticsearchPollStatus", api_client)

    def test_frontend_surfaces_operational_backend_endpoints(self):
        dashboard = self.read_text("frontend/src/components/Dashboard.jsx")

        self.assertIn("getInvestigationEvidence", dashboard)
        self.assertIn("listAuditEntries", dashboard)
        self.assertIn("pollElasticsearch", dashboard)
        self.assertIn("Raw Evidence Files", dashboard)
        self.assertIn("Append-only Audit Log", dashboard)
        self.assertIn("Run Poll Now", dashboard)

    def test_vite_reads_root_environment_for_hybrid_mode(self):
        vite_config = self.read_text("frontend/vite.config.js")

        self.assertIn("envDir: '..'", vite_config)

    def test_readme_documents_new_operational_surfaces(self):
        readme = self.read_text("README.md")

        self.assertNotIn("MVP", readme)
        self.assertIn("Persistent raw evidence storage", readme)
        self.assertIn("Append-only SQLite audit logging", readme)
        self.assertIn("CISA Known Exploited Vulnerabilities connector", readme)
        self.assertIn("/threat-feeds/cisa-kev", readme)
        self.assertIn("/ingest/elasticsearch/status", readme)
        self.assertIn("RAPTOR_API_KEY", readme)
        self.assertIn("RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS", readme)


if __name__ == "__main__":
    unittest.main()
