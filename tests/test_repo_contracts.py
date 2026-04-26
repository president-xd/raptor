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
        self.assertIn("VITE_RAPTOR_API_KEY=change_me_raptor_api_key", env)
        self.assertIn("ELASTIC_POLL_ENABLED=false", env)
        self.assertIn("CISA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", env)
        self.assertNotIn("raptor_secret_2024", env)

    def test_docker_compose_binds_published_ports_to_localhost_by_default(self):
        compose = self.read_text("docker-compose.yml")

        for published_port in ("7474", "7687", "8080", "50051", "9200", "6379"):
            self.assertIn(f"${{LOCAL_BIND_ADDRESS:-127.0.0.1}}:{published_port}:{published_port}", compose)
        self.assertIn("${LOCAL_BIND_ADDRESS:-127.0.0.1}:${API_PORT:-8000}:8000", compose)
        self.assertIn("${LOCAL_BIND_ADDRESS:-127.0.0.1}:${FRONTEND_PORT:-3100}:3100", compose)
        self.assertNotIn("raptor_secret_2024", compose)

    def test_frontend_api_client_sends_configured_api_key(self):
        api_client = self.read_text("frontend/src/api/raptorApi.js")

        self.assertIn("import.meta.env.VITE_RAPTOR_API_KEY", api_client)
        self.assertIn("X-RAPTOR-API-Key", api_client)
        self.assertIn("getInvestigationEvidence", api_client)
        self.assertIn("listAuditEntries", api_client)
        self.assertIn("listCisaKev", api_client)
        self.assertIn("getElasticsearchPollStatus", api_client)

    def test_vite_reads_root_environment_for_hybrid_mode(self):
        vite_config = self.read_text("frontend/vite.config.js")

        self.assertIn("envDir: '..'", vite_config)

    def test_commit_script_commits_every_changed_file_individually(self):
        script = self.read_text("commit.sh")

        self.assertIn("git diff --name-only -z HEAD --", script)
        self.assertIn("git ls-files --others --exclude-standard -z", script)
        self.assertIn("git add -A -- \"$file\"", script)
        self.assertIn("git commit -m \"$subject\"", script)
        self.assertIn("All changed files were committed individually.", script)

    def test_readme_documents_new_operational_surfaces(self):
        readme = self.read_text("README.md")

        self.assertIn("Persistent raw evidence storage", readme)
        self.assertIn("Append-only SQLite audit logging", readme)
        self.assertIn("CISA Known Exploited Vulnerabilities connector", readme)
        self.assertIn("/threat-feeds/cisa-kev", readme)
        self.assertIn("/ingest/elasticsearch/status", readme)
        self.assertIn("RAPTOR_API_KEY", readme)


if __name__ == "__main__":
    unittest.main()
