import json
import tempfile
import unittest
from pathlib import Path

from helpers import BACKEND_DIR  # noqa: F401
from attribution import attack_catalog
from attribution import stix_validator
from attribution.stix_validator import validate_analysis_result
from rag.pipeline import build_sigma_fallback_analysis
from schema import AnalysisResult, Finding, RaptorEvent


def stix_bundle():
    return {
        "type": "bundle",
        "id": "bundle--test",
        "spec_version": "2.0",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--active",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials.",
                "x_mitre_platforms": ["Windows", "Linux"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1078",
                        "url": "https://attack.mitre.org/techniques/T1078/",
                    }
                ],
                "modified": "2026-01-01T00:00:00Z",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--inactive",
                "name": "Deprecated Technique",
                "x_mitre_deprecated": True,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
        ],
    }


class AttackCatalogMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_stix_dir = attack_catalog.STIX_DIR
        self.original_catalog = attack_catalog._CATALOG
        self.original_valid_ids = stix_validator._valid_ids
        attack_catalog.STIX_DIR = Path(self.tmp.name)
        attack_catalog.STIX_DIR.mkdir(parents=True, exist_ok=True)
        (attack_catalog.STIX_DIR / "enterprise-attack.json").write_text(
            json.dumps(stix_bundle()),
            encoding="utf-8",
        )
        attack_catalog._CATALOG = None
        stix_validator._valid_ids = None

    def tearDown(self):
        attack_catalog.STIX_DIR = self.original_stix_dir
        attack_catalog._CATALOG = self.original_catalog
        stix_validator._valid_ids = self.original_valid_ids
        self.tmp.cleanup()

    def test_catalog_filters_inactive_and_places_multi_tactic_techniques(self):
        matrix = attack_catalog.build_matrix([Finding(technique_id="T1078", confidence="high")])

        self.assertEqual(matrix["source"]["active_technique_count"], 1)
        self.assertEqual(matrix["observed_count"], 1)
        self.assertNotIn("T9999", attack_catalog.get_valid_technique_ids())

        placements = [
            column["tactic"]
            for column in matrix["matrix"]
            if any(cell["technique_id"] == "T1078" for cell in column["techniques"])
        ]
        self.assertEqual(
            placements,
            ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
        )

    def test_validation_canonicalizes_name_tactics_and_rejects_inactive_ids(self):
        result = validate_analysis_result(
            AnalysisResult(
                findings=[
                    Finding(technique_id="T1078", technique_name="Wrong Name", kill_chain_phase="execution"),
                    Finding(technique_id="T9999", technique_name="Deprecated Technique"),
                ],
                attack_sequence=["T1078", "T9999"],
            )
        )

        self.assertEqual([finding.technique_id for finding in result.findings], ["T1078"])
        self.assertEqual(result.findings[0].technique_name, "Valid Accounts")
        self.assertEqual(result.findings[0].kill_chain_phase, "initial-access")
        self.assertIn("defense-evasion", result.findings[0].tactics)
        self.assertEqual(result.attack_sequence, ["T1078"])

    def test_sigma_fallback_uses_catalog_for_t1078_phase(self):
        event = RaptorEvent(
            raw="successful logon unusual valid account compromise",
            sigma_matches=["T1078"],
            ioc_score=0.6,
        )

        result = build_sigma_fallback_analysis([event], "unit test")

        self.assertEqual(result.findings[0].technique_name, "Valid Accounts")
        self.assertEqual(result.findings[0].kill_chain_phase, "initial-access")
        self.assertIn("privilege-escalation", result.findings[0].tactics)


if __name__ == "__main__":
    unittest.main()
