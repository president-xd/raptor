import unittest

from helpers import BACKEND_DIR  # noqa: F401
from attribution.confidence import calculate_confidence
from attribution.jaccard import jaccard_attribution, jaccard_similarity
from schema import AnalysisResult, AttributionResult, Finding, RaptorEvent


class AttributionAndAnalysisTests(unittest.TestCase):
    def test_jaccard_similarity_and_ranking(self):
        profiles = {
            "APT Alpha": {"techniques": {"T1059.001", "T1003.001", "T1021.002"}},
            "APT Beta": {"techniques": {"T1059.001"}},
        }

        self.assertAlmostEqual(
            jaccard_similarity({"T1059.001", "T1003.001"}, {"T1059.001", "T1021.002"}),
            1 / 3,
        )

        ranked = jaccard_attribution({"T1059.001", "T1003.001"}, profiles)

        self.assertEqual(ranked[0]["apt"], "APT Alpha")
        self.assertEqual(ranked[0]["overlap"], ["T1003.001", "T1059.001"])
        self.assertGreater(ranked[0]["jaccard"], ranked[1]["jaccard"])

    def test_confidence_applies_false_flag_penalty_and_bonuses(self):
        profiles = {
            "APT Alpha": {
                "aliases": ["Alpha"],
                "techniques": {"T1059.001", "T1003.001", "T1021.002"},
            },
            "APT Beta": {
                "aliases": ["Beta"],
                "techniques": {"T1059.001", "T1003.001"},
            },
            "APT Gamma": {
                "aliases": ["Gamma"],
                "techniques": {"T1105"},
            },
        }

        results = calculate_confidence(
            {"T1059.001", "T1003.001", "T1021.002"},
            profiles,
            campaign_duration_hours=12,
            matched_infrastructure=True,
            matched_malware=True,
            temporal_sequence_match=True,
        )

        self.assertEqual(results[0].apt_name, "APT Alpha")
        self.assertEqual(results[0].confidence_label, "HIGH")
        self.assertTrue(any("Multi-group overlap" in item for item in results[0].penalties_applied))
        self.assertTrue(any("Short campaign" in item for item in results[0].penalties_applied))
        self.assertEqual(len(results[0].bonuses_applied), 3)
        self.assertEqual(len(results), 3)

    def test_stix_validation_removes_unknown_techniques(self):
        import attribution.stix_validator as validator

        original_ids = validator._valid_ids
        validator._valid_ids = {"T1059.001"}
        try:
            result = validator.validate_analysis_result(
                AnalysisResult(
                    findings=[
                        Finding(technique_id="T1059.001", technique_name="PowerShell"),
                        Finding(technique_id="T9999", technique_name="Imaginary"),
                    ],
                    attack_sequence=["T1059.001", "T9999"],
                )
            )
        finally:
            validator._valid_ids = original_ids

        self.assertEqual([finding.technique_id for finding in result.findings], ["T1059.001"])
        self.assertEqual(result.attack_sequence, ["T1059.001"])

    def test_llm_response_parser_extracts_fenced_json(self):
        from rag.pipeline import parse_llm_response

        result = parse_llm_response(
            """```json
            {
              "findings": [
                {
                  "event_ids": ["evt-1"],
                  "technique_id": "T1059.001",
                  "technique_name": "PowerShell",
                  "kill_chain_phase": "execution",
                  "confidence": "high",
                  "evidence_summary": "Encoded PowerShell execution.",
                  "apt_indicators": ["powershell"]
                }
              ],
              "attack_sequence": ["T1059.001"],
              "anomalies": ["none"]
            }
            ```"""
        )

        self.assertEqual(result.findings[0].technique_id, "T1059.001")
        self.assertEqual(result.attack_sequence, ["T1059.001"])
        self.assertEqual(result.anomalies, ["none"])

    def test_sigma_fallback_analysis_uses_local_matches(self):
        from rag.pipeline import build_sigma_fallback_analysis

        event = RaptorEvent(
            event_id="evt-1",
            timestamp="2026-04-25T10:00:00Z",
            source_host="WKSTN-01",
            event_type="process",
            raw="powershell.exe -enc SQBFAFgA",
            sigma_matches=["T1059.001"],
            ioc_score=0.6,
        )

        result = build_sigma_fallback_analysis([event], "offline test")

        self.assertEqual(result.findings[0].technique_id, "T1059.001")
        self.assertEqual(result.findings[0].confidence, "high")
        self.assertEqual(result.attack_sequence, ["T1059.001"])
        self.assertIn("fallback", result.anomalies[0].lower())

    def test_report_generation_uses_deterministic_fallback(self):
        import report.generator as generator

        original_call_llm = generator.call_llm
        generator.call_llm = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
        try:
            report = generator.generate_report(
                AnalysisResult(
                    findings=[
                        Finding(
                            technique_id="T1059.001",
                            technique_name="PowerShell",
                            kill_chain_phase="execution",
                            confidence="high",
                            evidence_summary="Encoded PowerShell execution.",
                        )
                    ],
                    attack_sequence=["T1059.001"],
                ),
                [
                    AttributionResult(
                        apt_name="APT Alpha",
                        confidence_score=0.82,
                        confidence_label="HIGH",
                        overlapping_ttps=["T1059.001"],
                    )
                ],
                {"total_events": 1, "unique_hosts": 1, "hosts_compromised": 1, "campaign_duration_hours": 1.0},
                "case-1",
            )
        finally:
            generator.call_llm = original_call_llm

        self.assertIn("# RAPTOR Investigation Report", report)
        self.assertIn("APT Alpha", report)
        self.assertIn("T1059.001", report)
        self.assertIn("deterministic fallback", report)


if __name__ == "__main__":
    unittest.main()
