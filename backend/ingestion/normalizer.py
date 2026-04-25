"""
RAPTOR | Log Normalizer
Converts parsed log dictionaries into validated RaptorEvent objects.
"""
import uuid
from typing import List, Dict, Any
from datetime import datetime
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import RaptorEvent
from ingestion.log_parser import LogParser
from ingestion.sigma_matcher import SigmaMatcher


class LogNormalizer:
    """Normalize parsed logs into RAPTOR Event Schema objects."""

    def __init__(self):
        self.parser = LogParser()
        self.sigma = SigmaMatcher()

    def normalize_file(self, filepath: str) -> List[RaptorEvent]:
        """Parse and normalize a log file."""
        raw_events = self.parser.parse_file(filepath)
        return self._normalize(raw_events)

    def normalize_content(self, content: str) -> List[RaptorEvent]:
        """Parse and normalize log content string."""
        raw_events = self.parser.parse_content(content)
        return self._normalize(raw_events)

    def _normalize(self, raw_events: List[Dict[str, Any]]) -> List[RaptorEvent]:
        """Convert parsed dicts to RaptorEvent objects with Sigma enrichment."""
        # Run sigma matching
        raw_events = self.sigma.match_events(raw_events)

        events = []
        for raw in raw_events:
            try:
                event = RaptorEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=self._normalize_timestamp(raw.get('timestamp', '')),
                    source_host=raw.get('source_host', '') or '',
                    source_ip=raw.get('source_ip', '') or '',
                    dest_host=raw.get('dest_host'),
                    dest_ip=raw.get('dest_ip'),
                    event_type=raw.get('event_type', 'process'),
                    raw=raw.get('raw', ''),
                    sigma_matches=raw.get('sigma_matches', []),
                    ioc_score=self._calculate_ioc_score(raw),
                    enriched=True,
                )
                events.append(event)
            except Exception as e:
                logger.warning(f"Failed to normalize event: {e}")
                continue

        logger.info(f"Normalized {len(events)} events ({sum(1 for e in events if e.sigma_matches)} with Sigma matches)")
        return events

    def _normalize_timestamp(self, ts: str) -> str:
        """Normalize timestamp to ISO8601 format."""
        if not ts:
            return datetime.utcnow().isoformat() + "Z"

        # Already ISO8601
        if 'T' in ts and ('-' in ts[:10]):
            return ts

        # Try common formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%b %d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.year == 1900:  # Syslog format without year
                    dt = dt.replace(year=datetime.utcnow().year)
                return dt.isoformat() + "Z"
            except ValueError:
                continue

        # Try epoch
        try:
            epoch = float(ts)
            if epoch > 1e12:  # milliseconds
                epoch /= 1000
            return datetime.utcfromtimestamp(epoch).isoformat() + "Z"
        except ValueError:
            pass

        return ts  # Return as-is if can't parse

    def _calculate_ioc_score(self, raw_event: Dict) -> float:
        """Calculate a preliminary IoC score based on Sigma matches and event characteristics."""
        score = 0.0
        sigma_matches = raw_event.get('sigma_matches', [])

        # Each sigma match adds to the score
        score += min(len(sigma_matches) * 0.2, 0.6)

        # High-risk technique families boost score
        high_risk_prefixes = ['T1003', 'T1059', 'T1021', 'T1047', 'T1105', 'T1486']
        for match in sigma_matches:
            if any(match.startswith(p) for p in high_risk_prefixes):
                score += 0.15

        # Lateral movement events are inherently suspicious
        if raw_event.get('event_type') == 'lateral':
            score += 0.2

        return min(score, 1.0)
