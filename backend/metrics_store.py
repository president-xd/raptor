"""
RAPTOR | Metrics Store
Thread-safe Prometheus-compatible metrics using prometheus_client.
Counters survive the process lifetime; resets are visible via Prometheus rate().
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        REGISTRY,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROMETHEUS_AVAILABLE = False

# ── Process start time ────────────────────────────────────────────────────────

_STARTED_AT = time.time()

# ── Counters ──────────────────────────────────────────────────────────────────

if _PROMETHEUS_AVAILABLE:
    requests_total = Counter(
        "raptor_requests_total",
        "Total HTTP requests processed by the API middleware",
    )
    requests_by_status = Counter(
        "raptor_requests_by_status_total",
        "Total HTTP requests bucketed by status code",
        ["status"],
    )
    auth_failures_total = Counter(
        "raptor_auth_failures_total",
        "Authentication and authorization failures",
    )
    investigations_created_total = Counter(
        "raptor_investigations_created_total",
        "Investigations successfully queued",
    )
    investigations_completed_total = Counter(
        "raptor_investigations_completed_total",
        "Investigations that reached the 'complete' state",
    )
    investigations_failed_total = Counter(
        "raptor_investigations_failed_total",
        "Investigations that reached the 'failed' state after all retries",
    )
    parser_errors_total = Counter(
        "raptor_parser_errors_total",
        "Individual log lines that failed parsing (dead-letter records)",
    )
    llm_external_blocked_total = Counter(
        "raptor_llm_external_blocked_total",
        "LLM prompts rejected because RAPTOR_ALLOW_EXTERNAL_LLM=false",
    )

    request_latency_seconds = Histogram(
        "raptor_request_latency_seconds",
        "End-to-end HTTP request latency",
        buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )

    uptime_seconds = Gauge(
        "raptor_uptime_seconds",
        "Seconds since the API process started",
    )

    def record_request(status_code: int, duration_s: float) -> None:
        requests_total.inc()
        requests_by_status.labels(status=str(status_code)).inc()
        request_latency_seconds.observe(duration_s)

    def inc_auth_failures(n: int = 1) -> None:
        auth_failures_total.inc(n)

    def inc_investigations_created() -> None:
        investigations_created_total.inc()

    def inc_investigations_completed() -> None:
        investigations_completed_total.inc()

    def inc_investigations_failed() -> None:
        investigations_failed_total.inc()

    def inc_parser_errors(n: int = 1) -> None:
        parser_errors_total.inc(n)

    def inc_llm_external_blocked() -> None:
        llm_external_blocked_total.inc()

    def get_metrics_text() -> tuple[str, str]:
        """Render all registered metrics in Prometheus text exposition format."""
        uptime_seconds.set(max(0.0, time.time() - _STARTED_AT))
        return generate_latest(REGISTRY).decode("utf-8"), CONTENT_TYPE_LATEST

else:
    # Fallback: thread-safe counters via simple int (no prometheus_client installed)
    import threading

    _lock = threading.Lock()
    _counters: dict = {
        "requests_total": 0,
        "auth_failures_total": 0,
        "investigations_created_total": 0,
        "investigations_completed_total": 0,
        "investigations_failed_total": 0,
        "parser_errors_total": 0,
        "llm_external_blocked_total": 0,
        "request_latency_seconds_sum": 0.0,
        "request_latency_seconds_count": 0,
        "requests_by_status": {},
    }

    def record_request(status_code: int, duration_s: float) -> None:
        with _lock:
            _counters["requests_total"] += 1
            _counters["request_latency_seconds_sum"] += duration_s
            _counters["request_latency_seconds_count"] += 1
            bucket = str(status_code)
            _counters["requests_by_status"][bucket] = _counters["requests_by_status"].get(bucket, 0) + 1

    def inc_auth_failures(n: int = 1) -> None:
        with _lock:
            _counters["auth_failures_total"] += n

    def inc_investigations_created() -> None:
        with _lock:
            _counters["investigations_created_total"] += 1

    def inc_investigations_completed() -> None:
        with _lock:
            _counters["investigations_completed_total"] += 1

    def inc_investigations_failed() -> None:
        with _lock:
            _counters["investigations_failed_total"] += 1

    def inc_parser_errors(n: int = 1) -> None:
        with _lock:
            _counters["parser_errors_total"] += n

    def inc_llm_external_blocked() -> None:
        with _lock:
            _counters["llm_external_blocked_total"] += 1

    def get_metrics_text() -> tuple[str, str]:
        """Render Prometheus text format from the fallback in-memory counters."""
        with _lock:
            c = dict(_counters)
        uptime = max(0.0, time.time() - _STARTED_AT)
        count = max(1, c["request_latency_seconds_count"])
        avg = c["request_latency_seconds_sum"] / count

        from config import RAPTOR_DB_ENGINE  # local import avoids top-level cycle

        lines = [
            "# HELP raptor_requests_total Total HTTP requests",
            "# TYPE raptor_requests_total counter",
            f"raptor_requests_total {c['requests_total']}",
            "# HELP raptor_requests_by_status_total Requests by HTTP status",
            "# TYPE raptor_requests_by_status_total counter",
            *(
                f'raptor_requests_by_status_total{{status="{s}"}} {n}'
                for s, n in sorted(c["requests_by_status"].items())
            ),
            "# HELP raptor_request_latency_seconds_sum Total latency seconds",
            "# TYPE raptor_request_latency_seconds_sum counter",
            f"raptor_request_latency_seconds_sum {c['request_latency_seconds_sum']:.6f}",
            "# HELP raptor_request_latency_seconds_count Latency observation count",
            "# TYPE raptor_request_latency_seconds_count counter",
            f"raptor_request_latency_seconds_count {c['request_latency_seconds_count']}",
            "# HELP raptor_request_latency_seconds_avg Mean request latency",
            "# TYPE raptor_request_latency_seconds_avg gauge",
            f"raptor_request_latency_seconds_avg {avg:.6f}",
            "# HELP raptor_auth_failures_total Authentication failures",
            "# TYPE raptor_auth_failures_total counter",
            f"raptor_auth_failures_total {c['auth_failures_total']}",
            "# HELP raptor_investigations_created_total Investigations queued",
            "# TYPE raptor_investigations_created_total counter",
            f"raptor_investigations_created_total {c['investigations_created_total']}",
            "# HELP raptor_investigations_completed_total Investigations completed",
            "# TYPE raptor_investigations_completed_total counter",
            f"raptor_investigations_completed_total {c['investigations_completed_total']}",
            "# HELP raptor_investigations_failed_total Investigations failed",
            "# TYPE raptor_investigations_failed_total counter",
            f"raptor_investigations_failed_total {c['investigations_failed_total']}",
            "# HELP raptor_parser_errors_total Parser dead-letter records",
            "# TYPE raptor_parser_errors_total counter",
            f"raptor_parser_errors_total {c['parser_errors_total']}",
            "# HELP raptor_uptime_seconds Process uptime",
            "# TYPE raptor_uptime_seconds gauge",
            f"raptor_uptime_seconds {uptime:.0f}",
            "# HELP raptor_db_backend Database backend label",
            "# TYPE raptor_db_backend gauge",
            f'raptor_db_backend{{backend="{RAPTOR_DB_ENGINE}"}} 1',
        ]
        return "\n".join(lines) + "\n", "text/plain; version=0.0.4"
