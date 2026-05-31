"""
RAPTOR | Investigation Pipeline
Background investigation pipeline and worker loop.

All functions here are synchronous — FastAPI runs them in a thread pool, which
keeps the asyncio event loop free for concurrent API requests.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import traceback
import uuid
from typing import Optional

from fastapi import HTTPException
from loguru import logger

from config import (
    ELASTIC_POLL_ENABLED,
    ELASTIC_POLL_INTERVAL_SECONDS,
    ELASTIC_POLL_QUERY,
    ELASTIC_POLL_WINDOW_MINUTES,
    ELASTICSEARCH_URL,
    ELASTIC_INDEX_PREFIX,
    MAX_UPLOAD_BYTES,
    RAPTOR_ALLOW_EXTERNAL_LLM,
    RAPTOR_PROCESS_ROLE,
    RAPTOR_PRODUCTION,
)
from database import (
    _utcnow,
    audit_log,
    claim_next_investigation_job,
    complete_investigation_job,
    db_create,
    db_get,
    db_update,
    enqueue_investigation_job,
    filter_new_elasticsearch_events,
    get_elastic_poll_state,
    increment_elastic_poll_investigations,
    store_evidence_file,
    store_parser_errors,
    update_elastic_poll_state,
)
from models import ElasticPollResponse, InvestigateResponse
from schema import AttackGraph
import metrics_store

WORKER_ID: str = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
_WORKER_STARTED = False
_WORKER_LOCK = threading.Lock()

_EVENT_USER_KEYS = ("user", "username", "User", "account", "SubjectUserName", "TargetUserName")
_EVENT_PROCESS_KEYS = ("process", "process_name", "ProcessName", "Image", "NewProcessName", "image")


def _extract_case_scope(events) -> tuple[list[str], list[str], list[str]]:
    """Derive affected hosts, users, and processes from structured event data.

    Hosts come from the structured source/dest fields; users and processes are a
    best-effort parse of JSON event bodies. This replaces fragile regex scraping
    of free-text evidence summaries in the report generator.
    """
    hosts: list[str] = []
    users: list[str] = []
    processes: list[str] = []

    def _add(bucket: list[str], value) -> None:
        text = str(value or "").strip()
        if text and text not in bucket:
            bucket.append(text)

    for event in events:
        _add(hosts, getattr(event, "source_host", ""))
        _add(hosts, getattr(event, "dest_host", ""))
        raw = getattr(event, "raw", "") or ""
        if not raw.strip().startswith("{"):
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for key in _EVENT_USER_KEYS:
            if data.get(key):
                _add(users, data[key])
                break
        for key in _EVENT_PROCESS_KEYS:
            if data.get(key):
                _add(processes, data[key])
                break

    return hosts, users, processes


def _temporal_sequence_match(attack_sequence) -> bool:
    """True when the observed technique order largely progresses through the
    ATT&CK kill chain (a conservative signal for the attribution temporal bonus)."""
    try:
        from attribution.attack_catalog import (
            TACTIC_ORDER,
            get_technique_metadata,
            normalize_tactic,
        )
    except Exception:
        return False

    indices: list[int] = []
    for tid in attack_sequence or []:
        metadata = get_technique_metadata(tid) or {}
        phase = normalize_tactic(
            metadata.get("kill_chain_phase") or (metadata.get("tactics") or [""])[0]
        )
        if phase in TACTIC_ORDER:
            indices.append(TACTIC_ORDER.index(phase))

    if len(indices) < 3:
        return False
    increases = sum(1 for a, b in zip(indices, indices[1:]) if b > a)
    decreases = sum(1 for a, b in zip(indices, indices[1:]) if b < a)
    return increases >= 2 and increases > decreases


# ── Investigation creation helpers ────────────────────────────────────────────

def start_investigation_from_content(
    log_content: str,
    metadata: Optional[dict] = None,
    raw_bytes: Optional[bytes] = None,
) -> InvestigateResponse:
    """Validate *log_content*, persist a job, and return a queued response."""
    if not log_content or not log_content.strip():
        raise HTTPException(status_code=400, detail="Investigation input is empty")

    byte_count = len(log_content.encode("utf-8", errors="replace"))
    if byte_count > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Input too large ({byte_count} bytes). Max is {MAX_UPLOAD_BYTES}.",
        )

    investigation_id = str(uuid.uuid4())
    db_create(investigation_id, metadata, byte_count)
    store_evidence_file(
        investigation_id,
        raw_bytes if raw_bytes is not None else log_content.encode("utf-8", errors="replace"),
        metadata,
    )
    enqueue_investigation_job(investigation_id, log_content, metadata or {})

    logger.info(f"Investigation {investigation_id} queued ({byte_count} bytes)")
    metrics_store.inc_investigations_created()
    return InvestigateResponse(
        investigation_id=investigation_id,
        status="queued",
        message=f"Investigation started. {byte_count} bytes of logs received.",
    )


# ── Elasticsearch integration ─────────────────────────────────────────────────

def fetch_elasticsearch_logs(
    query: str,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 500,
) -> str:
    """Fetch matching Elasticsearch documents and return them as JSON lines."""
    import re

    if not query or not query.strip():
        raise HTTPException(status_code=400, detail="Elasticsearch query is required")
    if len(query) > 1000:
        raise HTTPException(
            status_code=400, detail="Elasticsearch query is too long"
        )
    if re.search(r'(^|\s)[*?]{2,}|/[^"]{80,}/', query):
        raise HTTPException(
            status_code=400, detail="Elasticsearch query is too broad or expensive"
        )

    try:
        from elasticsearch import Elasticsearch

        client = Elasticsearch(ELASTICSEARCH_URL, request_timeout=10)
        filters = []
        time_range = {}
        if time_range_start:
            time_range["gte"] = time_range_start
        if time_range_end:
            time_range["lte"] = time_range_end
        if time_range:
            filters.append({"range": {"@timestamp": time_range}})

        response = client.search(
            index=f"{ELASTIC_INDEX_PREFIX}*",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {
                                "simple_query_string": {
                                    "query": query,
                                    "default_operator": "and",
                                }
                            }
                        ],
                        "filter": filters,
                    }
                },
                "size": max(1, min(limit, 1000)),
                "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
            },
            ignore_unavailable=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            raise HTTPException(
                status_code=404, detail="No Elasticsearch events matched that query"
            )
        lines = []
        for hit in hits:
            source = hit.get("_source", {}) or {}
            event = dict(source)
            event["_raptor_elastic"] = {
                "index": hit.get("_index", ""),
                "id": hit.get("_id", ""),
                "sort": hit.get("sort", []),
            }
            lines.append(json.dumps(event, default=str))
        return "\n".join(lines)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Elasticsearch investigation query failed: {exc}")
        detail = (
            "Search service temporarily unavailable"
            if RAPTOR_PRODUCTION
            else f"Elasticsearch unavailable: {exc}"
        )
        raise HTTPException(status_code=503, detail=detail)


def run_elasticsearch_poll_once(
    query: str = ELASTIC_POLL_QUERY,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    case_name: str = "",
    apt_filters: Optional[list[str]] = None,
    owner_id: str = "system",
    tenant_id: str = "default",
) -> ElasticPollResponse:
    """Poll Elasticsearch once and queue any returned events as an investigation."""
    started_at = _utcnow()
    update_elastic_poll_state(
        last_polled_at=started_at, last_status="polling", last_error=""
    )
    try:
        content = fetch_elasticsearch_logs(
            query=query,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
        )
    except HTTPException as exc:
        if exc.status_code == 404:
            update_elastic_poll_state(last_status="no_events", last_error="")
            return ElasticPollResponse(
                status="no_events", message=exc.detail, event_bytes=0
            )
        update_elastic_poll_state(last_status="error", last_error=str(exc.detail))
        raise

    content, duplicate_count = filter_new_elasticsearch_events(content)
    if not content.strip():
        update_elastic_poll_state(last_status="duplicate_events", last_error="")
        return ElasticPollResponse(
            status="no_events",
            message=(
                f"All matched events already ingested ({duplicate_count} duplicates)."
            ),
            event_bytes=0,
        )

    metadata: dict = {
        "source": "elasticsearch-poller",
        "filename": "elasticsearch_poll.jsonl",
        "case_name": case_name or f"Elasticsearch poll {started_at}",
        "elastic_query": query,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "apt_filters": apt_filters or [],
        "owner_id": owner_id or "system",
        "tenant_id": tenant_id or "default",
    }
    response = start_investigation_from_content(content, metadata=metadata)
    audit_log(
        "elasticsearch-poller",
        "investigation.created",
        response.investigation_id,
        {
            "source": "elasticsearch-poller",
            "case_name": metadata["case_name"],
            "query": query,
        },
    )
    increment_elastic_poll_investigations()
    update_elastic_poll_state(
        last_status="investigation_created",
        last_error=(
            f"deduped {duplicate_count} replayed events" if duplicate_count else ""
        ),
    )
    return ElasticPollResponse(
        status="investigation_created",
        message="Elasticsearch events queued for RAPTOR analysis.",
        investigation_id=response.investigation_id,
        event_bytes=len(content.encode("utf-8", errors="replace")),
    )


# ── Full investigation pipeline ───────────────────────────────────────────────

def run_investigation(
    investigation_id: str,
    log_content: str,
    metadata: Optional[dict] = None,
) -> None:
    """Execute the end-to-end analysis pipeline in a background thread.

    Must remain a *sync* function so FastAPI's thread-pool runs it without
    blocking the asyncio event loop.
    """
    metadata = metadata or {}
    try:
        db_update(
            investigation_id, status="processing", progress=5,
            current_phase="Parsing logs",
        )

        # Phase 1 — parse and normalise logs
        from ingestion.normalizer import LogNormalizer

        normalizer = LogNormalizer()
        events = normalizer.normalize_content(log_content)
        store_parser_errors(
            investigation_id, getattr(normalizer, "parse_errors", [])
        )
        db_update(
            investigation_id, progress=15,
            current_phase="Log parsing complete", event_count=len(events),
        )
        logger.info(f"[{investigation_id}] Parsed {len(events)} events")

        # Phase 2 — RAG / LLM reasoning
        db_update(
            investigation_id, progress=25,
            current_phase="RAG analysis (LLM reasoning)",
        )
        from rag.pipeline import analyze_events_batch

        analysis = analyze_events_batch(events)
        logger.info(
            f"[{investigation_id}] Analysis: {len(analysis.findings)} findings"
        )

        # Phase 3 — STIX technique validation
        db_update(
            investigation_id, progress=45,
            current_phase="Validating technique IDs (STIX)",
        )
        from attribution.stix_validator import validate_analysis_result

        analysis = validate_analysis_result(analysis)

        # Phase 4 — attack graph
        db_update(
            investigation_id, progress=55,
            current_phase="Building attack graph",
        )
        attack_graph = AttackGraph(
            investigation_id=investigation_id, nodes=[], edges=[]
        )
        graph_json = attack_graph.model_dump_json()
        neo4j = None
        try:
            from graph.neo4j_client import Neo4jClient
            from graph.graph_builder import GraphBuilder

            neo4j = Neo4jClient()
            if neo4j.is_connected():
                neo4j.setup_schema()
                builder = GraphBuilder(neo4j)
                attack_graph = builder.build_graph(investigation_id, events, analysis)
                graph_json = attack_graph.model_dump_json()
            else:
                # In-memory fallback when Neo4j is unavailable
                builder = GraphBuilder.__new__(GraphBuilder)  # type: ignore[call-arg]
                _noop = type(
                    "Mock",
                    (),
                    {
                        "run_write": lambda *a, **kw: None,
                        "run_query": lambda *a, **kw: [],
                    },
                )()
                builder.neo4j = _noop
                builder.investigation_id = investigation_id
                attack_graph = builder._build_sigma_graph(
                    builder._extract_hosts(events),
                    builder._extract_users(events),
                    builder._extract_techniques(analysis),
                    events,
                    analysis,
                )
                graph_json = attack_graph.model_dump_json()
        except Exception as exc:
            logger.warning(f"Graph building error (non-fatal): {exc}")
        finally:
            if neo4j:
                neo4j.close()

        # Phase 5 — APT attribution
        db_update(
            investigation_id, progress=70,
            current_phase="APT attribution scoring",
        )
        from attribution.apt_profiles import load_apt_profiles
        from attribution.confidence import calculate_confidence

        observed_ttps: set[str] = set()
        for finding in analysis.findings:
            if finding.technique_id:
                observed_ttps.add(finding.technique_id)
        for tid in analysis.attack_sequence:
            observed_ttps.add(tid)

        apt_profiles = load_apt_profiles()
        apt_filters = [
            str(f).strip().lower()
            for f in metadata.get("apt_filters", [])
            if str(f).strip()
        ]
        if apt_filters:
            filtered = {
                name: profile
                for name, profile in apt_profiles.items()
                if any(
                    fv in haystack
                    for fv in apt_filters
                    for haystack in [name.lower()] + [
                        str(a).lower() for a in profile.get("aliases", [])
                    ]
                )
            }
            apt_profiles = filtered or apt_profiles
            analysis.anomalies.append(
                f"APT focus filter applied: {', '.join(metadata.get('apt_filters', []))}"
                if filtered
                else "APT focus filter matched no profiles; scored full library."
            )

        campaign_hours = 0.0
        if events:
            timestamps = sorted(e.timestamp for e in events if e.timestamp)
            if len(timestamps) >= 2:
                try:
                    from datetime import datetime as _dt

                    t1 = _dt.fromisoformat(timestamps[0].replace("Z", "+00:00"))
                    t2 = _dt.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
                    campaign_hours = (t2 - t1).total_seconds() / 3600
                except Exception:
                    pass

        attribution_results = calculate_confidence(
            observed_ttps=observed_ttps,
            apt_profiles=apt_profiles,
            campaign_duration_hours=campaign_hours,
            temporal_sequence_match=_temporal_sequence_match(analysis.attack_sequence),
        )
        attribution_json = json.dumps([a.model_dump() for a in attribution_results])
        logger.info(
            f"[{investigation_id}] Attribution: "
            f"{attribution_results[0].apt_name if attribution_results else 'None'}"
        )

        # Phase 6 — narrative report
        db_update(
            investigation_id, progress=85,
            current_phase="Generating enterprise report",
        )
        from report.generator import generate_report

        affected_hosts, observed_users, observed_processes = _extract_case_scope(events)
        graph_summary = {
            "hosts_compromised": sum(
                1
                for n in (attack_graph.nodes or [])
                if n.node_type == "host" and bool(n.metadata.get("compromised"))
            )
            if attack_graph
            else sum(1 for e in events if e.event_type == "lateral"),
            "total_events": len(events),
            "unique_hosts": len(set(e.source_host for e in events if e.source_host)),
            "campaign_duration_hours": campaign_hours,
            "affected_hosts": affected_hosts[:12],
            "observed_users": observed_users[:12],
            "observed_processes": observed_processes[:12],
        }
        narrative = generate_report(
            analysis,
            attribution_results,
            graph_summary,
            investigation_id,
            report_name=str(metadata.get("case_name") or metadata.get("filename") or ""),
        )

        db_update(
            investigation_id,
            status="complete",
            progress=100,
            current_phase="Investigation complete",
            findings_json=json.dumps([f.model_dump() for f in analysis.findings]),
            attack_sequence_json=json.dumps(analysis.attack_sequence),
            anomalies_json=json.dumps(analysis.anomalies),
            attribution_json=attribution_json,
            graph_json=graph_json,
            narrative_report=narrative,
            technique_count=len(analysis.findings),
            completed_at=_utcnow(),
        )
        logger.info(f"[{investigation_id}] Investigation complete")
        metrics_store.inc_investigations_completed()

    except Exception as exc:
        logger.error(
            f"[{investigation_id}] Investigation failed: {exc}\n"
            f"{traceback.format_exc()}"
        )
        db_update(
            investigation_id,
            status="failed",
            error=str(exc),
            current_phase=f"Failed: {str(exc)[:200]}",
        )
        metrics_store.inc_investigations_failed()


# ── Worker loop ───────────────────────────────────────────────────────────────

def investigation_worker_loop() -> None:
    logger.info(f"Investigation worker started: {WORKER_ID}")
    while True:
        job = claim_next_investigation_job()
        if not job:
            time.sleep(2)
            continue
        try:
            payload = json.loads(job.get("payload_json") or "{}")
            run_investigation(
                job["investigation_id"],
                payload.get("log_content", ""),
                payload.get("metadata", {}),
            )
            record = db_get(job["investigation_id"]) or {}
            failed = record.get("status") == "failed"
            complete_investigation_job(
                job["id"], failed=failed, error=record.get("error") or ""
            )
        except Exception as exc:
            logger.error(
                f"Worker failed job {job.get('investigation_id')}: {exc}"
            )
            complete_investigation_job(job["id"], failed=True, error=str(exc))


def start_investigation_worker() -> None:
    global _WORKER_STARTED
    with _WORKER_LOCK:
        if _WORKER_STARTED:
            return
        _WORKER_STARTED = True
    thread = threading.Thread(
        target=investigation_worker_loop, daemon=True, name="raptor-worker"
    )
    thread.start()


def elastic_poll_loop() -> None:
    logger.info(
        f"Elasticsearch poller started: query={ELASTIC_POLL_QUERY!r}, "
        f"interval={ELASTIC_POLL_INTERVAL_SECONDS}s"
    )
    while True:
        try:
            run_elasticsearch_poll_once(
                query=ELASTIC_POLL_QUERY,
                time_range_start=f"now-{ELASTIC_POLL_WINDOW_MINUTES}m",
                time_range_end="now",
                case_name="Continuous Elasticsearch poll",
            )
        except Exception as exc:
            logger.warning(f"Elasticsearch poller iteration failed: {exc}")
            update_elastic_poll_state(last_status="error", last_error=str(exc))
        time.sleep(max(30, ELASTIC_POLL_INTERVAL_SECONDS))


def start_optional_services() -> None:
    if RAPTOR_PROCESS_ROLE not in {"all", "worker"}:
        logger.info(
            f"Background services disabled for "
            f"RAPTOR_PROCESS_ROLE={RAPTOR_PROCESS_ROLE!r}"
        )
        return
    start_investigation_worker()
    if ELASTIC_POLL_ENABLED:
        thread = threading.Thread(
            target=elastic_poll_loop, daemon=True, name="raptor-es-poller"
        )
        thread.start()


def run_worker_process() -> None:
    """Entry point for a dedicated worker container (not the API process)."""
    logger.info(f"Starting RAPTOR worker process ({WORKER_ID})")
    if ELASTIC_POLL_ENABLED:
        thread = threading.Thread(
            target=elastic_poll_loop, daemon=True, name="raptor-es-poller"
        )
        thread.start()
    investigation_worker_loop()
