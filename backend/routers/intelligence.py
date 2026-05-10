"""
RAPTOR | Intelligence Router
GET  /api/v1/threat-feeds/cisa-kev               — CISA KEV catalog
POST /api/v1/threat-feeds/cisa-kev/sync          — force refresh
POST /api/v1/ingest/elasticsearch/poll           — on-demand poll
GET  /api/v1/ingest/elasticsearch/status         — poller state
PUT  /api/v1/ingest/elasticsearch/config         — update poller config
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from auth_core import audit_log, enforce_rate_limit, require_role
from config import (
    CISA_KEV_URL,
    ELASTIC_POLL_INTERVAL_SECONDS,
    ELASTIC_POLL_QUERY,
    ELASTIC_POLL_WINDOW_MINUTES,
)
from database import (
    fetch_cisa_kev,
    get_elastic_poll_state,
    update_elastic_poll_state,
)
from models import (
    CisaKevResponse,
    ElasticConfigRequest,
    ElasticPollRequest,
    ElasticPollResponse,
    ElasticPollStatus,
)
from pipeline_runner import run_elasticsearch_poll_once

router = APIRouter(tags=["intelligence"])


@router.get("/api/v1/threat-feeds/cisa-kev", response_model=CisaKevResponse)
def get_cisa_kev(
    request: Request,
    query: str = "",
    limit: int = 50,
    refresh: bool = False,
) -> dict:
    """Fetch the CISA Known Exploited Vulnerabilities catalog (cached)."""
    require_role(request, "viewer")
    payload = fetch_cisa_kev(refresh=refresh)
    vulnerabilities = payload.get("vulnerabilities", [])

    if query:
        needle = query.lower()
        import json
        vulnerabilities = [
            item
            for item in vulnerabilities
            if needle in json.dumps(item, default=str).lower()
        ]

    safe_limit = max(1, min(limit, 500))
    selected = vulnerabilities[:safe_limit]
    audit_log(
        request,
        "threat_feed.cisa_kev.viewed",
        None,
        {"query": query, "limit": safe_limit, "refresh": refresh, "returned": len(selected)},
    )
    return {
        "title": payload.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
        "catalogVersion": payload.get("catalogVersion", ""),
        "dateReleased": payload.get("dateReleased", ""),
        "count": len(vulnerabilities),
        "source": payload.get("_raptor_source", CISA_KEV_URL),
        "cached_at": payload.get("_raptor_cached_at", ""),
        "vulnerabilities": selected,
    }


@router.post("/api/v1/threat-feeds/cisa-kev/sync", response_model=CisaKevResponse)
def sync_cisa_kev(request: Request) -> dict:
    """Force refresh the CISA KEV catalog cache."""
    enforce_rate_limit(request, "connector")
    require_role(request, "analyst")
    payload = fetch_cisa_kev(refresh=True)
    vulnerabilities = payload.get("vulnerabilities", [])
    audit_log(
        request,
        "threat_feed.cisa_kev.synced",
        None,
        {"count": len(vulnerabilities), "source": CISA_KEV_URL},
    )
    return {
        "title": payload.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
        "catalogVersion": payload.get("catalogVersion", ""),
        "dateReleased": payload.get("dateReleased", ""),
        "count": len(vulnerabilities),
        "source": payload.get("_raptor_source", CISA_KEV_URL),
        "cached_at": payload.get("_raptor_cached_at", ""),
        "vulnerabilities": vulnerabilities[:50],
    }


@router.post("/api/v1/ingest/elasticsearch/poll", response_model=ElasticPollResponse)
def poll_elasticsearch(
    request: Request, payload: ElasticPollRequest
) -> ElasticPollResponse:
    """Poll Elasticsearch on demand and queue any new events as an investigation."""
    enforce_rate_limit(request, "connector")
    principal = require_role(request, "analyst")
    response = run_elasticsearch_poll_once(
        query=payload.query,
        time_range_start=payload.time_range_start,
        time_range_end=payload.time_range_end,
        case_name=payload.case_name,
        apt_filters=payload.apt_filters,
        owner_id=principal.get("user_id") or principal.get("actor"),
        tenant_id=principal.get("tenant_id", "default"),
    )
    audit_log(
        request,
        "elasticsearch.poll",
        response.investigation_id,
        {"status": response.status, "query": payload.query, "event_bytes": response.event_bytes},
    )
    return response


@router.get(
    "/api/v1/ingest/elasticsearch/status", response_model=ElasticPollStatus
)
async def get_elasticsearch_poll_status(request: Request) -> ElasticPollStatus:
    """Return the current Elasticsearch poller configuration and last-run state."""
    require_role(request, "viewer")
    state = get_elastic_poll_state()
    audit_log(request, "elasticsearch.poll_status.viewed", None, {})
    return ElasticPollStatus(
        enabled=state.get("enabled", False),
        query=state.get("query", ELASTIC_POLL_QUERY),
        interval_seconds=state.get("interval_seconds", ELASTIC_POLL_INTERVAL_SECONDS),
        window_minutes=state.get("window_minutes", ELASTIC_POLL_WINDOW_MINUTES),
        last_polled_at=state.get("last_polled_at", ""),
        last_status=state.get("last_status", ""),
        last_error=state.get("last_error", ""),
        investigation_count=state.get("investigation_count", 0),
    )


@router.put(
    "/api/v1/ingest/elasticsearch/config", response_model=ElasticPollStatus
)
async def update_elasticsearch_config(
    request: Request, payload: ElasticConfigRequest
) -> ElasticPollStatus:
    """Update the Elasticsearch poller configuration at runtime."""
    require_role(request, "admin")
    updates: dict = {}
    if payload.enabled is not None:
        updates["enabled"] = 1 if payload.enabled else 0
    if payload.query is not None:
        updates["query"] = payload.query
    if payload.interval_seconds is not None:
        updates["interval_seconds"] = payload.interval_seconds
    if payload.window_minutes is not None:
        updates["window_minutes"] = payload.window_minutes
    if updates:
        update_elastic_poll_state(**updates)
    audit_log(request, "elasticsearch.config.updated", None, {"updates": updates})
    state = get_elastic_poll_state()
    return ElasticPollStatus(
        enabled=state.get("enabled", False),
        query=state.get("query", ELASTIC_POLL_QUERY),
        interval_seconds=state.get("interval_seconds", ELASTIC_POLL_INTERVAL_SECONDS),
        window_minutes=state.get("window_minutes", ELASTIC_POLL_WINDOW_MINUTES),
        last_polled_at=state.get("last_polled_at", ""),
        last_status=state.get("last_status", ""),
        last_error=state.get("last_error", ""),
        investigation_count=state.get("investigation_count", 0),
    )
