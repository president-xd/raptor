"""
RAPTOR | Full RAG Pipeline
Events → Sigma → Retrieve → Augmented Prompt → LLM → Validated JSON
This is the intelligence core (spec Section 3.3 Query Pipeline).
Every LLM call goes through retrieval. No naked LLM calls.
"""
import json
from typing import List, Dict, Any, Optional
from openai import OpenAI
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from llm_redactor import redact
from config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_PROVIDER, LLM_MODEL,
    LLM_FALLBACK_MODEL, LLM_TEMPERATURE, LLM_MAX_TOKENS,
    LLM_TOP_P, LLM_TIMEOUT_SECONDS, LLM_STREAM_RESPONSES,
    LLM_ENABLE_THINKING, LLM_CLEAR_THINKING, RAPTOR_ALLOW_EXTERNAL_LLM,
    LOG_ANALYSIS_SYSTEM_PROMPT, RAG_RERANK_K,
)
from schema import RaptorEvent, Finding, AnalysisResult
from attribution.attack_catalog import get_technique_metadata
from rag.retriever import HybridRetriever
from rag.reranker import rerank_technique_results, rerank_report_results


# OpenAI-compatible LLM client.
_llm_client = None

def get_llm_client() -> OpenAI:
    global _llm_client
    if not RAPTOR_ALLOW_EXTERNAL_LLM:
        raise RuntimeError("External LLM calls are disabled by RAPTOR_ALLOW_EXTERNAL_LLM=false")
    if not LLM_API_KEY:
        raise RuntimeError(f"LLM_API_KEY is not configured for provider {LLM_PROVIDER}")

    if _llm_client is None:
        _llm_client = OpenAI(
            base_url=LLM_BASE_URL,
            api_key=LLM_API_KEY,
            timeout=LLM_TIMEOUT_SECONDS,
            max_retries=0,
        )
    return _llm_client


def _llm_extra_body(model: str) -> Optional[Dict[str, Any]]:
    if not LLM_ENABLE_THINKING:
        return None
    if not model.startswith("z-ai/"):
        return None
    return {
        "chat_template_kwargs": {
            "enable_thinking": True,
            "clear_thinking": LLM_CLEAR_THINKING,
        }
    }


def _chat_completion_content(client: OpenAI, args: Dict[str, Any], model: str) -> str:
    """Return assistant content while discarding provider reasoning streams."""
    if not LLM_STREAM_RESPONSES:
        response = client.chat.completions.create(**args)
        if not response or not getattr(response, "choices", None) or len(response.choices) == 0:
            logger.warning(f"LLM returned empty/null choices via {model}")
            raise ValueError(f"LLM returned no choices via {model}")
        return response.choices[0].message.content or ""

    content_parts = []
    reasoning_chars = 0
    for chunk in client.chat.completions.create(**args, stream=True):
        if not getattr(chunk, "choices", None):
            continue
        if len(chunk.choices) == 0 or getattr(chunk.choices[0], "delta", None) is None:
            continue

        delta = chunk.choices[0].delta
        reasoning = getattr(delta, "reasoning_content", None)
        if reasoning:
            reasoning_chars += len(reasoning)
        content = getattr(delta, "content", None)
        if content is not None:
            content_parts.append(content)

    content = "".join(content_parts)
    if reasoning_chars:
        logger.debug(f"Discarded {reasoning_chars} reasoning chars from {model} stream")
    return content


def extract_candidate_signatures(events: List[RaptorEvent]) -> List[str]:
    """Step 1: Extract candidate TTP signatures from events (regex + Sigma matches)."""
    candidates = set()
    for event in events:
        # Collect all Sigma matches
        for match in event.sigma_matches:
            candidates.add(match)
        # Also extract keywords for search queries
    return list(candidates)


def build_retrieval_queries(events: List[RaptorEvent], sigma_matches: List[str]) -> List[str]:
    """Build search queries from events and their Sigma matches."""
    queries = []

    # Query per unique sigma match
    for tid in sigma_matches:
        queries.append(f"ATT&CK technique {tid}")

    # Query per unique event type cluster
    event_descriptions = set()
    for event in events:
        desc = f"{event.event_type}: {event.raw[:200]}"
        event_descriptions.add(desc)

    # Take top 5 most interesting event descriptions
    scored = sorted(event_descriptions, key=lambda x: len(x), reverse=True)
    queries.extend(scored[:5])

    return queries[:10]  # Cap at 10 queries


def retrieve_context(retriever: HybridRetriever, queries: List[str]) -> Dict[str, List[Dict]]:
    """Step 2-3: Retrieve and rerank context from Weaviate."""
    all_techniques = []
    all_reports = []

    for query in queries:
        results = retriever.search_all(query)
        all_techniques.extend(results.get("techniques", []))
        all_reports.extend(results.get("reports", []))

    # Deduplicate by technique_id
    seen_techniques = set()
    unique_techniques = []
    for t in all_techniques:
        tid = t.get("technique_id", "")
        if tid and tid not in seen_techniques:
            seen_techniques.add(tid)
            unique_techniques.append(t)

    # Rerank (Step 3)
    combined_query = " ".join(queries[:3])
    reranked_techniques = rerank_technique_results(combined_query, unique_techniques, top_k=RAG_RERANK_K)
    reranked_reports = rerank_report_results(combined_query, all_reports, top_k=3)

    return {
        "techniques": reranked_techniques,
        "reports": reranked_reports,
    }


def build_augmented_prompt(events: List[RaptorEvent], context: Dict[str, List[Dict]]) -> str:
    """Step 4: Construct augmented prompt with events + retrieved context."""
    # Format events — cap at 20 to stay within token budget
    event_lines = []
    for e in events[:20]:
        sigma_str = ','.join(e.sigma_matches) if e.sigma_matches else 'none'
        event_lines.append(
            f"[{e.event_type}] {redact(e.source_host)} Sigma:{sigma_str} | {redact(e.raw[:300])[:150]}"
        )

    # Format retrieved ATT&CK context (cap description at 120 chars)
    technique_context = []
    for t in context.get("techniques", []):
        tactic_text = ", ".join(t.get("tactics") or [t.get("kill_chain_phase", "")])
        technique_context.append(
            f"- {t.get('technique_id', '')}: {t.get('name', '')} ({tactic_text})"
            f" — {t.get('description', '')[:120]}"
        )

    # Format retrieved threat reports (cap at 2, 150 chars each)
    report_context = []
    for r in context.get("reports", [])[:2]:
        report_context.append(
            f"- [{r.get('apt_group', 'Unknown')}]: {r.get('content', '')[:150]}"
        )

    prompt = f"""Analyze these security events using the retrieved ATT&CK context.

=== EVENTS ({len(event_lines)}) ===
{chr(10).join(event_lines)}

=== ATT&CK TECHNIQUES ===
{chr(10).join(technique_context) if technique_context else 'No techniques retrieved — use Sigma matches directly.'}

=== THREAT INTEL ===
{chr(10).join(report_context) if report_context else 'None.'}

Map suspicious events to ATT&CK techniques. Use only IDs from the context above or from Sigma matches shown."""

    return prompt



def _phase_for_technique(technique_id: str) -> str:
    """Canonical ATT&CK tactic for local fallback analysis."""
    metadata = get_technique_metadata(technique_id)
    if not metadata:
        return "unknown"
    tactics = metadata.get("tactics") or []
    return tactics[0] if tactics else "unknown"


def _tactics_for_technique(technique_id: str) -> List[str]:
    metadata = get_technique_metadata(technique_id)
    if not metadata:
        return []
    return list(metadata.get("tactics") or [])


def _name_for_technique(technique_id: str, fallback: str = "") -> str:
    metadata = get_technique_metadata(technique_id)
    if metadata and metadata.get("name"):
        return metadata["name"]
    return fallback or technique_id


def _evidence_host(event: RaptorEvent) -> str:
    """Best-effort host label for an event, preferring the structured fields."""
    return (getattr(event, "source_host", "") or getattr(event, "dest_host", "") or "").strip()


def _clean_evidence_summary(event: RaptorEvent) -> str:
    """A clean, analyst-readable evidence sentence — never raw log text."""
    host = _evidence_host(event)
    location = f" on host {host}" if host else ""
    return f"Matched local detection signatures in {event.event_type} telemetry{location}."


def build_sigma_fallback_analysis(events: List[RaptorEvent], reason: str = "") -> AnalysisResult:
    """Create a deterministic analysis from normalized events and Sigma matches."""
    try:
        from ingestion.sigma_matcher import SIGMA_SIGNATURES
    except Exception:
        SIGMA_SIGNATURES = {}

    findings_by_tid: Dict[str, Finding] = {}
    attack_sequence: List[str] = []

    for event in events:
        for technique_id in event.sigma_matches:
            if technique_id not in attack_sequence:
                attack_sequence.append(technique_id)

            signature = SIGMA_SIGNATURES.get(technique_id, {})
            tactics = _tactics_for_technique(technique_id)
            finding = findings_by_tid.get(technique_id)
            if not finding:
                # Evidence text is a clean sentence built from structured event
                # fields. Raw log content is never concatenated here — it caused
                # raw JSON to leak into downstream reports and exports.
                findings_by_tid[technique_id] = Finding(
                    event_ids=[],
                    technique_id=technique_id,
                    technique_name=_name_for_technique(technique_id, signature.get("name", technique_id)),
                    tactics=tactics,
                    kill_chain_phase=tactics[0] if tactics else _phase_for_technique(technique_id),
                    confidence="high" if event.ioc_score >= 0.5 else "medium",
                    evidence_summary=_clean_evidence_summary(event),
                    apt_indicators=[],
                )
                finding = findings_by_tid[technique_id]

            finding.event_ids.append(event.event_id)

    anomalies = []
    if reason:
        anomalies.append(f"LLM/RAG fallback used: {reason[:180]}")
    if not findings_by_tid and events:
        anomalies.append("No local Sigma signatures matched the supplied logs.")

    for finding in findings_by_tid.values():
        finding.event_ids = sorted(set(finding.event_ids))

    logger.warning(
        f"Using Sigma fallback analysis: {len(findings_by_tid)} findings, "
        f"{len(attack_sequence)} sequence steps"
    )
    return AnalysisResult(
        findings=list(findings_by_tid.values()),
        attack_sequence=attack_sequence,
        anomalies=anomalies,
    )


def call_llm(system_prompt: str, user_prompt: str, model: str = None, _retries: int = 0) -> str:
    """Step 5: Call the configured OpenAI-compatible LLM with robust error handling."""
    import time
    client = get_llm_client()
    model = model or LLM_MODEL
    MAX_RETRIES = 3

    try:
        request_args = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": LLM_TEMPERATURE,
            "top_p": LLM_TOP_P,
            "max_tokens": LLM_MAX_TOKENS,
            "timeout": LLM_TIMEOUT_SECONDS,
        }
        extra_body = _llm_extra_body(model)
        if extra_body:
            request_args["extra_body"] = extra_body

        content = _chat_completion_content(client, request_args, model)
        if not content:
            logger.warning(f"LLM returned empty content via {model}")
            raise ValueError(f"LLM returned empty content via {model}")

        logger.info(f"LLM response received ({len(content)} chars) via {LLM_PROVIDER}/{model}")
        return content

    except Exception as e:
        error_str = str(e)
        is_rate_limit = "429" in error_str or "rate" in error_str.lower()

        logger.error(f"LLM call failed with {model}: {e}")

        # Retry same model on rate-limit with backoff
        if is_rate_limit and _retries < MAX_RETRIES:
            wait_time = 2 ** (_retries + 1)  # 2, 4, 8 seconds
            logger.info(f"Rate-limited on {model}, waiting {wait_time}s before retry {_retries + 1}/{MAX_RETRIES}")
            time.sleep(wait_time)
            return call_llm(system_prompt, user_prompt, model=model, _retries=_retries + 1)

        # Try fallback model
        if model != LLM_FALLBACK_MODEL:
            logger.info(f"Retrying with fallback model: {LLM_FALLBACK_MODEL}")
            return call_llm(system_prompt, user_prompt, model=LLM_FALLBACK_MODEL, _retries=0)

        raise


def parse_llm_response(response: str) -> AnalysisResult:
    """Parse and validate LLM JSON response into AnalysisResult."""
    # Extract JSON from response (handle markdown code blocks)
    json_str = response.strip()
    if json_str.startswith("```"):
        lines = json_str.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.strip().startswith("```") and not in_block:
                in_block = True
                continue
            elif line.strip() == "```" and in_block:
                in_block = False
                continue
            elif in_block:
                json_lines.append(line)
        json_str = "\n".join(json_lines)

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse LLM JSON response: {e}")
        # Try to extract JSON object from response
        import re
        match = re.search(r'\{.*\}', json_str, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                logger.error("Could not extract valid JSON from LLM response")
                return AnalysisResult()
        else:
            return AnalysisResult()

    # Build AnalysisResult
    findings = []
    for f in data.get("findings", []):
        findings.append(Finding(
            event_ids=f.get("event_ids", []),
            technique_id=f.get("technique_id", ""),
            technique_name=f.get("technique_name", ""),
            tactics=f.get("tactics", []),
            kill_chain_phase=f.get("kill_chain_phase", ""),
            confidence=f.get("confidence", "low"),
            evidence_summary=f.get("evidence_summary", ""),
            apt_indicators=f.get("apt_indicators", []),
        ))

    return AnalysisResult(
        findings=findings,
        attack_sequence=data.get("attack_sequence", []),
        anomalies=data.get("anomalies", []),
    )


def analyze_events(events: List[RaptorEvent], retriever: Optional[HybridRetriever] = None) -> AnalysisResult:
    """
    Full RAG pipeline: Events → Retrieve → Augment → LLM → Validate.
    This is THE core function of RAPTOR.
    """
    logger.info(f"Starting RAG analysis of {len(events)} events")

    # Step 1: Extract candidate TTP signatures
    sigma_matches = extract_candidate_signatures(events)
    logger.info(f"Step 1: Extracted {len(sigma_matches)} candidate signatures: {sigma_matches}")

    # Step 2-3: Retrieve and rerank context
    own_retriever = False
    if retriever is None:
        retriever = HybridRetriever()
        own_retriever = True

    queries = build_retrieval_queries(events, sigma_matches)
    context = retrieve_context(retriever, queries)
    logger.info(f"Step 2-3: Retrieved {len(context.get('techniques', []))} techniques, "
                f"{len(context.get('reports', []))} reports")

    # Step 4: Build augmented prompt
    prompt = build_augmented_prompt(events, context)
    logger.info(f"Step 4: Augmented prompt built ({len(prompt)} chars)")

    # Step 5: LLM inference. If the provider is unavailable, keep the product
    # functional by falling back to validated local detections.
    try:
        response = call_llm(LOG_ANALYSIS_SYSTEM_PROMPT, prompt)
        result = parse_llm_response(response)
        if not result.findings and sigma_matches:
            result = build_sigma_fallback_analysis(events, "LLM returned no findings")
    except Exception as e:
        logger.error(f"LLM analysis failed, falling back to Sigma detections: {e}")
        result = build_sigma_fallback_analysis(events, str(e))

    # Step 6: Parse and return
    logger.info(f"Step 5-6: Analysis complete - {len(result.findings)} findings, "
                f"{len(result.attack_sequence)} attack sequence steps")

    if own_retriever:
        retriever.close()

    return result


def analyze_events_batch(events: List[RaptorEvent], window_minutes: int = 15) -> AnalysisResult:
    """
    Batch analysis with map-reduce for large event sets.
    Per spec Section 3.5: analyze each 15-min window independently,
    then synthesize with a consolidation LLM call.
    """
    from datetime import datetime, timezone

    if len(events) <= 50:
        return analyze_events(events)

    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # Split into time windows
    windows = []
    current_window = []
    window_start = None

    for event in sorted_events:
        try:
            ts = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        if window_start is None:
            window_start = ts

        if (ts - window_start).total_seconds() > window_minutes * 60:
            if current_window:
                windows.append(current_window)
            current_window = [event]
            window_start = ts
        else:
            current_window.append(event)

    if current_window:
        windows.append(current_window)

    logger.info(f"Split {len(events)} events into {len(windows)} time windows")

    # Map: analyze each window
    retriever = HybridRetriever()
    window_results = []
    for i, window in enumerate(windows):
        logger.info(f"Analyzing window {i+1}/{len(windows)} ({len(window)} events)")
        result = analyze_events(window, retriever=retriever)
        window_results.append(result)

    retriever.close()

    # Reduce: merge all results
    merged = AnalysisResult()
    all_findings = []
    all_attack_seq = []
    all_anomalies = set()

    for result in window_results:
        all_findings.extend(result.findings)
        all_attack_seq.extend(result.attack_sequence)
        all_anomalies.update(result.anomalies)

    # Deduplicate findings by technique_id
    seen_techniques = {}
    for f in all_findings:
        tid = f.technique_id
        if tid not in seen_techniques:
            seen_techniques[tid] = f
        else:
            # Merge event_ids
            existing = seen_techniques[tid]
            existing.event_ids.extend(f.event_ids)
            existing.event_ids = list(set(existing.event_ids))
            # Keep higher confidence
            conf_order = {"high": 3, "medium": 2, "low": 1}
            if conf_order.get(f.confidence, 0) > conf_order.get(existing.confidence, 0):
                seen_techniques[tid] = f

    merged.findings = list(seen_techniques.values())
    # Deduplicate attack sequence while preserving order
    seen = set()
    for tid in all_attack_seq:
        if tid not in seen:
            seen.add(tid)
            merged.attack_sequence.append(tid)
    merged.anomalies = list(all_anomalies)

    return merged
