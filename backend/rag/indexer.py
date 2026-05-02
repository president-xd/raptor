"""
RAPTOR | Weaviate Indexer
Indexes ATT&CK STIX objects and threat reports into Weaviate.
Classes: Technique, ThreatReport, Vulnerability (per spec Section 3.3).
"""
import json
import uuid
from typing import List, Dict, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    APT_REPORTS_DIR,
    WEAVIATE_API_KEY,
    WEAVIATE_URL,
    WEAVIATE_GRPC_URL,
    RAG_CHUNK_SIZE,
    RAG_CHUNK_OVERLAP,
)
from attribution.attack_catalog import is_active_attack_pattern, load_stix_bundle
from rag.embeddings import embed_document


def _split_host_port(endpoint: str, default_port: int) -> tuple[str, int]:
    cleaned = endpoint.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in cleaned:
        host, port = cleaned.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    return cleaned, default_port


def get_weaviate_client():
    """Get Weaviate client."""
    import weaviate
    http_host, http_port = _split_host_port(WEAVIATE_URL, 8080)
    grpc_host, grpc_port = _split_host_port(WEAVIATE_GRPC_URL, 50051)
    auth_credentials = weaviate.auth.AuthApiKey(WEAVIATE_API_KEY) if WEAVIATE_API_KEY else None

    try:
        return weaviate.connect_to_custom(
            http_host=http_host,
            http_port=http_port,
            http_secure=False,
            grpc_host=grpc_host,
            grpc_port=grpc_port,
            grpc_secure=False,
            auth_credentials=auth_credentials,
        )
    except Exception:
        return weaviate.connect_to_local(
            host=http_host,
            port=http_port,
            grpc_port=grpc_port,
            auth_credentials=auth_credentials,
        )


def setup_weaviate_schema(client) -> None:
    """Create Weaviate collections for Technique, ThreatReport, Vulnerability."""
    import weaviate.classes.config as wc

    collections = {
        "Technique": [
            wc.Property(name="technique_id", data_type=wc.DataType.TEXT),
            wc.Property(name="name", data_type=wc.DataType.TEXT),
            wc.Property(name="description", data_type=wc.DataType.TEXT),
            wc.Property(name="tactics", data_type=wc.DataType.TEXT_ARRAY),
            wc.Property(name="tactic", data_type=wc.DataType.TEXT),
            wc.Property(name="kill_chain_phase", data_type=wc.DataType.TEXT),
            wc.Property(name="detection", data_type=wc.DataType.TEXT),
            wc.Property(name="platforms", data_type=wc.DataType.TEXT),
        ],
        "ThreatReport": [
            wc.Property(name="title", data_type=wc.DataType.TEXT),
            wc.Property(name="content", data_type=wc.DataType.TEXT),
            wc.Property(name="apt_group", data_type=wc.DataType.TEXT),
            wc.Property(name="source", data_type=wc.DataType.TEXT),
            wc.Property(name="chunk_index", data_type=wc.DataType.INT),
        ],
        "Vulnerability": [
            wc.Property(name="cve_id", data_type=wc.DataType.TEXT),
            wc.Property(name="description", data_type=wc.DataType.TEXT),
            wc.Property(name="related_techniques", data_type=wc.DataType.TEXT),
            wc.Property(name="severity", data_type=wc.DataType.TEXT),
        ],
    }

    for name, properties in collections.items():
        try:
            if client.collections.exists(name):
                logger.info(f"Collection '{name}' already exists, skipping")
                continue
            client.collections.create(
                name=name,
                properties=properties,
                vectorizer_config=wc.Configure.Vectorizer.none(),
            )
            logger.info(f"Created collection: {name}")
        except Exception as e:
            logger.warning(f"Error creating collection {name}: {e}")


def download_attack_stix() -> dict:
    """Download ATT&CK STIX bundle."""
    return load_stix_bundle()


def index_attack_techniques(client, stix_bundle: dict) -> int:
    """Index ATT&CK techniques into Weaviate Technique collection."""
    objects = stix_bundle.get("objects", [])
    techniques = [o for o in objects if is_active_attack_pattern(o)]

    collection = client.collections.get("Technique")
    count = 0

    for tech in techniques:
        # Extract external ID (e.g., T1059.001)
        ext_refs = tech.get("external_references", [])
        tech_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break

        if not tech_id:
            continue

        tactics = []
        for phase_obj in tech.get("kill_chain_phases", []):
            if phase_obj.get("kill_chain_name") != "mitre-attack":
                continue
            tactic_name = phase_obj.get("phase_name", "")
            if tactic_name and tactic_name not in tactics:
                tactics.append(tactic_name)
        phase = tactics[0] if tactics else ""
        tactic = phase.replace("-", " ").title() if phase else ""

        # Build description
        description = tech.get("description", "")
        detection = ""
        # Try to extract detection info
        for ref in ext_refs:
            if "detection" in str(ref).lower():
                detection = ref.get("description", "")

        name = tech.get("name", "")
        platforms = ", ".join(tech.get("x_mitre_platforms", []))

        # Create text for embedding
        embed_text = f"ATT&CK Technique {tech_id}: {name}. {description[:500]}"
        vector = embed_document(embed_text).flatten().tolist()

        try:
            collection.data.insert(
                uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, f"raptor:attack-technique:{tech_id}")),
                properties={
                    "technique_id": tech_id,
                    "name": name,
                    "description": description[:2000],
                    "tactics": tactics,
                    "tactic": tactic,
                    "kill_chain_phase": phase,
                    "detection": detection[:1000],
                    "platforms": platforms,
                },
                vector=vector,
            )
            count += 1
        except Exception as e:
            logger.debug(f"Error indexing technique {tech_id}: {e}")
            continue

    logger.info(f"Indexed {count} ATT&CK techniques into Weaviate")
    return count


def chunk_text(text: str, chunk_size: int = RAG_CHUNK_SIZE, overlap: int = RAG_CHUNK_OVERLAP) -> List[str]:
    """Chunk text into overlapping segments."""
    words = text.split()
    chunks = []
    for i in range(0, len(words), chunk_size - overlap):
        chunk = " ".join(words[i:i + chunk_size])
        if chunk.strip():
            chunks.append(chunk)
    return chunks


def index_threat_reports(client, reports: List[Dict[str, str]]) -> int:
    """Index threat report chunks into Weaviate ThreatReport collection."""
    collection = client.collections.get("ThreatReport")
    count = 0

    for report in reports:
        title = report.get("title", "Unknown")
        content = report.get("content", "")
        apt_group = report.get("apt_group", "Unknown")
        source = report.get("source", "APTNotes")

        chunks = chunk_text(content)
        for i, chunk in enumerate(chunks):
            embed_text = f"{title}: {chunk}"
            vector = embed_document(embed_text).flatten().tolist()

            try:
                collection.data.insert(
                    properties={
                        "title": title,
                        "content": chunk,
                        "apt_group": apt_group,
                        "source": source,
                        "chunk_index": i,
                    },
                    vector=vector,
                )
                count += 1
            except Exception as e:
                logger.debug(f"Error indexing report chunk: {e}")
                continue

    logger.info(f"Indexed {count} threat report chunks into Weaviate")
    return count


def load_threat_report_corpus(stix_bundle: Optional[dict] = None) -> List[Dict[str, str]]:
    """
    Load a real local report corpus from APT_REPORTS_DIR when present.

    Supported formats are .txt, .md, .json, and .jsonl. JSON records may use
    title/content/apt_group/source or title/text/actor/source keys. If no local
    corpus exists, ATT&CK intrusion-set profiles are used as an explicit fallback
    corpus instead of being labeled as external reports.
    """
    reports: List[Dict[str, str]] = []
    if APT_REPORTS_DIR.exists():
        for path in sorted(APT_REPORTS_DIR.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".txt", ".md", ".json", ".jsonl"}:
                continue
            try:
                if path.suffix.lower() == ".jsonl":
                    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        if not line.strip():
                            continue
                        item = json.loads(line)
                        reports.append({
                            "title": item.get("title") or path.stem,
                            "content": item.get("content") or item.get("text") or "",
                            "apt_group": item.get("apt_group") or item.get("actor") or "Unknown",
                            "source": item.get("source") or str(path.relative_to(APT_REPORTS_DIR)),
                        })
                elif path.suffix.lower() == ".json":
                    payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                    items = payload if isinstance(payload, list) else payload.get("reports", [payload])
                    for item in items:
                        reports.append({
                            "title": item.get("title") or path.stem,
                            "content": item.get("content") or item.get("text") or "",
                            "apt_group": item.get("apt_group") or item.get("actor") or "Unknown",
                            "source": item.get("source") or str(path.relative_to(APT_REPORTS_DIR)),
                        })
                else:
                    reports.append({
                        "title": path.stem.replace("_", " ").replace("-", " ").title(),
                        "content": path.read_text(encoding="utf-8", errors="ignore"),
                        "apt_group": "Unknown",
                        "source": str(path.relative_to(APT_REPORTS_DIR)),
                    })
            except Exception as e:
                logger.debug(f"Skipping threat report {path}: {e}")

    reports = [report for report in reports if report.get("content")]
    if reports:
        logger.info(f"Loaded {len(reports)} local threat reports from {APT_REPORTS_DIR}")
        return reports

    if not stix_bundle:
        return []

    fallback_reports = []
    for group in [o for o in stix_bundle.get("objects", []) if o.get("type") == "intrusion-set"]:
        desc = group.get("description", "")
        if not desc:
            continue
        fallback_reports.append({
            "title": f"ATT&CK Threat Profile: {group.get('name', 'Unknown')}",
            "content": desc,
            "apt_group": group.get("name", "Unknown"),
            "source": "MITRE ATT&CK STIX intrusion-set profile",
        })
    logger.warning(
        f"No local threat report corpus found in {APT_REPORTS_DIR}; "
        f"using {len(fallback_reports)} ATT&CK intrusion-set profiles as fallback context"
    )
    return fallback_reports


def run_full_indexing() -> dict:
    """Run the complete indexing pipeline."""
    results = {"techniques": 0, "reports": 0, "status": "success"}
    try:
        client = get_weaviate_client()
        setup_weaviate_schema(client)

        # Index ATT&CK techniques
        stix_bundle = download_attack_stix()
        results["techniques"] = index_attack_techniques(client, stix_bundle)

        reports = load_threat_report_corpus(stix_bundle)
        results["reports"] = index_threat_reports(client, reports)

        client.close()
    except Exception as e:
        logger.error(f"Indexing failed: {e}")
        results["status"] = f"error: {e}"

    return results


if __name__ == "__main__":
    results = run_full_indexing()
    print(f"Indexing results: {json.dumps(results, indent=2)}")
