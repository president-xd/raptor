"""
RAPTOR | Weaviate Indexer
Indexes ATT&CK STIX objects and threat reports into Weaviate.
Classes: Technique, ThreatReport, Vulnerability (per spec Section 3.3).
"""
import json
import requests
from typing import List, Dict, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import WEAVIATE_URL, ATTACK_STIX_URL, STIX_DIR, RAG_CHUNK_SIZE, RAG_CHUNK_OVERLAP
from rag.embeddings import embed_document, get_embedding_dimension


def get_weaviate_client():
    """Get Weaviate client."""
    import weaviate
    client = weaviate.connect_to_local(
        host=WEAVIATE_URL.replace("http://", "").split(":")[0],
        port=int(WEAVIATE_URL.split(":")[-1]),
    )
    return client


def setup_weaviate_schema(client) -> None:
    """Create Weaviate collections for Technique, ThreatReport, Vulnerability."""
    import weaviate.classes.config as wc

    collections = {
        "Technique": [
            wc.Property(name="technique_id", data_type=wc.DataType.TEXT),
            wc.Property(name="name", data_type=wc.DataType.TEXT),
            wc.Property(name="description", data_type=wc.DataType.TEXT),
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
    cache_path = STIX_DIR / "enterprise-attack.json"
    if cache_path.exists():
        logger.info(f"Loading cached STIX bundle from {cache_path}")
        with open(cache_path, 'r') as f:
            return json.load(f)

    logger.info(f"Downloading ATT&CK STIX bundle from {ATTACK_STIX_URL}")
    resp = requests.get(ATTACK_STIX_URL, timeout=120)
    resp.raise_for_status()
    data = resp.json()

    with open(cache_path, 'w') as f:
        json.dump(data, f)
    logger.info(f"Saved STIX bundle to {cache_path} ({len(data.get('objects', []))} objects)")
    return data


def index_attack_techniques(client, stix_bundle: dict) -> int:
    """Index ATT&CK techniques into Weaviate Technique collection."""
    objects = stix_bundle.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern"]

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

        # Extract kill chain phase
        kill_chain = tech.get("kill_chain_phases", [])
        phase = kill_chain[0].get("phase_name", "") if kill_chain else ""
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
                properties={
                    "technique_id": tech_id,
                    "name": name,
                    "description": description[:2000],
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


def run_full_indexing() -> dict:
    """Run the complete indexing pipeline."""
    results = {"techniques": 0, "reports": 0, "status": "success"}
    try:
        client = get_weaviate_client()
        setup_weaviate_schema(client)

        # Index ATT&CK techniques
        stix_bundle = download_attack_stix()
        results["techniques"] = index_attack_techniques(client, stix_bundle)

        # Generate synthetic threat reports from STIX groups
        objects = stix_bundle.get("objects", [])
        groups = [o for o in objects if o.get("type") == "intrusion-set"]
        reports = []
        for g in groups[:50]:  # Limit for MVP
            desc = g.get("description", "")
            if desc:
                reports.append({
                    "title": f"Threat Profile: {g.get('name', 'Unknown')}",
                    "content": desc,
                    "apt_group": g.get("name", "Unknown"),
                    "source": "MITRE ATT&CK STIX",
                })
        results["reports"] = index_threat_reports(client, reports)

        client.close()
    except Exception as e:
        logger.error(f"Indexing failed: {e}")
        results["status"] = f"error: {e}"

    return results


if __name__ == "__main__":
    results = run_full_indexing()
    print(f"Indexing results: {json.dumps(results, indent=2)}")
