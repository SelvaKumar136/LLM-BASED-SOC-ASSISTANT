"""
Vector memory backed by ChromaDB.
Stores past incident investigations so the Investigator agent can retrieve
similar historical cases for context-aware analysis.
"""

import json
import uuid
import chromadb
from config import CHROMA_PATH

# ---------------------------------------------------------------------------
# Initialise persistent ChromaDB client
# ---------------------------------------------------------------------------
_client = chromadb.PersistentClient(path=CHROMA_PATH)
_collection = _client.get_or_create_collection(
    name="soc_incidents",
    metadata={"hnsw:space": "cosine"},
)
print(f"[MEMORY] ChromaDB loaded – {_collection.count()} past incidents")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def store_incident(alert: dict, triage: dict, investigation: str) -> str:
    """
    Store a completed investigation in vector memory.
    Returns the document id.
    """
    doc_id = alert.get("alert_id", str(uuid.uuid4()))

    # Build a rich text document for embedding
    summary_parts = [
        f"Title: {alert.get('title', 'N/A')}",
        f"Source IP: {alert.get('src_ip', 'N/A')}",
        f"Hostname: {alert.get('hostname', 'N/A')}",
        f"Username: {alert.get('username', 'N/A')}",
        f"Process: {alert.get('process', 'N/A')}",
        f"Severity: {triage.get('severity', 'N/A')}",
        f"MITRE Tactic: {triage.get('mitre_tactic', 'N/A')}",
        f"MITRE Technique: {triage.get('mitre_technique', 'N/A')}",
        f"Threat Category: {triage.get('threat_category', 'N/A')}",
        f"Classification: {triage.get('reasoning', 'N/A')}",
        f"Investigation: {investigation[:1000]}",
    ]
    document = "\n".join(summary_parts)

    metadata = {
        "title": str(alert.get("title", "")),
        "severity": str(triage.get("severity", "")),
        "mitre_tactic": str(triage.get("mitre_tactic", "")),
        "mitre_technique": str(triage.get("mitre_technique", "")),
        "threat_category": str(triage.get("threat_category", "")),
        "false_positive": str(triage.get("false_positive", False)),
        "source": str(alert.get("source", "")),
        "timestamp": str(alert.get("timestamp", "")),
    }

    _collection.upsert(
        ids=[doc_id],
        documents=[document],
        metadatas=[metadata],
    )
    print(f"[MEMORY] Stored incident {doc_id[:8]}… ({_collection.count()} total)")
    return doc_id


def retrieve_similar(text: str, top_k: int = 3) -> list[dict]:
    """
    Retrieve the most similar past incidents to the given text.
    Returns a list of dicts with 'summary' and 'metadata' keys.
    """
    if _collection.count() == 0:
        return []

    # Don't request more results than we have
    n = min(top_k, _collection.count())

    results = _collection.query(
        query_texts=[text],
        n_results=n,
    )

    cases = []
    for i in range(len(results["ids"][0])):
        cases.append({
            "id": results["ids"][0][i],
            "summary": results["documents"][0][i],
            "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
            "distance": results["distances"][0][i] if results["distances"] else None,
        })
    return cases