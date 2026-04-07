"""
Supervisor — LangGraph Orchestrator
Wires the Triage → Investigate → Respond pipeline and records
completed investigations to vector memory.
"""

import time
from langgraph.graph import StateGraph, END
from typing import TypedDict, Optional
from agents.triage import triage_node
from agents.investigator import investigate_node
from agents.responder import respond_node
from memory.vector_store import store_incident


class InvestigationState(TypedDict):
    alert:         dict
    triage:        Optional[dict]
    investigation: Optional[str]
    response:      Optional[str]


def close_node(state: InvestigationState) -> InvestigationState:
    """Handle alerts classified as false positives."""
    print(f"\n[CLOSE] ✅ False positive — {state['alert'].get('title')}")
    return {**state, "response": "Closed as false positive — no action required."}


def memory_node(state: InvestigationState) -> InvestigationState:
    """Store the completed investigation in vector memory for future reference."""
    try:
        store_incident(
            alert=state.get("alert", {}),
            triage=state.get("triage", {}),
            investigation=state.get("investigation", ""),
        )
    except Exception as e:
        print(f"[MEMORY] ⚠️  Failed to store incident: {e}")
    return state


def route_after_triage(state: InvestigationState) -> str:
    """Route to close (false positive) or investigate (real threat)."""
    triage = state.get("triage", {})
    if triage.get("route") == "close" and triage.get("fp_confidence", 0) >= 0.85:
        return "close"
    return "investigate"


# ---------------------------------------------------------------------------
# Build the LangGraph state machine
# ---------------------------------------------------------------------------
graph = StateGraph(InvestigationState)

graph.add_node("triage",      triage_node)
graph.add_node("investigate", investigate_node)
graph.add_node("respond",     respond_node)
graph.add_node("close",       close_node)
graph.add_node("memory",      memory_node)

graph.set_entry_point("triage")
graph.add_conditional_edges(
    "triage",
    route_after_triage,
    {"investigate": "investigate", "close": "close"},
)
graph.add_edge("investigate", "respond")
graph.add_edge("respond",     "memory")
graph.add_edge("memory",      END)
graph.add_edge("close",       "memory")

soc_graph = graph.compile()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_investigation(alert: dict) -> dict:
    """Run the full investigation pipeline on a normalised alert."""
    print(f"\n{'='*60}")
    print(f"🚨 NEW ALERT: {alert.get('title')}")
    print(f"{'='*60}")

    t0 = time.time()
    final_state = soc_graph.invoke({
        "alert": alert,
        "triage": None,
        "investigation": None,
        "response": None,
    })
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"✅ ALERT PROCESSED: {alert.get('alert_id')} ({elapsed:.1f}s)")
    print(f"{'='*60}\n")

    return final_state