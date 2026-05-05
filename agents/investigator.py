"""
Investigator Agent — SOC Tier-2 Analyst
Performs deep investigation using threat intelligence tools, SIEM log queries,
and past incident memory to build an investigation report.
"""

import json
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from tools.threat_intel import lookup_ip, lookup_hash
from tools.siem import search_siem
from memory.vector_store import retrieve_similar
from config import GROQ_API_KEY

llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, api_key=GROQ_API_KEY, max_retries=10)
tools = [lookup_ip, lookup_hash, search_siem]
llm_with_tools = llm.bind_tools(tools)

SYSTEM_PROMPT = """You are an expert SOC Tier-2 analyst performing deep investigation on a triaged alert.

## Investigation Methodology
Follow this structured approach:
1. **Threat Intelligence Enrichment**: Check suspicious IPs with lookup_ip and file hashes with lookup_hash
2. **Log Correlation**: Search SIEM logs with search_siem using relevant keywords (process names, IPs, usernames, hostnames)
3. **Behavioral Analysis**: Analyze patterns across the gathered evidence
4. **Attribution**: Map findings to MITRE ATT&CK kill chain stages

## Report Format
After gathering evidence, write a structured investigation report with:
- **Executive Summary**: 2-3 sentence overview
- **Evidence Collected**: What each tool call revealed
- **Indicators of Compromise (IOCs)**: IPs, hashes, domains, processes
- **Attack Chain Analysis**: Timeline of events and MITRE ATT&CK mapping
- **Risk Assessment**: Business impact and confidence level
- **Recommendations**: Specific next steps

Be thorough but concise. Always use the available tools before concluding."""


def investigate_node(state: dict) -> dict:
    """LangGraph node: investigate the alert using tools and past knowledge."""
    alert = state["alert"]
    triage = state["triage"]
    print(f"\n[INVESTIGATION] Starting deep investigation...")

    # Retrieve similar past incidents for context
    past_cases = retrieve_similar(alert.get("title", ""), top_k=3)
    past_parts = []
    for c in past_cases:
        if isinstance(c, dict):
            meta = c.get("metadata", {})
            past_parts.append(
                f"- [{meta.get('severity', '?')}] {meta.get('title', 'Unknown')} "
                f"(MITRE: {meta.get('mitre_technique', 'N/A')}, "
                f"Category: {meta.get('threat_category', 'N/A')})"
            )
        else:
            past_parts.append(f"- {c}")

    past_text = "\n".join(past_parts) if past_parts else "No similar past incidents found."

    # --- Compact alert representation to stay within token limits ---
    compact_alert = {
        k: v for k, v in alert.items()
        if k not in ("raw", "ip_reputation")  # skip large fields
    }
    ip_rep = alert.get("ip_reputation", {})
    if ip_rep and "error" not in ip_rep:
        compact_alert["ip_reputation"] = {
            "abuse_score": ip_rep.get("abuse_score"),
            "country": ip_rep.get("country"),
            "total_reports": ip_rep.get("total_reports"),
        }

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=(
            f"## Alert Details\n```json\n{json.dumps(compact_alert, indent=2)}\n```\n\n"
            f"## Triage Classification\n```json\n{json.dumps(triage, indent=2)}\n```\n\n"
            f"## Similar Past Incidents\n{past_text}\n\n"
            f"Investigate this alert using the available tools."
        )),
    ]

    # Agentic tool-calling loop (max 5 iterations, with dedup cache)
    tool_cache: dict = {}   # (tool_name, frozen_args) -> result_str
    tool_rounds = 0

    response = None
    for iteration in range(5):
        response = llm_with_tools.invoke(messages)
        messages.append(response)

        if not response.tool_calls:
            break

        tool_rounds += 1
        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_id = tool_call["id"]

            # Deduplication: skip re-running the same call
            cache_key = (tool_name, json.dumps(tool_args, sort_keys=True))
            if cache_key in tool_cache:
                print(f"  [TOOL] Cache hit: {tool_name}")
                result_str = tool_cache[cache_key]
            else:
                print(f"  [TOOL] Calling: {tool_name}({json.dumps(tool_args)})")
                result = None
                for t in tools:
                    if t.name == tool_name:
                        try:
                            result = t.invoke(tool_args)
                        except Exception as e:
                            result = {"error": str(e)}
                            print(f"  [TOOL] ERROR: {e}")
                        break

                # Truncate large results
                result_str = json.dumps(result or {"error": "Tool not found"})
                if len(result_str) > 1500:
                    if isinstance(result, dict) and "results" in result:
                        result["results"] = result["results"][:5]
                        result["note"] = "Truncated to 5 results"
                    result_str = json.dumps(result)[:1500]
                tool_cache[cache_key] = result_str

            messages.append(ToolMessage(content=result_str, tool_call_id=tool_id))

        # After first round of tools, nudge the model to write the report
        if tool_rounds == 1:
            messages.append(HumanMessage(
                content="You have gathered sufficient evidence. "
                        "Do NOT call any more tools. Write your investigation report now."
            ))

    investigation_text = (response.content if response else None) or "Investigation complete."
    print(f"[INVESTIGATION] Complete ({iteration + 1} iterations, {len(tool_cache)} unique tool calls)")
    return {**state, "investigation": investigation_text}