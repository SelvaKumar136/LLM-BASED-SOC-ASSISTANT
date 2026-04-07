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

llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, api_key=GROQ_API_KEY)
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
    print(f"\n[INVESTIGATION] 🔎 Starting deep investigation...")

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

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=(
            f"## Alert Details\n```json\n{json.dumps(alert, indent=2)}\n```\n\n"
            f"## Triage Classification\n```json\n{json.dumps(triage, indent=2)}\n```\n\n"
            f"## Similar Past Incidents\n{past_text}\n\n"
            f"Investigate this alert thoroughly using the available tools."
        )),
    ]

    # Agentic tool-calling loop (max 10 iterations)
    for iteration in range(10):
        response = llm_with_tools.invoke(messages)
        messages.append(response)

        if not response.tool_calls:
            break

        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_id = tool_call["id"]
            print(f"  [TOOL] 🔧 {tool_name}({json.dumps(tool_args)})")

            result = None
            for t in tools:
                if t.name == tool_name:
                    try:
                        result = t.invoke(tool_args)
                    except Exception as e:
                        result = {"error": str(e)}
                        print(f"  [TOOL] ❌ Error: {e}")
                    break

            messages.append(ToolMessage(
                content=json.dumps(result or {"error": "Tool not found"}),
                tool_call_id=tool_id,
            ))

    investigation_text = response.content or "Investigation complete — no additional findings."
    print(f"[INVESTIGATION] ✅ Complete ({iteration + 1} iterations)")
    return {**state, "investigation": investigation_text}