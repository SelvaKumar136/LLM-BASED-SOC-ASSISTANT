"""
Responder Agent — SOC Response Coordinator
Determines and executes appropriate response actions based on investigation findings.
"""

import json
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from tools.soar import create_ticket, block_ip, isolate_host
from config import GROQ_API_KEY

llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, api_key=GROQ_API_KEY)
tools = [create_ticket, block_ip, isolate_host]
llm_with_tools = llm.bind_tools(tools)

SYSTEM_PROMPT = """You are a SOC Response Coordinator. Based on the investigation findings, determine and execute the appropriate response actions.

## Response Playbooks

### Critical Severity
- Create an incident ticket immediately
- Block all malicious IPs identified
- Isolate compromised hosts
- Escalation: Notify SOC Manager and IR team

### High Severity
- Create an incident ticket
- Block malicious IPs if confirmed malicious (malicious score > 3)
- Consider host isolation if active compromise confirmed

### Medium Severity
- Create an incident ticket for tracking
- Monitor but don't block/isolate unless clear evidence

### Low Severity / False Positive
- Create a ticket marked as false positive or informational
- No blocking or isolation needed

## Guidelines
- ALWAYS create a ticket for any alert (real or FP) — this ensures audit trail
- Include detailed description with IOCs, MITRE mapping, and recommended follow-up
- For blocking/isolation actions: include clear justification in the reason field
- After taking actions, provide a structured summary of what was done and why

## Response Summary Format
After executing actions, summarize:
- **Actions Taken**: List each action and its status
- **Justification**: Why these actions were chosen
- **Escalation**: Who should be notified
- **Follow-up**: Recommended next steps within 24h"""


def respond_node(state: dict) -> dict:
    """LangGraph node: determine and execute response actions."""
    triage = state.get("triage", {})
    investigation = state.get("investigation", "No investigation data.")
    alert = state.get("alert", {})

    severity = triage.get("severity", "Medium")
    category = triage.get("threat_category", "Unknown")

    print(f"\n[RESPONSE] 🛡️ Determining response for {severity} / {category} alert...")

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=(
            f"## Alert: {alert.get('title', 'Unknown')}\n\n"
            f"## Triage Result\n"
            f"- Severity: {severity}\n"
            f"- Threat Category: {category}\n"
            f"- MITRE Technique: {triage.get('mitre_technique', 'N/A')}\n"
            f"- False Positive: {triage.get('false_positive', False)}\n\n"
            f"## Investigation Findings\n{investigation}\n\n"
            f"Execute the appropriate response actions now."
        )),
    ]

    for iteration in range(5):
        response = llm_with_tools.invoke(messages)
        messages.append(response)

        if not response.tool_calls:
            break

        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_id = tool_call["id"]
            print(f"  [ACTION] ⚡ {tool_name}({json.dumps(tool_args)})")

            result = None
            for t in tools:
                if t.name == tool_name:
                    try:
                        result = t.invoke(tool_args)
                    except Exception as e:
                        result = {"error": str(e)}
                        print(f"  [ACTION] ❌ Error: {e}")
                    break

            messages.append(ToolMessage(
                content=json.dumps(result or {"error": "Tool not found"}),
                tool_call_id=tool_id,
            ))

    print(f"[RESPONSE] ✅ Complete")
    return {**state, "response": response.content or "Response actions executed."}