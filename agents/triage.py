"""
Triage Agent — SOC Tier-1 Analyst
Classifies alerts with severity, MITRE ATT&CK mapping, threat category,
and routes them to investigation or closure.
"""

import json
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from config import GROQ_API_KEY

llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, api_key=GROQ_API_KEY, max_retries=10)

TRIAGE_PROMPT = """You are an expert SOC Tier-1 analyst performing initial triage on security alerts.

Analyze the alert below and classify it. You MUST respond ONLY with raw valid JSON (no markdown, no code fences, no explanation outside the JSON):

{
  "severity": "Critical" or "High" or "Medium" or "Low",
  "false_positive": true or false,
  "fp_confidence": 0.0 to 1.0,
  "threat_category": one of ["Malware", "Intrusion", "Phishing", "Insider Threat", "Data Exfiltration", "Reconnaissance", "Lateral Movement", "Credential Theft", "Command and Control", "Denial of Service", "Unknown"],
  "category_confidence": 0.0 to 1.0,
  "mitre_tactic": "tactic name (e.g. Credential Access, Execution, Lateral Movement)",
  "mitre_technique": "technique ID and name (e.g. T1003.001 - LSASS Memory)",
  "reasoning": "2-3 sentence explanation of your classification",
  "ioc_summary": "key indicators of compromise found in the alert",
  "route": "investigate" or "close"
}

Classification guidelines:
- Severity Critical: Active exploitation, data exfiltration in progress, ransomware
- Severity High: Known malicious tools (mimikatz, cobalt strike), compromised credentials
- Severity Medium: Suspicious but unconfirmed activity, policy violations
- Severity Low: Informational, benign anomalies
- Set route to "close" ONLY if fp_confidence >= 0.85
- For MITRE mappings, use the most specific sub-technique when possible"""


def _parse_json_response(raw: str) -> dict:
    """Robust JSON parser with multiple fallback strategies."""
    text = raw.strip()

    # Strategy 1: Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Strip markdown code fences
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            cleaned = part.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                continue

    # Strategy 3: Find JSON object boundaries
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    # Strategy 4: Return safe defaults
    print(f"[WARN] All JSON parse strategies failed for: {text[:200]}")
    return {
        "severity": "Medium",
        "false_positive": False,
        "fp_confidence": 0.0,
        "threat_category": "Unknown",
        "category_confidence": 0.0,
        "mitre_tactic": "Unknown",
        "mitre_technique": "Unknown",
        "reasoning": "Automated parse failed — defaulting to investigate",
        "ioc_summary": "Parse error",
        "route": "investigate",
    }


def triage_node(state: dict) -> dict:
    """LangGraph node: perform initial triage classification on an alert."""
    alert = state["alert"]

    alert_text = f"""
Title: {alert.get('title', 'N/A')}
Source: {alert.get('source', 'N/A')}
Source IP: {alert.get('src_ip', 'N/A')}
Destination IP: {alert.get('dst_ip', 'N/A')}
Hostname: {alert.get('hostname', 'N/A')}
Username: {alert.get('username', 'N/A')}
Process: {alert.get('process', 'N/A')}
IP Reputation: {json.dumps(alert.get('ip_reputation', {}), indent=2)}
Timestamp: {alert.get('timestamp', 'N/A')}
"""

    print(f"\n[TRIAGE] Analyzing '{alert.get('title')}'...")
    response = llm.invoke([
        SystemMessage(content=TRIAGE_PROMPT),
        HumanMessage(content=alert_text),
    ])

    triage_result = _parse_json_response(response.content)

    severity = triage_result.get("severity", "Medium")
    technique = triage_result.get("mitre_technique", "Unknown")
    category = triage_result.get("threat_category", "Unknown")
    print(f"[TRIAGE] Result: {severity} | {category} | {technique} | Route: {triage_result.get('route')}")

    return {**state, "triage": triage_result}