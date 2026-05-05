"""
Simulated SIEM log search tool.
Generates realistic log entries based on query context so the
Investigator agent has meaningful data to reason about.
"""

import random
import hashlib
from datetime import datetime, timedelta, timezone
from langchain_core.tools import tool


# ---------------------------------------------------------------------------
# Sample data pools for realistic log generation
# ---------------------------------------------------------------------------

_INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.2.50", "10.0.3.101",
    "192.168.1.10", "192.168.1.45", "192.168.2.80",
]
_EXTERNAL_IPS = [
    "185.220.101.5", "91.219.236.222", "45.33.32.156",
    "198.51.100.23", "203.0.113.42", "104.21.56.78",
]
_USERS = ["jsmith", "admin", "svc_backup", "mary.jones", "dbadmin", "guest"]
_HOSTS = [
    "DESKTOP-HR-04", "SRV-DC-01", "SRV-DB-02", "WS-FIN-07",
    "SRV-WEB-03", "LAPTOP-IT-12",
]
_PROCESSES = [
    "mimikatz.exe", "powershell.exe", "cmd.exe", "psexec.exe",
    "svchost.exe", "explorer.exe", "chrome.exe", "python.exe",
    "wscript.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
]


def _ts(minutes_ago: int) -> str:
    """Return an ISO timestamp `minutes_ago` in the past."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _random_hash() -> str:
    return hashlib.sha256(str(random.random()).encode()).hexdigest()[:64]


# ---------------------------------------------------------------------------
# Log generators by category
# ---------------------------------------------------------------------------

def _auth_logs(query: str, n: int = 3) -> list[dict]:
    logs = []
    for i in range(n):
        success = random.choice([True, True, False, False, False])
        logs.append({
            "log_type": "authentication",
            "timestamp": _ts(random.randint(1, 120)),
            "event": "LOGIN_SUCCESS" if success else "LOGIN_FAILED",
            "username": random.choice(_USERS),
            "source_ip": random.choice(_EXTERNAL_IPS + _INTERNAL_IPS),
            "hostname": random.choice(_HOSTS),
            "auth_method": random.choice(["password", "kerberos", "ntlm"]),
            "failure_reason": None if success else random.choice([
                "INVALID_PASSWORD", "ACCOUNT_LOCKED", "EXPIRED_CREDENTIAL",
            ]),
        })
    return logs


def _process_logs(query: str, n: int = 3) -> list[dict]:
    logs = []
    for i in range(n):
        proc = random.choice(_PROCESSES)
        # If the query mentions a specific process, include it
        for p in _PROCESSES:
            if p.lower().replace(".exe", "") in query.lower():
                proc = p
                break
        logs.append({
            "log_type": "process_execution",
            "timestamp": _ts(random.randint(1, 60)),
            "hostname": random.choice(_HOSTS),
            "username": random.choice(_USERS),
            "process_name": proc,
            "parent_process": random.choice(["explorer.exe", "cmd.exe", "powershell.exe", "services.exe"]),
            "command_line": f"C:\\Windows\\Temp\\{proc}" if random.random() > 0.5 else f"C:\\Windows\\System32\\{proc}",
            "pid": random.randint(1000, 65000),
            "file_hash": _random_hash(),
        })
    return logs


def _network_logs(query: str, n: int = 3) -> list[dict]:
    logs = []
    for i in range(n):
        logs.append({
            "log_type": "network_connection",
            "timestamp": _ts(random.randint(1, 90)),
            "source_ip": random.choice(_INTERNAL_IPS),
            "source_port": random.randint(49152, 65535),
            "destination_ip": random.choice(_EXTERNAL_IPS),
            "destination_port": random.choice([80, 443, 4444, 8080, 8443, 53, 22]),
            "protocol": random.choice(["TCP", "TCP", "UDP"]),
            "bytes_sent": random.randint(100, 500000),
            "bytes_received": random.randint(100, 200000),
            "hostname": random.choice(_HOSTS),
            "action": random.choice(["ALLOW", "ALLOW", "BLOCK"]),
        })
    return logs


def _dns_logs(query: str, n: int = 2) -> list[dict]:
    suspicious_domains = [
        "c2-server.evil.com", "data-exfil.malware.net",
        "update.legitimat3.xyz", "cdn-static.phishsite.ru",
    ]
    normal_domains = [
        "google.com", "microsoft.com", "github.com", "office365.com",
    ]
    logs = []
    for i in range(n):
        logs.append({
            "log_type": "dns_query",
            "timestamp": _ts(random.randint(1, 60)),
            "hostname": random.choice(_HOSTS),
            "queried_domain": random.choice(suspicious_domains + normal_domains),
            "query_type": random.choice(["A", "AAAA", "TXT", "CNAME"]),
            "response_code": random.choice(["NOERROR", "NOERROR", "NXDOMAIN"]),
        })
    return logs


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

@tool
def search_siem(query: str) -> dict:
    """Search SIEM logs for events matching the query. Returns authentication,
    process execution, network connection, and DNS logs relevant to the query."""
    print(f"  [SIEM] Searching: {query}")
    q = query.lower()

    results = []

    # Decide which log types to return based on query keywords
    if any(kw in q for kw in ["login", "auth", "password", "brute", "credential", "kerberos", "ntlm", "logon"]):
        results.extend(_auth_logs(q, n=random.randint(3, 5)))

    if any(kw in q for kw in ["process", "exec", "mimikatz", "powershell", "cmd", "psexec", "rundll", "certutil"]):
        results.extend(_process_logs(q, n=random.randint(2, 4)))

    if any(kw in q for kw in ["network", "connection", "ip", "traffic", "c2", "beacon", "exfil", "lateral"]):
        results.extend(_network_logs(q, n=random.randint(2, 4)))

    if any(kw in q for kw in ["dns", "domain", "resolve", "phish"]):
        results.extend(_dns_logs(q, n=random.randint(2, 3)))

    # If no specific keywords matched, return a mix
    if not results:
        results.extend(_auth_logs(q, n=2))
        results.extend(_process_logs(q, n=2))
        results.extend(_network_logs(q, n=2))

    # Sort by timestamp (most recent first) and cap at 6 results for token budget
    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    results = results[:6]

    return {
        "query": query,
        "count": len(results),
        "results": results,
    }