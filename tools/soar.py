import random
from langchain_core.tools import tool
from hitl.approval_queue import queue_action

@tool
def create_ticket(title: str, description: str, severity: str) -> dict:
    """Create an incident ticket."""
    print(f"  [SOAR] Ticket: {title} [{severity}]")
    ticket_id = f"INC-{random.randint(1000, 9999)}"
    return {"status": "created", "ticket_id": ticket_id}

@tool
def block_ip(ip: str, reason: str) -> dict:
    """Block a malicious IP address. Requires human approval."""
    print(f"  [SOAR] Queuing block: {ip}")
    queue_action({"action_type": "block_ip", "ip": ip, "reason": reason})
    return {"status": "queued_for_approval", "ip": ip}

@tool
def isolate_host(hostname: str, reason: str) -> dict:
    """Isolate a compromised host. Requires human approval."""
    print(f"  [SOAR] Queuing isolate: {hostname}")
    queue_action({"action_type": "isolate_host", "hostname": hostname, "reason": reason})
    return {"status": "queued_for_approval", "hostname": hostname}