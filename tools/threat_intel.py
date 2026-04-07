import requests
from langchain_core.tools import tool
from config import VIRUSTOTAL_API_KEY

@tool
def lookup_ip(ip: str) -> dict:
    """Look up threat reputation for an IP address using VirusTotal."""
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        d = r.json().get("data", {}).get("attributes", {})
        s = d.get("last_analysis_stats", {})
        return {"malicious": s.get("malicious", 0), "clean": s.get("harmless", 0),
                "country": d.get("country", "Unknown"), "owner": d.get("as_owner", "Unknown")}
    except Exception as e:
        return {"error": str(e)}

@tool
def lookup_hash(file_hash: str) -> dict:
    """Check if a file hash is malicious using VirusTotal."""
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                         headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        d = r.json().get("data", {}).get("attributes", {})
        s = d.get("last_analysis_stats", {})
        return {"malicious": s.get("malicious", 0), "clean": s.get("harmless", 0),
                "name": d.get("meaningful_name", "Unknown")}
    except Exception as e:
        return {"error": str(e)}