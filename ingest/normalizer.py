import uuid, requests
from datetime import datetime, timezone
from config import ABUSEIPDB_API_KEY

def normalize_alert(source: str, raw: dict) -> dict:
    alert = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source":   source,
        "title":    raw.get("title") or raw.get("alert_name", "Unknown"),
        "src_ip":   raw.get("src_ip") or raw.get("source_ip", ""),
        "dst_ip":   raw.get("dst_ip") or raw.get("dest_ip", ""),
        "hostname": raw.get("hostname") or raw.get("host", ""),
        "username": raw.get("username") or raw.get("user", ""),
        "process":  raw.get("process_name", ""),
        "raw":      raw,
    }
    if alert["src_ip"]:
        alert["ip_reputation"] = check_ip(alert["src_ip"])
    return alert

def check_ip(ip: str) -> dict:
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=5)
        d = r.json().get("data", {})
        return {"abuse_score": d.get("abuseConfidenceScore", 0), "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""), "total_reports": d.get("totalReports", 0)}
    except Exception as e:
        return {"error": str(e)}