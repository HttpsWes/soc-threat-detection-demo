def load_threat_intel(filepath="threat_intel/malicious_ips.txt"):
    """
    Loads threat intel IPs from a text file into a set.
    """
    intel_ips = set()
    with open(filepath, "r") as f:
        for line in f:
            ip = line.strip()
            if ip:
                intel_ips.add(ip)
    return intel_ips


def enrich_alerts_with_intel(alerts, intel_ips):
    """
    Adds threat intel context to existing alerts.
    If alert IP is in intel list, mark intel_match True and raise severity if needed.
    """
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    for alert in alerts:
        ip = alert.get("ip")
        match = ip in intel_ips
        alert["intel_match"] = match

        if match:
            # Upgrade severity to HIGH if not already
            current = alert.get("severity", "LOW")
            if severity_rank.get(current, 1) < severity_rank["HIGH"]:
                alert["severity"] = "HIGH"

            alert["intel_source"] = "local_list"

    return alerts


def detect_intel_hits_from_logs(logs, intel_ips):
    """
    Creates alerts for any log entry whose IP matches threat intel.
    """
    hits = []
    seen = set()

    for log in logs:
        ip = log["ip"]
        if ip in intel_ips and ip not in seen:
            hits.append({
                "type": "Threat Intel Match",
                "ip": ip,
                "severity": "HIGH",
                "first_seen": log["timestamp"].isoformat(sep=" ")
            })
            seen.add(ip)

    return hits
