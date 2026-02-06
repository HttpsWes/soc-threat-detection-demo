from collections import Counter

from collections import Counter

def generate_report(alerts):
    """
    This function Generates a summary report of all potentail harmful  alerts.
    Only MEDIUM and HIGH alerts are included.
    Uses underlying correlated 'types' (list) instead of generic 'type'.
    """
    report = {}

    # Only include MEDIUM and HIGH. LOW alerts are not included due to noise and overload 
    reportable_alerts = [
        a for a in alerts
        if a.get("severity") in ("MEDIUM", "HIGH")
    ]
    # Add each alert to our list and get the total amounts
    report["total_alerts"] = len(reportable_alerts)

    # Add and count up total amount of alerts and arrange them by severity 
    severities = [a.get("severity", "UNKNOWN") for a in reportable_alerts]
    report["alerts_by_severity"] = dict(Counter(severities))

    # Create a list of Types of alerts that occurs and the amount for each type
    detected_types = []
    
    for a in reportable_alerts:
        # Alerts are dynamic we arent creating a fixed list rather we add any new type of alert thats recorded in our logs and the amount of time it happened 
        if "types" in a and isinstance(a["types"], list):
            detected_types.extend(a["types"])
        else:
            # If the type of alert is unknown
            detected_types.append(a.get("type", "UNKNOWN"))

    report["alerts_by_type"] = dict(Counter(detected_types))

    # IPs grouped by severity (MEDIUM/HIGH only) 
    # If IPs was involed in multipule types of alerts it will only be accounted for once hence why this is in a set.
    high_risk_ips = {a["ip"] for a in reportable_alerts if a.get("severity") == "HIGH" and "ip" in a}
    medium_risk_ips = {a["ip"] for a in reportable_alerts if a.get("severity") == "MEDIUM" and "ip" in a}

    report["high_risk_ips"] = sorted(list(high_risk_ips))
    report["medium_risk_ips"] = sorted(list(medium_risk_ips))

    return report



def print_report(report):
    print("\n=== SOC DAILY THREAT REPORT ===\n")

    print(f"Total Alerts: {report['total_alerts']}\n")

    print("Alerts by Severity:")
    for sev, count in report["alerts_by_severity"].items():
        print(f"  {sev}: {count}")

    print("\nAlerts by Type:")
    for t, count in report["alerts_by_type"].items():
        print(f"  {t}: {count}")

    print("\nHigh-Risk IPs:")
    if report["high_risk_ips"]:
        for ip in report["high_risk_ips"]:
            print(f"  - {ip}")
    else:
        print("  None")

    print("\nMedium-Risk IPs:")
    if report["medium_risk_ips"]:
        for ip in report["medium_risk_ips"]:
            print(f"  - {ip}")
    else:
        print("  None")


    print("\n==============================\n")

