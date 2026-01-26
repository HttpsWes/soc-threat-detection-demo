from collections import Counter

def generate_report(alerts):
    """
    Generates a SOC-style summary report from alerts.
    """
    report = {}

    report["total_alerts"] = len(alerts)

    # Count by severity
    severities = [a.get("severity", "UNKNOWN") for a in alerts]
    report["alerts_by_severity"] = dict(Counter(severities))

    # Count by alert type
    types = [a.get("type", "UNKNOWN") for a in alerts]
    report["alerts_by_type"] = dict(Counter(types))

    # High-risk IPs
       # IPs grouped by severity
    high_risk_ips = {a["ip"] for a in alerts if a.get("severity") == "HIGH" and "ip" in a}
    medium_risk_ips = {a["ip"] for a in alerts if a.get("severity") == "MEDIUM" and "ip" in a}
    low_risk_ips = {a["ip"] for a in alerts if a.get("severity") == "LOW" and "ip" in a}

    report["high_risk_ips"] = sorted(list(high_risk_ips))
    report["medium_risk_ips"] = sorted(list(medium_risk_ips))
    report["low_risk_ips"] = sorted(list(low_risk_ips))


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

    print("\nLow-Risk IPs:")
    if report["low_risk_ips"]:
        for ip in report["low_risk_ips"]:
            print(f"  - {ip}")
    else:
        print("  None")

    print("\n==============================\n")

