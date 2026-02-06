from detector.parser import parse_logs
from detector.rules import (
    detect_brute_force,
    detect_after_hours_admin_access,
    detect_informational_logins,
    detect_unknown_user_login
)
from detector.alerts import (
    load_threat_intel,
    enrich_alerts_with_intel,
    detect_intel_hits_from_logs
)
from report.report_generator import generate_report, print_report


def correlate_alerts(alerts):
    """
    Merge alerts by IP into a single alert with combined reasons and preserve
    the original detection types that fired.
    """
    correlated = {}
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    for alert in alerts:
        ip = alert.get("ip")
        if not ip:
            continue

        if ip not in correlated:
            correlated[ip] = {
                "type": "Suspicious Activity",
                "types": set(),
                "ip": ip,
                "severity": alert.get("severity", "LOW"),
                "confidence": alert.get("confidence", 0),
                "reasons": []
            }

        # Track original alert type(s)
        if alert.get("type"):
            correlated[ip]["types"].add(alert["type"])

        # Upgrade severity if higher
        if severity_rank.get(alert.get("severity"), 1) > severity_rank.get(correlated[ip]["severity"], 1):
            correlated[ip]["severity"] = alert.get("severity")

        # Keep highest confidence
        correlated[ip]["confidence"] = max(
            correlated[ip]["confidence"],
            alert.get("confidence", 0)
        )

        # Collect reasons
        if alert.get("reason"):
            correlated[ip]["reasons"].append(alert["reason"])

    # Convert sets -> sorted lists
    for a in correlated.values():
        a["types"] = sorted(list(a["types"]))

    return list(correlated.values())


def print_alerts(alerts):
    for alert in alerts:
        #Skip any low alerts
        if alert.get("severity") == "LOW":
            continue

        # After merging alerts by ips we print them
        print(f"[{alert['severity']}] {alert['type']} | {alert['ip']}")
        print("  Reasons:")
        for r in alert.get("reasons", []):
            print(f"   - {r}")
        print(f"  Confidence: {alert.get('confidence')}")
        print()


if __name__ == "__main__":
    logs = parse_logs()

    # Detection rules
    alerts = []
    alerts += detect_brute_force(logs)
    alerts += detect_after_hours_admin_access(logs)
    alerts += detect_informational_logins(logs)   # baseline LOW (won't print/report)
    alerts += detect_unknown_user_login(logs)

    # Threat intel
    intel_ips = load_threat_intel()
    alerts = enrich_alerts_with_intel(alerts, intel_ips)
    alerts += detect_intel_hits_from_logs(logs, intel_ips)

    # Correlate + output
    correlated_alerts = correlate_alerts(alerts)

    print_alerts(correlated_alerts)

    report = generate_report(correlated_alerts)
    print_report(report)



