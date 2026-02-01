from detector.parser import parse_logs
from detector.rules import (
    detect_brute_force,
    detect_after_hours_admin_access,
    detect_informational_logins
)
from detector.alerts import (
    load_threat_intel,
    enrich_alerts_with_intel,
    detect_intel_hits_from_logs
)
from report.report_generator import generate_report, print_report


if __name__ == "__main__":
    logs = parse_logs()

    # Detection rules
    alerts = []
    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_after_hours_admin_access(logs))
    alerts.extend(detect_informational_logins(logs))  # ✅ LOW alerts here

    # Threat intel
    intel_ips = load_threat_intel()
    alerts = enrich_alerts_with_intel(alerts, intel_ips)
    intel_hit_alerts = detect_intel_hits_from_logs(logs, intel_ips)

    # Combine all alerts
    all_alerts = alerts + intel_hit_alerts

    # Print alerts
    for alert in all_alerts:
        if alert["severity"] != "LOW":
            print(f"[{alert['severity']}] {alert['type']} | {alert['ip']}")
            print(f"  Reason: {alert.get('reason')}")
            print(f"  Confidence: {alert.get('confidence')}")
            print()



    # Print report
    report = generate_report(all_alerts)
    print_report(report)



