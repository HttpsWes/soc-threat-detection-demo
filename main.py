from detector.parser import parse_logs
from detector.rules import detect_brute_force
from detector.alerts import load_threat_intel, enrich_alerts_with_intel, detect_intel_hits_from_logs

if __name__ == "__main__":
    logs = parse_logs()

    # Detection alerts
    alerts = detect_brute_force(logs)

    # Threat intel
    intel_ips = load_threat_intel()
    intel_hit_alerts = detect_intel_hits_from_logs(logs, intel_ips)

    # Enrich brute-force alerts with intel
    alerts = enrich_alerts_with_intel(alerts, intel_ips)

    # Combine + print
    all_alerts = alerts + intel_hit_alerts

    for a in all_alerts:
        print(a)
