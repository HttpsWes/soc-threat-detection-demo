from detector.parser import parse_logs
from detector.rules import detect_brute_force

if __name__ == "__main__":
    logs = parse_logs()
    alerts = detect_brute_force(logs)

    for alert in alerts:
        print(alert)
