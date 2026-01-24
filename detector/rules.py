from collections import defaultdict
from datetime import timedelta

def detect_brute_force(logs, threshold=5, window_minutes=2):
    """
    Detects brute force login attempts based on failed logins.
    """
    alerts = []
    failed_logins = defaultdict(list)

    # Group failed logins by IP
    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            failed_logins[log["ip"]].append(log["timestamp"])

    # Analyze login attempts
    for ip, timestamps in failed_logins.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            count = 1

            for j in range(i + 1, len(timestamps)):
                if timestamps[j] - window_start <= timedelta(minutes=window_minutes):
                    count += 1
                else:
                    break

            if count >= threshold:
                alerts.append({
                    "type": "Brute Force Login Attempt",
                    "ip": ip,
                    "severity": "HIGH",
                    "attempts": count
                })
                break  # one alert per IP

    return alerts
