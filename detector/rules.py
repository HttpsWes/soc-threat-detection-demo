from collections import defaultdict
from datetime import timedelta
from detector.alerts import add_metadata


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
                alerts.append(add_metadata({
                    "type": "Brute Force Login Attempt",
                    "ip": ip,
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "reason": f"{count} failed login attempts within {window_minutes} minutes",
                    "attempts": count
                }))

                break  # one alert per IP

    return alerts

def detect_after_hours_admin_access(logs, start_hour=0, end_hour=5):
    """
    Detects successful admin logins during after-hours.
    """
    alerts = []

    for log in logs:
        hour = log["timestamp"].hour

        if (
            log["event"] == "LOGIN_SUCCESS"
            and log["user"] == "admin"
            and start_hour <= hour < end_hour
        ):
            alerts.append(add_metadata({
                "type": "After-Hours Admin Login",
                "ip": log["ip"],
                "user": log["user"],
                "severity": "MEDIUM",
                "confidence": 0.6,
                "reason": "Admin login detected outside normal business hours",
                "time": log["timestamp"].isoformat(sep=" ")
            }))



    return alerts

def detect_informational_logins(logs):
    """
    Creates LOW severity informational alerts for successful logins.
    Useful for demonstrating baseline activity.
    """
    alerts = []

    for log in logs:
        if log["event"] == "LOGIN_SUCCESS":
            alerts.append(add_metadata({
            "type": "Informational Login",
            "ip": log["ip"],
            "user": log["user"],
            "severity": "LOW",
            "confidence": 0.2,
            "reason": "Normal successful login activity",
            "time": log["timestamp"].isoformat(sep=" ")
        }))


    return alerts

def detect_unknown_user_login(logs):
    """
    Detects successful logins by users who are not admins or employees.
    """
    alerts = []

    for log in logs:
        user = log.get("user", "")

        if (
            log["event"] == "LOGIN_SUCCESS"
            and user != "admin"
            and not user.startswith("employee")
        ):
            alerts.append(add_metadata({
                "type": "Unauthorized User Login",
                "ip": log["ip"],
                "user": user,
                "severity": "HIGH",
                "confidence": 0.85,
                "reason": "Successful login by non-employee, non-admin user",
                "time": log["timestamp"].isoformat(sep=" ")
            }))

    return alerts

