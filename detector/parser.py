import csv
from datetime import datetime

LOG_FILE = "logs/sample_logs.csv"

def parse_logs(log_file=LOG_FILE):
    """
    Reads CSV log data and returns a list of normalized log entries.
    """
    logs = []

    with open(log_file, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            log_entry = {
                "timestamp": datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S"),
                "ip": row["ip"],
                "event": row["event"],
                "user": row["user"]
            }
            logs.append(log_entry)

    return logs


if __name__ == "__main__":
    logs = parse_logs()
    for log in logs:
        print(log)
