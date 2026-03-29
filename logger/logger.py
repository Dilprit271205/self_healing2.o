import json
from datetime import datetime

LOG_FILE = "logs/system_log.json"

def log_data(data):
    data["timestamp"] = datetime.now().isoformat()

    try:
        with open(LOG_FILE, "a") as f:
            json.dump(data, f)
            f.write("\n")
    except Exception as e:
        print("Logging error:", e)