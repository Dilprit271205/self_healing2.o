import json
import os
import threading
import queue
from datetime import datetime

os.makedirs("logs", exist_ok=True)

PROCESS_LOG = "logs/system_log.json"
ENTITY_LOG = "logs/entity_log.json"

process_queue = queue.Queue(maxsize=10000)
entity_queue = queue.Queue(maxsize=5000)


def writer(file_path, q):
    with open(file_path, "a", buffering=8192) as f:
        while True:
            try:
                data = q.get()
                line = json.dumps(data, separators=(",", ":")) + "\n"
                f.write(line)
            except:
                pass


threading.Thread(
    target=writer,
    args=(PROCESS_LOG, process_queue),
    daemon=True
).start()

threading.Thread(
    target=writer,
    args=(ENTITY_LOG, entity_queue),
    daemon=True
).start()


def timestamp():
    return datetime.now().isoformat(timespec="seconds")


def log_process(data):
    try:
        data["timestamp"] = timestamp()
        process_queue.put_nowait(data)
    except:
        pass


def log_entity(data):
    try:
        data["timestamp"] = timestamp()
        entity_queue.put_nowait(data)
    except:
        pass