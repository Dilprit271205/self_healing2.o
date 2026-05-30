# logger/logger.py

import json
import os
import threading
import queue

from datetime import datetime


# ---------------------------------------------------
# LOG DIRECTORY
# ---------------------------------------------------
os.makedirs(
    "logs",
    exist_ok=True
)

PROCESS_LOG = (
    "logs/system_log.json"
)

ENTITY_LOG = (
    "logs/entity_log.json"
)

HEALING_LOG = (
    "logs/healing_log.json"
)


# ---------------------------------------------------
# ASYNC QUEUES
# ---------------------------------------------------
process_queue = queue.Queue(
    maxsize=10000
)

entity_queue = queue.Queue(
    maxsize=5000
)

healing_queue = queue.Queue(
    maxsize=5000
)


# ---------------------------------------------------
# TIMESTAMP
# ---------------------------------------------------
def timestamp():

    return datetime.now().isoformat(
        timespec="seconds"
    )


# ---------------------------------------------------
# SAFE JSON SERIALIZATION
# ---------------------------------------------------
def safe_json(data):

    try:

        return json.dumps(
            data,
            separators=(",", ":"),
            default=str
        )

    except:

        return json.dumps({

            "error":
                "serialization_failed"
        })


# ---------------------------------------------------
# WRITER THREAD
# ---------------------------------------------------
def writer(
    file_path,
    q
):

    with open(
        file_path,
        "a",
        buffering=8192
    ) as f:

        while True:

            try:

                data = q.get()

                line = (
                    safe_json(data)
                    + "\n"
                )

                f.write(line)
                f.flush()

            except:
                pass


# ---------------------------------------------------
# START THREADS
# ---------------------------------------------------
threading.Thread(

    target=writer,

    args=(
        PROCESS_LOG,
        process_queue
    ),

    daemon=True

).start()


threading.Thread(

    target=writer,

    args=(
        ENTITY_LOG,
        entity_queue
    ),

    daemon=True

).start()


threading.Thread(

    target=writer,

    args=(
        HEALING_LOG,
        healing_queue
    ),

    daemon=True

).start()


# ---------------------------------------------------
# PROCESS LOGGER
# ---------------------------------------------------
def log_process(data):

    try:

        normalized = {

            # -----------------------------
            # runtime metadata
            # -----------------------------
            "timestamp":
                timestamp(),

            "type":
                "process",

            # -----------------------------
            # process
            # -----------------------------
            "pid":
                data.get("pid"),

            "name":
                data.get("name"),

            "entity_root":
                data.get(
                    "entity_root"
                ),

            # -----------------------------
            # trust
            # -----------------------------
            "dynamic_trust":
                data.get(
                    "trust",
                    {}
                ).get(
                    "dynamic_trust"
                ),

            "final_trust":
                data.get(
                    "trust",
                    {}
                ).get(
                    "final_trust"
                ),

            "static_trust":
                data.get(
                    "trust",
                    {}
                ).get(
                    "static_trust"
                ),

            # -----------------------------
            # classification
            # -----------------------------
            "worm_score":
                data.get(
                    "worm_score"
                ),

            "confidence":
                data.get(
                    "confidence"
                ),

            "label":
                data.get(
                    "label"
                ),

            "severity":
                data.get(
                    "severity"
                ),

            # -----------------------------
            # healing
            # -----------------------------
            "stage":
                data.get(
                    "stage"
                ),

            "response":
                data.get(
                    "response"
                ),

            # -----------------------------
            # learning
            # -----------------------------
            "learning_state":
                data.get(
                    "learning_state"
                ),

            # -----------------------------
            # telemetry
            # -----------------------------
            "anomalies":
                data.get(
                    "anomalies",
                    {}
                ),

            "features":
                data.get(
                    "features",
                    {}
                )
        }

        process_queue.put_nowait(
            normalized
        )

    except:
        pass


# ---------------------------------------------------
# ENTITY LOGGER
# ---------------------------------------------------
def log_entity(data):

    try:

        normalized = {

            "timestamp":
                timestamp(),

            "type":
                "entity",

            "entity_root":
                data.get(
                    "entity_root"
                ),

            "children_count":
                data.get(
                    "children_count",
                    0
                ),

            "growth_velocity":
                data.get(
                    "growth_velocity",
                    0
                ),

            "total_cpu":
                data.get(
                    "total_cpu",
                    0
                ),

            "total_memory":
                data.get(
                    "total_memory",
                    0
                ),

            "members":
                data.get(
                    "members",
                    []
                )
        }

        entity_queue.put_nowait(
            normalized
        )

    except:
        pass


# ---------------------------------------------------
# HEALING LOGGER
# ---------------------------------------------------
def log_healing(data):

    try:

        normalized = {

            "timestamp":
                timestamp(),

            "type":
                "healing",

            "pid":
                data.get("pid"),

            "stage":
                data.get(
                    "stage"
                ),

            "action_taken":
                data.get(
                    "action_taken"
                ),

            "status":
                data.get(
                    "status"
                )
        }

        healing_queue.put_nowait(
            normalized
        )

    except:
        pass