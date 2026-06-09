# logger/logger.py

import json
import os
import threading
import queue
import time

from datetime import datetime
from pathlib import Path


# ---------------------------------------------------
# LOG DIRECTORY
# ---------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def project_path(env_name, default):
    configured = os.getenv(
        env_name
    )
    path = Path(
        configured
        if configured
        else default
    )
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return str(path)


os.makedirs(
    PROJECT_ROOT / "logs",
    exist_ok=True
)

PROCESS_LOG = project_path(
    "SELF_HEALING_SYSTEM_LOG",
    "logs/system_log.json"
)

ENTITY_LOG = project_path(
    "SELF_HEALING_ENTITY_LOG",
    "logs/entity_log.json"
)

HEALING_LOG = project_path(
    "SELF_HEALING_HEALING_LOG",
    "logs/healing_log.json"
)


try:
    MAX_LOG_BYTES = int(
        os.getenv(
            "SELF_HEALING_MAX_LOG_BYTES",
            str(8 * 1024 * 1024)
        )
    )
except Exception:
    MAX_LOG_BYTES = 8 * 1024 * 1024

try:
    LOG_NORMAL_PROCESSES = os.getenv(
        "SELF_HEALING_LOG_NORMAL_PROCESSES",
        "false"
    ).lower() in (
        "1",
        "true",
        "yes",
        "y"
    )
except Exception:
    LOG_NORMAL_PROCESSES = False

try:
    PROCESS_LOG_INTERVAL = float(
        os.getenv(
            "SELF_HEALING_PROCESS_LOG_INTERVAL",
            "0.5"
        )
    )
except Exception:
    PROCESS_LOG_INTERVAL = 0.5

try:
    ENTITY_LOG_INTERVAL = float(
        os.getenv(
            "SELF_HEALING_ENTITY_LOG_INTERVAL",
            "10"
        )
    )
except Exception:
    ENTITY_LOG_INTERVAL = 10.0

last_process_log = {}
last_process_state = {}
last_entity_log = {}
logger_drop_counts = {
    "process": 0,
    "entity": 0,
    "healing": 0,
}


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


def enqueue_latest(
    q,
    data,
    stream_name
):
    try:
        q.put_nowait(
            data
        )
        return True
    except queue.Full:
        logger_drop_counts[
            stream_name
        ] = (
            logger_drop_counts.get(
                stream_name,
                0
            )
            + 1
        )
        try:
            q.get_nowait()
        except queue.Empty:
            pass
        try:
            q.put_nowait(
                data
            )
            return True
        except queue.Full:
            logger_drop_counts[
                stream_name
            ] = (
                logger_drop_counts.get(
                    stream_name,
                    0
                )
                + 1
            )
            return False


# ---------------------------------------------------
# TIMESTAMP
# ---------------------------------------------------
def timestamp():

    return datetime.now().isoformat(
        timespec="milliseconds"
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

    except Exception:
        return json.dumps({

            "error":
                "serialization_failed"
        })


def rotate_if_needed(
    file_path
):
    try:
        if (
            MAX_LOG_BYTES <= 0
            or not os.path.exists(
                file_path
            )
            or os.path.getsize(
                file_path
            ) < MAX_LOG_BYTES
        ):
            return

        rotated = (
            file_path
            + ".1"
        )

        if os.path.exists(
            rotated
        ):
            os.remove(
                rotated
            )

        os.replace(
            file_path,
            rotated
        )

    except Exception:
        pass


def should_log_process(
    data
):
    label = data.get(
        "label",
        "normal"
    )
    severity = data.get(
        "severity",
        "low"
    )
    stage = data.get(
        "stage",
        "observe"
    )
    response = str(
        data.get(
            "response",
            ""
        )
        or
        ""
    ).lower()

    interesting = (
        label != "normal"
        or severity not in {
            "low",
            "normal"
        }
        or stage not in {
            "observe",
            "protected"
        }
        or "terminated" in response
        or "isolated" in response
        or "throttled" in response
    )

    pid = data.get(
        "pid"
    )

    previous_state = last_process_state.get(
        pid
    )
    previous_interesting = (
        previous_state or {}
    ).get(
        "interesting",
        False
    )

    if not LOG_NORMAL_PROCESSES and not interesting and not previous_interesting:
        return False

    key = (
        pid,
        label,
        severity,
        stage,
        response
    )
    now = time.time()

    if previous_state and previous_state.get("key") != key:
        last_process_log[
            key
        ] = now
        last_process_state[
            pid
        ] = {
            "key": key,
            "interesting": interesting,
            "last_logged": now
        }
        return True

    previous = last_process_log.get(
        key,
        0
    )

    if PROCESS_LOG_INTERVAL > 0 and now - previous < PROCESS_LOG_INTERVAL:
        return False

    last_process_log[
        key
    ] = now
    last_process_state[
        pid
    ] = {
        "key": key,
        "interesting": interesting,
        "last_logged": now
    }
    return True


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
        buffering=8192,
        encoding="utf-8"
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

                if f.tell() >= MAX_LOG_BYTES > 0:
                    f.close()
                    rotate_if_needed(
                        file_path
                    )
                    f = open(
                        file_path,
                        "a",
                        buffering=8192,
                        encoding="utf-8"
                    )

            except Exception:
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
        if not should_log_process(
            data
        ):
            return

        features = data.get(
            "features",
            {}
        ) or {}

        anomalies = data.get(
            "anomalies",
            {}
        ) or {}

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

            "signals":
                data.get(
                    "signals",
                    {}
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
            # top-level telemetry
            # dashboard compatibility
            # -----------------------------
            "cpu":
                features.get(
                    "cpu",
                    data.get(
                        "cpu",
                        0
                    )
                ),

            "memory":
                features.get(
                    "memory",
                    data.get(
                        "memory",
                        0
                    )
                ),

            "threads":
                features.get(
                    "f_thread",
                    features.get(
                        "threads",
                        data.get(
                            "threads",
                            0
                        )
                    )
                ),

            "connections":
                features.get(
                    "connections",
                    data.get(
                        "connections",
                        0
                    )
                ),

            "file_events":
                features.get(
                    "file_events",
                    data.get(
                        "file_events",
                        0
                    )
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
                anomalies,

            "features":
                features
        }

        enqueue_latest(
            process_queue,
            normalized,
            "process"
        )

    except Exception:
        pass


# ---------------------------------------------------
# ENTITY LOGGER
# ---------------------------------------------------
def log_entity(data):

    try:
        entity_root = data.get(
            "entity_root"
        )
        now = time.time()
        previous = last_entity_log.get(
            entity_root,
            0
        )

        if now - previous < ENTITY_LOG_INTERVAL:
            return

        last_entity_log[
            entity_root
        ] = now

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

        enqueue_latest(
            entity_queue,
            normalized,
            "entity"
        )

    except Exception:
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

        enqueue_latest(
            healing_queue,
            normalized,
            "healing"
        )

    except Exception:
        pass
