from collections import Counter
from threading import Lock
import hashlib
import os


# ==========================================
# THREAD-SAFE FILE EVENT STORE
# ==========================================
file_events = Counter()
path_events = Counter()
event_type_counts = Counter()
path_event_type_counts = Counter()
content_hash_counts = Counter()

file_lock = Lock()


# ==========================================
# RECORD FILE EVENT
# thread safe
# ==========================================
def record_file_event(
    pid,
    path=None,
    event_type="event"
):

    with file_lock:
        event_type = str(
            event_type
            or "event"
        ).lower()

        if pid is not None:
            file_events[
                pid
            ] += 1
            event_type_counts[
                event_type
            ] += 1

        if path:
            path_events[
                path
            ] += 1
            event_type_counts[
                event_type
            ] += 1
            path_event_type_counts[
                f"{event_type}:{path}"
            ] += 1

            if event_type in {
                "create",
                "modify"
            }:
                digest = _safe_file_hash(
                    path
                )

                if digest:
                    content_hash_counts[
                        digest
                    ] += 1


def _safe_file_hash(
    path
):
    try:
        max_bytes = int(
            os.getenv(
                "SELF_HEALING_HASH_MAX_BYTES",
                str(
                    2 * 1024 * 1024
                )
            )
        )
        stat = os.stat(
            path
        )

        if (
            stat.st_size <= 0
            or stat.st_size > max_bytes
        ):
            return None

        hasher = hashlib.sha256()

        with open(
            path,
            "rb"
        ) as handle:
            while True:
                chunk = handle.read(
                    65536
                )

                if not chunk:
                    break

                hasher.update(
                    chunk
                )

        return hasher.hexdigest()

    except Exception:
        return None


# ==========================================
# GET FILE MAP
# atomic snapshot + reset
# ==========================================
def get_file_map():

    global file_events
    global path_events
    global event_type_counts
    global path_event_type_counts
    global content_hash_counts

    with file_lock:

        current = dict(
            file_events
        )

        current[
            "__paths__"
        ] = dict(
            path_events
        )
        current[
            "__event_types__"
        ] = dict(
            event_type_counts
        )
        current[
            "__path_event_types__"
        ] = dict(
            path_event_type_counts
        )
        current[
            "__duplicate_hash_count__"
        ] = sum(
            count - 1
            for count in content_hash_counts.values()
            if count > 1
        )

        # atomic swap
        file_events = Counter()
        path_events = Counter()
        event_type_counts = Counter()
        path_event_type_counts = Counter()
        content_hash_counts = Counter()

    return current  
