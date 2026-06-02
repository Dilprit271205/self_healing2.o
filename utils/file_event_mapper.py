from collections import Counter
from threading import Lock


# ==========================================
# THREAD-SAFE FILE EVENT STORE
# ==========================================
file_events = Counter()
path_events = Counter()

file_lock = Lock()


# ==========================================
# RECORD FILE EVENT
# thread safe
# ==========================================
def record_file_event(
    pid,
    path=None
):

    with file_lock:

        if pid is not None:
            file_events[
                pid
            ] += 1

        if path:
            path_events[
                path
            ] += 1


# ==========================================
# GET FILE MAP
# atomic snapshot + reset
# ==========================================
def get_file_map():

    global file_events
    global path_events

    with file_lock:

        current = dict(
            file_events
        )

        current[
            "__paths__"
        ] = dict(
            path_events
        )

        # atomic swap
        file_events = Counter()
        path_events = Counter()

    return current  
