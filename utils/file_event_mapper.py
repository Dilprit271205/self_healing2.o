from collections import Counter
from threading import Lock


# ==========================================
# THREAD-SAFE FILE EVENT STORE
# ==========================================
file_events = Counter()

file_lock = Lock()


# ==========================================
# RECORD FILE EVENT
# thread safe
# ==========================================
def record_file_event(
    pid
):

    with file_lock:

        file_events[
            pid
        ] += 1


# ==========================================
# GET FILE MAP
# atomic snapshot + reset
# ==========================================
def get_file_map():

    global file_events

    with file_lock:

        current = dict(
            file_events
        )

        # atomic swap
        file_events = Counter()

    return current