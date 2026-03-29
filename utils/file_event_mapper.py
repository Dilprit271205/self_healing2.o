from collections import defaultdict

file_events = defaultdict(int)

def record_file_event(pid):
    file_events[pid] += 1

def get_file_map():
    global file_events
    current = dict(file_events)
    file_events = defaultdict(int)  # reset per cycle
    return current