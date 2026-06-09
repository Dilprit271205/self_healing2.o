# analysis/feature_extractor.py

import os
import time
from analysis.static.static_analyzer import compute_static_trust

# ---------------------------------------------------
# HISTORY STORE
# ---------------------------------------------------
process_history = {}

# Legacy extractor kept behavior-first; active detection must not depend on
# simulator/file names.
SUSPECT_KEYWORDS = []

# Safe/common processes that should not score high
SAFE_NAMES = [
    "systemd", "kthreadd", "kworker",
    "packagekitd", "gdm", "pipewire",
    "dnsmasq", "mariadbd", "prometheus",
    "chrome", "firefox", "code",
    "kdeconnectd", "dbus-daemon"
]


def extract_features(process, connection_map, file_map):
    pid = process["pid"]

    # ---------------------------------------------------
    # BASIC META
    # ---------------------------------------------------
    name = str(process.get("name", "unknown"))
    name_lower = name.lower()

    cmdline = str(process.get("cmdline", "")).lower()
    ppid = process.get("ppid", 0)

    # ---------------------------------------------------
    # EXECUTABLE PATH
    # ---------------------------------------------------
    file_path = process.get("exe", None)

    if not file_path or not os.path.exists(file_path):
        file_path = name

    # ---------------------------------------------------
    # STATIC ANALYSIS
    # ---------------------------------------------------
    static_data = compute_static_trust(file_path)

    # ---------------------------------------------------
    # LIVE VALUES
    # ---------------------------------------------------
    cpu = float(process.get("cpu", 0))
    memory = float(process.get("memory", 0))
    connections = int(connection_map.get(pid, 0))
    file_events = int(file_map.get(pid, 0))

    children_count = int(process.get("children_count", 1))
    thread_count = int(process.get("threads", 1))
    create_time = process.get("create_time", 0)

    now = time.time()

    # ---------------------------------------------------
    # HISTORY INIT
    # ---------------------------------------------------
    if pid not in process_history:
        process_history[pid] = {
            "last_time": now,
            "last_children": children_count,
            "last_cpu": cpu,
            "last_memory": memory,
            "growth": [children_count]
        }

    hist = process_history[pid]

    delta_time = max(now - hist["last_time"], 0.5)

    # ---------------------------------------------------
    # CORE WORM FEATURES
    # ---------------------------------------------------

    # real spawn burst
    f_proc_spawn = max(
        (children_count - hist["last_children"]) / delta_time,
        0
    )

    # keep for dashboard visibility only
    f_proc_tree = children_count

    # growth trend
    hist["growth"].append(children_count)

    if len(hist["growth"]) > 4:
        hist["growth"].pop(0)

    f_process_trend = 0

    if len(hist["growth"]) >= 3:
        a, b, c = hist["growth"][-3:]

        if b > a and c > b:
            f_process_trend = 1

    # resource indicators
    f_cpu = cpu
    f_cpu_trend = cpu - hist["last_cpu"]

    f_memory = memory
    f_memory_spike = memory - hist["last_memory"]

    f_thread = thread_count

    # proxy syscall rate
    f_syscall_freq = f_proc_spawn

    # repeated clone pattern
    f_syscall_pattern = 1 if (
        f_proc_spawn > 2 and
        file_events == 0 and
        connections == 0
    ) else 0

    # ---------------------------------------------------
    # YOUNG PROCESS CHECK
    # ---------------------------------------------------
    try:
        process_age = max(now - create_time, 0)
    except Exception:
        process_age = 999999

    f_young_process = 1 if process_age < 45 else 0

    # ---------------------------------------------------
    # NAME BASED SIGNAL
    # ---------------------------------------------------
    suspicious_name = 0

    for word in SUSPECT_KEYWORDS:
        if word in name_lower or word in cmdline:
            suspicious_name = 1
            break

    # ---------------------------------------------------
    # SAFE PROCESS REDUCTION
    # ---------------------------------------------------
    safe_process = 0

    for word in SAFE_NAMES:
        if word in name_lower:
            safe_process = 1
            break

    # ---------------------------------------------------
    # FINAL WORM SCORE (False Positive Resistant)
    # ---------------------------------------------------
    worm_score = (
        (f_proc_spawn * 22) +
        (f_process_trend * 28) +
        (f_young_process * 18) +
        (suspicious_name * 30) +
        (f_syscall_pattern * 15) +
        (f_cpu * 0.35)
    )

    # heavy penalty for trusted daemons
    if safe_process:
        worm_score *= 0.08

    worm_score = round(worm_score, 2)

    # ---------------------------------------------------
    # UPDATE HISTORY
    # ---------------------------------------------------
    hist["last_time"] = now
    hist["last_children"] = children_count
    hist["last_cpu"] = cpu
    hist["last_memory"] = memory

    # ---------------------------------------------------
    # FEATURE VECTOR
    # ---------------------------------------------------
    features = {

        # Basic
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "cmdline": cmdline,

        # Dynamic
        "cpu": cpu,
        "memory": memory,
        "connections": connections,
        "file_events": file_events,

        # Worm Engine
        "f_proc_spawn": round(f_proc_spawn, 2),
        "f_proc_tree": f_proc_tree,
        "f_process_trend": f_process_trend,
        "f_cpu": f_cpu,
        "f_cpu_trend": round(f_cpu_trend, 2),
        "f_memory": f_memory,
        "f_memory_spike": round(f_memory_spike, 4),
        "f_thread": f_thread,
        "f_syscall_freq": round(f_syscall_freq, 2),
        "f_syscall_pattern": f_syscall_pattern,
        "f_young_process": f_young_process,
        "suspicious_name": suspicious_name,
        "safe_process": safe_process,
        "worm_score": worm_score,

        # Static
        "file_path": file_path,
        "file_size": static_data["features"]["file_size"],
        "is_hidden": static_data["features"]["is_hidden"],
        "extension": static_data["features"]["extension"],
        "location_risk": static_data["features"]["location_risk"],

        # Trust
        "static_risk": static_data["static_risk"],
        "static_trust": static_data["static_trust"],
    }

    return features
