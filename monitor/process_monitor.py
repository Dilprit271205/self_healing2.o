# monitor/process_monitor.py

import psutil
import time

_initialized = False


# ---------------------------------------------------
# INIT CPU SAMPLING
# ---------------------------------------------------
def init_cpu():
    global _initialized

    if not _initialized:
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except:
                pass

        _initialized = True


# ---------------------------------------------------
# MAIN PROCESS COLLECTOR
# ---------------------------------------------------
def get_process_data():
    """
    Worm-aware process collector

    Captures:
    - pid
    - ppid
    - process name
    - cpu
    - memory
    - executable path
    - thread count
    - create time
    - cmdline

    Used for:
    lineage tracking
    rabbit worm detection
    trust scoring
    """

    init_cpu()

    # short sampling window
    time.sleep(0.35)

    processes = []

    for proc in psutil.process_iter([
        "pid",
        "ppid",
        "name",
        "cpu_percent",
        "memory_percent",
        "exe",
        "create_time",
        "num_threads",
        "cmdline"
    ]):

        try:
            info = proc.info

            name = info.get("name") or "unknown"

            # safe cmdline string
            cmdline = " ".join(info.get("cmdline", []))

            processes.append({
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": name,
                "cpu": round(info["cpu_percent"], 2),
                "memory": round(info["memory_percent"], 4),
                "exe": info.get("exe", ""),
                "threads": info.get("num_threads", 1),
                "create_time": info.get("create_time", 0),
                "cmdline": cmdline
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

        except:
            continue

    return processes