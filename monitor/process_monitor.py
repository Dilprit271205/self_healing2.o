# monitor/process_monitor.py

import psutil
import os
import time

_initialized = False


# ---------------------------------------------------
# CPU INITIALIZATION
# ---------------------------------------------------
def init_cpu():

    global _initialized

    if not _initialized:

        for proc in psutil.process_iter():

            try:
                proc.cpu_percent(
                    interval=None
                )

            except:
                pass

        _initialized = True


# ---------------------------------------------------
# PROCESS COLLECTOR
# PPT + REVIEW ALIGNED
# ---------------------------------------------------
def get_process_data():

    init_cpu()

    try:
        sample_window = float(
            os.getenv(
                "SELF_HEALING_PROCESS_SAMPLE_SECONDS",
                "0.10"
            )
        )
    except Exception:
        sample_window = 0.10

    # short sampling window keeps response latency low
    # while preserving non-blocking cpu_percent readings.
    time.sleep(
        max(
            sample_window,
            0.02
        )
    )

    processes = []

    for proc in psutil.process_iter([

        "pid",
        "ppid",
        "name",
        "cpu_percent",
        "memory_percent",
        "memory_info",
        "exe",
        "cwd",
        "create_time",
        "num_threads",
        "cmdline",
        "username",
        "status",
        "open_files"

    ]):

        try:

            with proc.oneshot():

                info = proc.info

                cmdline = " ".join(
                    info.get(
                        "cmdline",
                        []
                    )
                )

                open_files = (
                    len(
                        info.get(
                            "open_files"
                        )
                        or []
                    )
                )

                # NetworkMonitor performs one system-wide connection scan.
                # Per-process net_connections() is very expensive and can make
                # live response miss short bounded simulations.
                connections = 0

            age_seconds = (
                time.time()
                -
                info.get(
                    "create_time",
                    time.time()
                )
            )

            processes.append({

                # -----------------------------
                # identity
                # -----------------------------
                "pid":
                    info["pid"],

                "ppid":
                    info["ppid"],

                "name":
                    info.get(
                        "name",
                        "unknown"
                    ),

                "exe":
                    info.get(
                        "exe",
                        ""
                    ),

                "cwd":
                    info.get(
                        "cwd",
                        ""
                    ),

                "username":
                    info.get(
                        "username",
                        ""
                    ),

                "status":
                    info.get(
                        "status",
                        ""
                    ),

                # -----------------------------
                # resource behavior
                # -----------------------------
                "cpu":
                    round(
                        info.get(
                            "cpu_percent",
                            0
                        ),
                        2
                    ),

                "memory":
                    round(
                        info.get(
                            "memory_percent",
                            0
                        ),
                        4
                    ),

                "memory_rss":
                    (
                        info.get(
                            "memory_info"
                        ).rss
                        if info.get(
                            "memory_info"
                        )
                        else 0
                    ),

                "threads":
                    info.get(
                        "num_threads",
                        1
                    ),

                # -----------------------------
                # behavioral signals
                # -----------------------------
                "cmdline":
                    cmdline,

                "create_time":
                    info.get(
                        "create_time",
                        0
                    ),

                "age_seconds":
                    round(
                        age_seconds,
                        2
                    ),

                "open_files":
                    open_files,

                "connections":
                    connections
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
