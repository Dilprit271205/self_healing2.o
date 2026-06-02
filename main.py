# main.py

import os
import sys
import time
import threading
import traceback
from collections import Counter, defaultdict


def configure_console_output():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(
                encoding="utf-8",
                errors="replace"
            )
        except Exception:
            pass


configure_console_output()

# ===================================================
# ANALYSIS ENGINES
# ===================================================
from analysis.extractor_engine import (
    ExtractorEngine
)

from analysis.detector_engine import (
    DetectorEngine
)

from analysis.trust_engine import (
    TrustEngine
)

from analysis.worm_classifier import (
    WormClassifier
)

from analysis.persistence_engine import (
    PersistenceEngine
)

# ===================================================
# MONITORS
# ===================================================
from monitor.process_monitor import (
    get_process_data
)

from monitor.lineage import (
    ProcessLineageTracker,
    entity_history
)

from monitor.network_monitor import (
    NetworkMonitor
)

from monitor.file_monitor import (
    start_file_monitor
)

from analysis.baseline_engine import (
    feature_history
)

from analysis.policy_engine import (
    policy_engine
)

from analysis.extractor_engine import (
    process_history,
    thread_history,
    connection_history,
    spawn_history
)

from analysis.trust.trust_vector import (
    remove_trust
)

# ===================================================
# UTILITIES
# ===================================================
from utils.connection_mapper import (
    map_connections
)

from utils.file_event_mapper import (
    get_file_map
)

# ===================================================
# LOGGER
# ===================================================
from logger.logger import (
    log_process,
    log_entity
)

# ===================================================
# CONFIG
# ===================================================
try:
    MONITOR_INTERVAL = float(
        os.getenv(
            "SELF_HEALING_MONITOR_INTERVAL",
            "3"
        )
    )
except Exception:
    MONITOR_INTERVAL = 3.0

VERBOSE_RUNTIME_LOGS = os.getenv(
    "SELF_HEALING_VERBOSE",
    "false"
).lower() in (
    "1",
    "true",
    "yes",
    "y"
)


def debug_print(
    message
):
    if VERBOSE_RUNTIME_LOGS:
        print(
            message
        )

SYSTEM_SAFE_PIDS = {
    0,
    1,
    os.getpid()
}

# ===================================================
# ENGINE INIT
# ===================================================
extractor = ExtractorEngine()

detector = DetectorEngine()

trust_engine = TrustEngine()

worm_classifier = WormClassifier()

persistence_engine = (
    PersistenceEngine()
)

lineage_tracker = (
    ProcessLineageTracker()
)
network_monitor = (
    NetworkMonitor()
)

file_observer = None
rapid_lineage_thread = None
rapid_lineage_stop = threading.Event()
file_burst_window = defaultdict(list)
resource_burst_window = defaultdict(list)
last_console_events = {}


def rate_limited_print(
    key,
    message,
    interval=5
):
    now = time.time()
    previous = last_console_events.get(
        key,
        0
    )

    if now - previous < interval:
        return

    last_console_events[
        key
    ] = now
    print(
        message
    )

# ===================================================
# FILE MONITOR THREAD
# ===================================================

def start_background_monitors():

    global file_observer

    try:

        file_observer = start_file_monitor()

        if file_observer is None:
            print(
                "[FILE] File monitor skipped (watchdog unavailable or paths missing)"
            )
            return

        print(
            "[FILE] File monitor started"
        )

    except Exception as e:

        print(
            f"File monitor failed: {e}"
        )


def stop_background_monitors():

    global file_observer
    rapid_lineage_stop.set()

    if file_observer is None:
        return

    try:
        file_observer.stop()
        file_observer.join()
        print("[FILE] File monitor stopped")
    except Exception as e:
        print(f"Failed to stop file monitor: {e}")
    finally:
        file_observer = None


def _lightweight_process_snapshot():
    try:
        import psutil
    except Exception:
        return []

    processes = []
    now = time.time()

    attrs = [
        "pid",
        "ppid",
        "name",
        "exe",
        "cwd",
        "create_time",
        "cpu_percent",
        "memory_percent",
        "memory_info",
        "cmdline",
        "username",
        "status",
        "num_threads"
    ]

    for proc in psutil.process_iter(attrs):
        try:
            with proc.oneshot():
                info = proc.info

                cmdline = " ".join(
                    info.get(
                        "cmdline",
                        []
                    )
                    or []
                )

                create_time = info.get(
                    "create_time",
                    now
                )

                processes.append({
                    "pid": info.get(
                        "pid"
                    ),
                    "ppid": info.get(
                        "ppid",
                        0
                    ),
                    "name": info.get(
                        "name",
                        "unknown"
                    ),
                    "exe": info.get(
                        "exe",
                        ""
                    ),
                    "cwd": info.get(
                        "cwd",
                        ""
                    ),
                    "username": info.get(
                        "username",
                        ""
                    ),
                    "status": info.get(
                        "status",
                        ""
                    ),
                    "cpu": round(
                        info.get(
                            "cpu_percent",
                            0
                        )
                        or 0,
                        2
                    ),
                    "memory": round(
                        info.get(
                            "memory_percent",
                            0
                        )
                        or 0,
                        4
                    ),
                    "memory_rss": (
                        info.get(
                            "memory_info"
                        ).rss
                        if info.get(
                            "memory_info"
                        )
                        else 0
                    ),
                    "threads": info.get(
                        "num_threads",
                        1
                    ),
                    "cmdline": cmdline,
                    "create_time": create_time,
                    "age_seconds": round(
                        now - create_time,
                        2
                    ),
                    "open_files": 0,
                    "connections": 0
                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

        except Exception:
            continue

    return processes


def rapid_lineage_monitor_loop():
    try:
        interval = float(
            os.getenv(
                "SELF_HEALING_RAPID_LINEAGE_INTERVAL",
                "1.5"
            )
        )
    except Exception:
        interval = 1.5

    while not rapid_lineage_stop.is_set():
        try:
            processes = _lightweight_process_snapshot()

            if processes:
                emergency_process_storm_preflight(
                    processes,
                    {},
                    {}
                )

                file_map = get_file_map()
                emergency_file_activity_preflight(
                    processes,
                    file_map
                )

                emergency_resource_preflight(
                    processes
                )

        except Exception as e:
            print(
                f"[RAPID] lineage monitor error: {e}"
            )

        rapid_lineage_stop.wait(
            max(
                interval,
                0.1
            )
        )


def start_rapid_lineage_monitor():
    global rapid_lineage_thread

    if rapid_lineage_thread is not None:
        return

    rapid_lineage_stop.clear()
    rapid_lineage_thread = threading.Thread(
        target=rapid_lineage_monitor_loop,
        name="rapid-lineage-monitor",
        daemon=True
    )
    rapid_lineage_thread.start()
    print(
        "[RAPID] Lineage storm monitor started"
    )

# ===================================================
# SAFE PROCESS FILTERS
# ===================================================

def is_idle_process(
    process
):

    return (
        process.get("cpu", 0) <= 0.5
        and
        process.get("memory", 0) < 0.5
        and
        process.get("connections", 0) == 0
        and
        process.get("open_files", 0) < 10
        and
        process.get("age_seconds", 0) > 30
    )


# ===================================================
# ENTITY LOGGER
# ===================================================
def log_entities(
    processes=None
):

    try:

        entity_summary = (

            lineage_tracker
            .get_entity_summary(
                processes
            )
        )

        for entity in entity_summary:

            log_entity(
                entity
            )

    except Exception as e:

        print(
            f"Entity logging error: {e}"
        )

# ===================================================
# PROCESS PRIORITY
# ===================================================
def process_priority(
    process,
    entity_map
):
    try:
        pid = process.get(
            "pid"
        )

        entity_size = len(
            entity_map.get(
                pid,
                []
            )
        )

        young_bonus = (
            50
            if process.get(
                "age_seconds",
                9999
            ) < 90
            else 0
        )

        return (
            entity_size * 10
            + float(process.get("cpu", 0)) * 2
            + int(process.get("threads", 0))
            + int(process.get("open_files", 0))
            + young_bonus
        )

    except Exception:
        return 0


def should_deep_inspect(
    process,
    entity_map
):
    try:
        pid = process.get(
            "pid"
        )

        entity_size = len(
            entity_map.get(
                pid,
                []
            )
        )

        return (
            process.get("age_seconds", 9999) < 120
            or float(process.get("cpu", 0)) >= 2.0
            or float(process.get("memory", 0)) >= 5.0
            or int(process.get("threads", 0)) >= 25
            or int(process.get("open_files", 0)) >= 25
            or entity_size >= 8
            or pid in persistence_engine.history
        )

    except Exception:
        return True


# ===================================================
# CATASTROPHIC PREFLIGHT
# ===================================================
def _process_signature(
    process
):
    name = str(
        process.get(
            "name",
            ""
        )
    ).lower()

    cmdline = str(
        process.get(
            "cmdline",
            ""
        )
    ).lower()

    if cmdline:
        return cmdline[:180]

    return name


def _child_storm_profile(
    process,
    children_by_parent
):
    pid = process.get(
        "pid"
    )

    direct_children = children_by_parent.get(
        pid,
        []
    )

    if not direct_children:
        return {
            "direct_children": 0,
            "repeated_child_count": 0,
            "child_similarity": 0,
            "young_child_ratio": 0
        }

    signatures = Counter(
        _process_signature(child)
        for child in direct_children
    )

    repeated_child_count = max(
        signatures.values()
    )

    young_children = sum(
        1
        for child in direct_children
        if child.get(
            "age_seconds",
            9999
        ) <= 90
    )

    child_similarity = (
        repeated_child_count
        /
        max(
            len(direct_children),
            1
        )
    )

    young_child_ratio = (
        young_children
        /
        max(
            len(direct_children),
            1
        )
    )

    return {
        "direct_children": len(direct_children),
        "repeated_child_count": repeated_child_count,
        "child_similarity": round(child_similarity, 3),
        "young_child_ratio": round(young_child_ratio, 3)
    }


def _build_children_by_parent(
    processes
):
    children_by_parent = defaultdict(list)

    for process in processes:
        children_by_parent[
            process.get(
                "ppid"
            )
        ].append(process)

    return children_by_parent


def _count_descendants(
    pid,
    children_by_parent
):
    total = 0
    stack = list(
        children_by_parent.get(
            pid,
            []
        )
    )
    seen = set()

    while stack:
        child = stack.pop()
        child_pid = child.get(
            "pid"
        )

        if child_pid in seen:
            continue

        seen.add(
            child_pid
        )
        total += 1
        stack.extend(
            children_by_parent.get(
                child_pid,
                []
            )
        )

    return total


def emergency_process_storm_preflight(
    processes,
    entity_map,
    root_map
):
    children_by_parent = _build_children_by_parent(
        processes
    )
    handled_pids = set()

    for process in sorted(
        processes,
        key=lambda p: len(
            children_by_parent.get(
                p.get(
                    "pid"
                ),
                []
            )
        ),
        reverse=True
    ):
        pid = process.get(
            "pid"
        )

        if (
            pid in SYSTEM_SAFE_PIDS
            or (
                pid is not None
                and
                int(pid) <= 10
            )
            or pid in getattr(
                globals().get(
                    "response_engine",
                    None
                ),
                "protected_pids",
                set()
            )
            or pid in handled_pids
        ):
            continue

        if policy_engine.is_suppressed_category(
            policy_engine.infer_category(
                process
            )
        ):
            continue

        profile = _child_storm_profile(
            process,
            children_by_parent
        )

        descendants = _count_descendants(
            pid,
            children_by_parent
        )

        catastrophic_storm = (
            profile["direct_children"] >= 12
            and profile["repeated_child_count"] >= 8
            and profile["child_similarity"] >= 0.65
            and profile["young_child_ratio"] >= 0.65
            and descendants >= 12
        )

        emergency_storm = (
            profile["direct_children"] >= 20
            and profile["repeated_child_count"] >= 12
            and profile["child_similarity"] >= 0.70
            and profile["young_child_ratio"] >= 0.50
            and descendants >= 20
        )

        if not (
            catastrophic_storm
            or emergency_storm
        ):
            continue

        features = {
            "f_proc_spawn": profile["direct_children"],
            "f_proc_tree": descendants,
            "f_process_trend": profile["direct_children"],
            "f_young_process": (
                1
                if process.get(
                    "age_seconds",
                    9999
                ) <= 180
                else 0
            ),
            "f_repeated_child_count": profile[
                "repeated_child_count"
            ],
            "f_child_similarity": profile[
                "child_similarity"
            ],
            "f_short_lived_child_ratio": profile[
                "young_child_ratio"
            ],
            "file_events": 0,
            "worm_score": 95,
            "emergency_preflight": True
        }

        classification = {
            "label": "forkbomb",
            "severity": "critical",
            "worm_score": 0.96,
            "confidence": 96,
            "signals": {
                "combined_risk": 0.96,
                "correlated_signal_count": 5,
                "catastrophic_behavior": True,
                "forkbomb_detected": True,
                "replication_detected": False,
                "fanout_detected": False,
                "correlated_signals": {
                    "rapid_child_spawning": True,
                    "large_or_growing_tree": True,
                    "repeated_similar_children": True,
                    "short_lived_recursive_children": True,
                    "process_storm_burst": True
                }
            }
        }

        trust_state = {
            "dynamic_trust": 0.25,
            "final_trust": 0.25,
            "static_trust": 0.78
        }

        persistence_state = {
            "persistent": True,
            "confidence": 0.96,
            "stage": "terminate",
            "avg_worm_score": 0.96,
            "avg_dynamic_trust": 0.25,
            "avg_final_trust": 0.25,
            "avg_confidence": 0.96,
            "avg_combined_risk": 0.96,
            "avg_correlated_signals": 5,
            "termination_ready": True,
            "catastrophic_ready": True,
            "force_terminate": True
        }

        rate_limited_print(
            f"process_storm_{pid}",
            f"[EMERGENCY] process storm pid={pid} "
            f"children={profile['direct_children']} "
            f"repeated={profile['repeated_child_count']} "
            f"similarity={profile['child_similarity']} "
            f"young_ratio={profile['young_child_ratio']} "
            f"tree={descendants}",
            interval=3
        )

        healing_result = execute_healing(
            pid=pid,
            process=process,
            features=features,
            classification=classification,
            persistence_state=persistence_state,
            trust_state=trust_state
        )

        response_result = healing_result[
            "response"
        ]

        log_process({
            "pid": pid,
            "name": process.get(
                "name",
                "unknown"
            ),
            "entity_root": root_map.get(
                pid,
                process.get(
                    "ppid",
                    0
                )
            ),
            "trust": trust_state,
            "worm_score": classification[
                "worm_score"
            ],
            "confidence": classification[
                "confidence"
            ],
            "label": classification[
                "label"
            ],
            "severity": classification[
                "severity"
            ],
            "stage": response_result[
                "stage"
            ],
            "response": response_result[
                "status"
            ],
            "learning_state": healing_result[
                "learning"
            ],
            "anomalies": {},
            "features": features
        })

        handled_pids.add(
            pid
        )

    return handled_pids


def _path_event_totals(
    path_events
):
    totals = defaultdict(int)

    for path, count in (
        path_events
        or {}
    ).items():
        try:
            normalized = os.path.abspath(
                path
            )
            directory = os.path.dirname(
                normalized
            )
        except Exception:
            continue

        totals[
            directory
        ] += int(
            count
        )

    return totals


def _is_broad_file_root(
    path
):
    try:
        normalized = os.path.abspath(
            path
        )
        normalized_posix = normalized.replace(
            "\\",
            "/"
        ).rstrip(
            "/"
        )

        home = os.path.abspath(
            os.path.expanduser(
                "~"
            )
        )

        broad_roots = {
            os.path.abspath(
                os.sep
            ),
            home,
            os.path.abspath(
                "/tmp"
            ),
            os.path.abspath(
                "/var/tmp"
            )
        }

        if normalized in broad_roots:
            return True

        parts = [
            part
            for part in normalized_posix.split(
                "/"
            )
            if part
        ]

        if (
            len(parts) <= 3
            and (
                normalized_posix.endswith(
                    "/home/kali"
                )
                or normalized_posix.endswith(
                    "/home"
                )
                or normalized_posix.endswith(
                    "/tmp"
                )
                or normalized_posix.endswith(
                    "/var/tmp"
                )
            )
        ):
            return True

        return False

    except Exception:
        return True


def _path_is_under(
    child,
    parent
):
    try:
        child_abs = os.path.abspath(
            child
        )
        parent_abs = os.path.abspath(
            parent
        )

        return (
            child_abs == parent_abs
            or
            child_abs.startswith(
                parent_abs + os.sep
            )
        )

    except Exception:
        return False


def emergency_file_activity_preflight(
    processes,
    file_map
):
    path_events = (
        file_map
        or {}
    ).get(
        "__paths__",
        {}
    )

    if (
        not path_events
        and
        not file_burst_window
    ):
        return set()

    directory_totals = _path_event_totals(
        path_events
    )

    now = time.time()
    for directory, count in directory_totals.items():
        file_burst_window[
            directory
        ].append(
            (
                now,
                int(count)
            )
        )

    for directory in list(
        file_burst_window.keys()
    ):
        file_burst_window[
            directory
        ] = [
            (
                timestamp,
                count
            )
            for timestamp, count in file_burst_window[
                directory
            ]
            if now - timestamp <= 5
        ]

        if not file_burst_window[
            directory
        ]:
            file_burst_window.pop(
                directory,
                None
            )

    rolling_totals = {
        directory: sum(
            count
            for _, count in samples
        )
        for directory, samples in file_burst_window.items()
    }

    total_events = sum(
        rolling_totals.values()
    )

    if total_events < 60:
        return set()

    active_directories = [
        directory
        for directory, count in rolling_totals.items()
        if count >= 35
    ]

    if not active_directories:
        return set()

    handled_pids = set()
    candidate_seen = False

    for process in sorted(
        processes,
        key=lambda p: p.get(
            "age_seconds",
            9999
        )
    ):
        pid = process.get(
            "pid"
        )

        if pid in SYSTEM_SAFE_PIDS:
            continue

        if pid in getattr(
            globals().get(
                "response_engine",
                None
            ),
            "protected_pids",
            set()
        ):
            continue

        if process.get(
            "age_seconds",
            9999
        ) > 240:
            continue

        if policy_engine.is_critical_process_hint(
            process
        ):
            continue

        category = policy_engine.infer_category(
            process
        )

        if policy_engine.is_suppressed_category(
            category
        ):
            continue

        cwd = process.get(
            "cwd",
            ""
        )

        matched_events = 0
        cwd_abs = ""

        if cwd:
            try:
                cwd_abs = os.path.abspath(
                    cwd
                )
            except Exception:
                cwd_abs = ""

        if cwd_abs:
            for directory, count in rolling_totals.items():
                if (
                    not _is_broad_file_root(
                        cwd_abs
                    )
                    and
                    _path_is_under(
                        directory,
                        cwd_abs
                    )
                ):
                    matched_events += count

        if not cwd_abs:
            cwd_abs = (
                process.get(
                    "cwd",
                    ""
                )
                or
                "unknown"
            )

        if matched_events < 60:
            continue

        candidate_seen = True
        file_containment_enabled = os.getenv(
            "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
            "false"
        ).lower() in (
            "1",
            "true",
            "yes",
            "y"
        )
        confirmed_file_owner = (
            matched_events >= 120
            and not _is_broad_file_root(
                cwd_abs
            )
        )

        stage = "observe"

        if not file_containment_enabled:
            rate_limited_print(
                "file_replication_observed",
                f"[OBSERVE] file activity pid={pid} "
                f"events={matched_events} cwd={cwd_abs}",
                interval=8
            )

            log_process({
                "pid": pid,
                "name": process.get(
                    "name",
                    "unknown"
                ),
                "entity_root": process.get(
                    "ppid",
                    0
                ),
                "trust": {
                    "dynamic_trust": 0.75,
                    "final_trust": 0.75,
                    "static_trust": 0.78
                },
                "worm_score": 0.45,
                "confidence": 45,
                "label": "suspicious",
                "severity": "medium",
                "stage": "observe",
                "response": "file activity observed",
                "learning_state": {},
                "anomalies": {},
                "features": {
                    "file_events": matched_events,
                    "file_replication_preflight": True,
                    "containment_enabled": False
                }
            })

            handled_pids.add(
                pid
            )
            continue

        if file_containment_enabled and confirmed_file_owner:
            stage = "quarantine"

        features = {
            "f_proc_spawn": 0,
            "f_proc_tree": 1,
            "f_process_trend": 0,
            "f_young_process": 1,
            "file_events": matched_events,
            "worm_score": 90,
            "emergency_preflight": True,
            "file_replication_preflight": True
        }

        classification = {
            "label": "worm",
            "severity": "critical",
            "worm_score": 0.92,
            "confidence": 92,
            "signals": {
                "combined_risk": 0.90,
                "correlated_signal_count": 4,
                "catastrophic_behavior": False,
                "forkbomb_detected": False,
                "replication_detected": True,
                "fanout_detected": False,
                "correlated_signals": {
                    "file_replication": True,
                    "high_file_velocity": True,
                    "extreme_file_velocity": matched_events >= 75,
                    "baseline_anomaly": True
                }
            }
        }

        trust_state = {
            "dynamic_trust": 0.35,
            "final_trust": 0.35,
            "static_trust": 0.78
        }

        persistence_state = {
            "persistent": True,
            "confidence": 0.92,
            "stage": stage,
            "avg_worm_score": 0.92,
            "avg_dynamic_trust": 0.35,
            "avg_final_trust": 0.35,
            "avg_confidence": 0.92,
            "avg_combined_risk": 0.90,
            "avg_correlated_signals": 4,
            "confirmed_behavior": (
                file_containment_enabled
                and confirmed_file_owner
            )
        }

        rate_limited_print(
            "file_replication_observed",
            f"[EMERGENCY] file replication pid={pid} "
            f"stage={stage} events={matched_events} cwd={cwd_abs}",
            interval=8
        )

        healing_result = execute_healing(
            pid=pid,
            process=process,
            features=features,
            classification=classification,
            persistence_state=persistence_state,
            trust_state=trust_state
        )

        response_result = healing_result[
            "response"
        ]

        log_process({
            "pid": pid,
            "name": process.get(
                "name",
                "unknown"
            ),
            "entity_root": process.get(
                "ppid",
                0
            ),
            "trust": trust_state,
            "worm_score": classification[
                "worm_score"
            ],
            "confidence": classification[
                "confidence"
            ],
            "label": classification[
                "label"
            ],
            "severity": classification[
                "severity"
            ],
            "stage": response_result[
                "stage"
            ],
            "response": response_result[
                "status"
            ],
            "learning_state": healing_result[
                "learning"
            ],
            "anomalies": {},
            "features": features
        })

        if response_result.get(
            "action_taken",
            False
        ):
            handled_pids.add(
                pid
            )
            break

    if (
        not handled_pids
        and not candidate_seen
        and total_events >= 100
    ):
        directory_summary = ", ".join(
            f"{os.path.basename(directory) or directory}:{count}"
            for directory, count in sorted(
                rolling_totals.items(),
                key=lambda item: item[1],
                reverse=True
            )[:3]
        )
        rate_limited_print(
            "file_burst_no_candidate",
            f"[EMERGENCY] file burst observed events={total_events} "
            f"dirs={directory_summary} "
            "but no eligible process candidate",
            interval=8
        )

    return handled_pids


def emergency_resource_preflight(
    processes
):
    now = time.time()
    handled_pids = set()

    live_pids = {
        process.get(
            "pid"
        )
        for process in processes
    }

    for pid in list(
        resource_burst_window.keys()
    ):
        if pid not in live_pids:
            resource_burst_window.pop(
                pid,
                None
            )

    for process in processes:
        pid = process.get(
            "pid"
        )

        if (
            pid in SYSTEM_SAFE_PIDS
            or (
                pid is not None
                and
                int(pid) <= 10
            )
            or pid in getattr(
                globals().get(
                    "response_engine",
                    None
                ),
                "protected_pids",
                set()
            )
        ):
            continue

        if policy_engine.is_critical_process_hint(
            process
        ):
            continue

        category = policy_engine.infer_category(
            process
        )

        if policy_engine.is_suppressed_category(
            category
        ):
            continue

        sample = {
            "timestamp": now,
            "cpu": float(
                process.get(
                    "cpu",
                    0
                )
            ),
            "memory": float(
                process.get(
                    "memory",
                    0
                )
            ),
            "memory_rss": int(
                process.get(
                    "memory_rss",
                    0
                )
            ),
            "threads": int(
                process.get(
                    "threads",
                    0
                )
            )
        }

        history = resource_burst_window[
            pid
        ]
        history.append(
            sample
        )
        resource_burst_window[
            pid
        ] = [
            item
            for item in history
            if now - item[
                "timestamp"
            ] <= 6
        ]

        history = resource_burst_window[
            pid
        ]

        if len(
            history
        ) < 2:
            continue

        latest = history[-1]
        previous = history[-2]

        thread_velocity = (
            latest["threads"]
            -
            previous["threads"]
        )

        memory_rss_mb = (
            latest["memory_rss"]
            /
            (1024 * 1024)
        )

        thread_storm = (
            (
                latest["threads"] >= 100
                and process.get(
                    "age_seconds",
                    9999
                ) <= 180
            )
            or thread_velocity >= 50
        )
        cpu_exhaustion = (
            latest["cpu"] >= 85
            and previous["cpu"] >= 70
        )
        memory_spike = (
            latest["memory"] >= 35
            or memory_rss_mb >= 750
        )

        if not (
            thread_storm
            or cpu_exhaustion
            or memory_spike
        ):
            continue

        stage = "throttle"
        severity = "medium"
        label = "suspicious"
        confidence = 58
        combined_risk = 0.55

        if thread_storm:
            stage = "quarantine"
            severity = "high"
            confidence = 76
            combined_risk = 0.74

        if (
            thread_storm
            and (
                cpu_exhaustion
                or memory_spike
            )
        ):
            stage = "quarantine"
            severity = "critical"
            confidence = 84
            combined_risk = 0.82

        features = {
            "cpu": latest["cpu"],
            "memory": latest["memory"],
            "memory_rss": latest["memory_rss"],
            "f_thread": latest["threads"],
            "f_thread_velocity": thread_velocity,
            "file_events": 0,
            "worm_score": confidence,
            "emergency_preflight": True,
            "resource_preflight": True
        }

        classification = {
            "label": label,
            "severity": severity,
            "worm_score": round(
                confidence / 100,
                2
            ),
            "confidence": confidence,
            "signals": {
                "combined_risk": combined_risk,
                "correlated_signal_count": (
                    3
                    if thread_storm
                    else 2
                ),
                "catastrophic_behavior": False,
                "forkbomb_detected": False,
                "replication_detected": False,
                "fanout_detected": False,
                "thread_storm_detected": thread_storm,
                "correlated_signals": {
                    "thread_explosion": thread_storm,
                    "cpu_memory_escalation": (
                        cpu_exhaustion
                        or memory_spike
                    ),
                    "resource_pressure": True,
                    "baseline_anomaly": True
                }
            }
        }

        trust_state = {
            "dynamic_trust": 0.55,
            "final_trust": 0.58,
            "static_trust": 0.78
        }

        persistence_state = {
            "persistent": True,
            "confidence": round(
                confidence / 100,
                2
            ),
            "stage": stage,
            "avg_worm_score": round(
                confidence / 100,
                2
            ),
            "avg_dynamic_trust": 0.55,
            "avg_final_trust": 0.58,
            "avg_confidence": round(
                confidence / 100,
                2
            ),
            "avg_combined_risk": combined_risk,
            "avg_correlated_signals": (
                3
                if thread_storm
                else 2
            )
        }

        print(
            f"[EMERGENCY] resource pressure pid={pid} "
            f"stage={stage} cpu={latest['cpu']} "
            f"mem={round(memory_rss_mb, 1)}MB "
            f"threads={latest['threads']} "
            f"thread_delta={thread_velocity}"
        )

        healing_result = execute_healing(
            pid=pid,
            process=process,
            features=features,
            classification=classification,
            persistence_state=persistence_state,
            trust_state=trust_state
        )

        response_result = healing_result[
            "response"
        ]

        log_process({
            "pid": pid,
            "name": process.get(
                "name",
                "unknown"
            ),
            "entity_root": process.get(
                "ppid",
                0
            ),
            "trust": trust_state,
            "worm_score": classification[
                "worm_score"
            ],
            "confidence": classification[
                "confidence"
            ],
            "label": classification[
                "label"
            ],
            "severity": classification[
                "severity"
            ],
            "stage": response_result[
                "stage"
            ],
            "response": response_result[
                "status"
            ],
            "learning_state": healing_result[
                "learning"
            ],
            "anomalies": {},
            "features": features
        })

        handled_pids.add(
            pid
        )

    return handled_pids

# ===================================================
# MAIN LOOP
# ===================================================
def monitor_loop():

    print(
        "\n[START] Self-Healing Cyber Defense Started"
    )

    while True:
        try:

            # =====================================
            # LIVE DATA COLLECTION
            # =====================================
            processes = (
                get_process_data()
            )
            emergency_handled = emergency_process_storm_preflight(
                processes,
                {},
                {}
            )

            network_data = (   
               network_monitor
               .get_network_data()
           )

            connection_map = (
                map_connections(
                    network_data
                )
            )

            file_map = (
                get_file_map()
            )

            # =====================================
            # BUILD ENTITY MAP
            # =====================================
            entity_map = {}
            root_map = {}

            entities = (

                lineage_tracker
                .build_entities(
                    processes
                )
            )
            for (
                root,
                members
            ) in entities.items():

                for proc in members:

                    entity_map[
                        proc["pid"]
                    ] = members
                    root_map[
                        proc["pid"]
                    ] = root

            # =====================================
            # ENTITY LOGGING
            # =====================================
            log_entities(
                processes
            )

            # =====================================
            # PROCESS PIPELINE
            # =====================================
            ordered_processes = [
                p for p in sorted(
                    processes,
                    key=lambda p: process_priority(
                        p,
                        entity_map
                    ),
                    reverse=True
                )
                if should_deep_inspect(
                    p,
                    entity_map
                )
            ][:30]

            rate_limited_print(
                "monitor_loop_summary",
                (
                    f"[LOOP] processes={len(processes)} "
                    f"entities={len(entities)} "
                    f"deep_inspect={len(ordered_processes)}"
                ),
                interval=15.0
            )

            for process in ordered_processes:

                try:

                    pid = process.get(
                        "pid"
                    )

                    if (
                        pid
                        in
                        SYSTEM_SAFE_PIDS
                        or
                        pid
                        in
                        emergency_handled
                    ):

                        continue

                    # -------------------------
                    # FEATURE EXTRACTION
                    # -------------------------
                    features = (
                        extractor.extract(

                            process=
                            process,

                            entity_map=
                            entity_map,

                            connection_map=
                            connection_map,

                            file_map=
                            file_map
                        )
                    )
                    debug_print(
                        "[FEATURES OK]"
                    )

                    # -------------------------
                    # DETECTOR
                    # -------------------------
                    anomaly_data = (

                        detector.detect(
                            pid,
                            features
                        )
                    )

                    anomaly_vector = (
                        anomaly_data[
                            "anomalies"
                        ]
                    )

                    # -------------------------
                    # BASE TRUST
                    # deliberately behavior-neutral:
                    # no process name can make a
                    # process trusted or suspicious.
                    # -------------------------
                    static_score = 0.85

                    if features.get(
                        "f_young_process",
                        0
                    ):

                        static_score = 0.78

                    if features.get(
                        "false_positive_suppression",
                        0
                    ):

                        static_score = max(
                            static_score,
                            0.88
                        )

                    # -------------------------
                    # TRUST ENGINE
                    # -------------------------
                    trust_state = (

                        trust_engine
                        .update(

                            pid=
                            pid,

                            anomaly_vector=
                            anomaly_vector,

                            static_score=
                            static_score
                        )
                    )

                    # -------------------------
                    # WORM CLASSIFIER
                    # -------------------------
                    classification = (

                        worm_classifier
                        .classify(

                            features=
                            features,

                            anomaly_data=
                            anomaly_data,

                            trust_state=
                            trust_state
                        )
                    )

                    # -------------------------
                    # FLAGGED PROCESS OUTPUT
                    # show trust drift and suspicious labels
                    # -------------------------
                    process_name = (
                        process.get(
                            "name",
                            "unknown"
                        )
                    )

                    low_trust = (
                        trust_state.get(
                            "final_trust",
                            1.0
                        )
                        <
                        0.9
                    )

                    if (
                        classification.get(
                            "label"
                        )
                        !=
                        "normal"
                        or
                        low_trust
                    ):

                        print(
                            f"[FLAGGED] pid={pid} "
                            f"name={process_name} "
                            f"label={classification.get('label')} "
                            f"severity={classification.get('severity')} "
                            f"worm_score={classification.get('worm_score')} "
                            f"final_trust={trust_state.get('final_trust')} "
                            f"dynamic_trust={trust_state.get('dynamic_trust')} "
                            f"static_trust={trust_state.get('static_trust')}"
                        )

                    # -------------------------
                    # PERSISTENCE
                    # -------------------------
                    persistence_engine.update(

                        pid=
                        pid,

                        classification=
                        classification,

                        trust_state=
                        trust_state
                    )

                    persistence_state = (

                        persistence_engine
                        .check_persistence(
                            pid
                        )
                    )

                    # -------------------------
                    # ADAPTIVE HEALING
                    # -------------------------
                    healing_result = execute_healing(

                            pid=pid,

                            process=process,

                            features=features,

                            classification=classification,

                            persistence_state=persistence_state,

                            trust_state=trust_state
                        )

                    response_result = (
                        healing_result[
                            "response"
                        ]
                    )

                    learning_state = (
                        healing_result[
                            "learning"
                        ]
                    )

                    # -------------------------
                    # PROCESS LOGGER
                    # dashboard compatible
                    # -------------------------
                    log_process({

                        "pid":
                            pid,

                        "name":
                            process.get(
                                "name",
                                "unknown"
                            ),

                        "entity_root":
                            root_map.get(
                                pid,
                                process.get(
                                    "ppid",
                                    0
                                )
                            ),

                        "trust":
                            trust_state,

                        "worm_score":
                            classification[
                                "worm_score"
                            ],

                        "confidence":
                            classification[
                                "confidence"
                            ],

                        "label":
                            classification[
                                "label"
                            ],

                        "severity":
                            classification[
                                "severity"
                            ],

                        "stage":
                            response_result[
                                "stage"
                            ],

                        "response":
                            response_result[
                                "status"
                            ],

                        "learning_state":
                            learning_state,

                        "anomalies":
                            anomaly_vector,

                        "features":
                            features
                    })
                    debug_print(
                        "[LOGGED]"
                    )

                except Exception as e:

                    import traceback

                    print(
                        f"\n{'='*60}"
                    )

                    print(
                        f"PROCESS ERROR PID {pid}"
                    )

                    print(
                        f"ERROR: {e}"
                    )

                    print(
                        traceback.format_exc()
                    )

                    print(
                        f"{'='*60}\n"
                    )

            # -------------------------
            # DEAD PID CLEANUP
            # -------------------------
            cleanup_dead_pids(
                processes
            )

            # -------------------------
            # LOOP DELAY
            # -------------------------
            time.sleep(
                MONITOR_INTERVAL
            )

        except KeyboardInterrupt:

            print(
                "\n[STOP] System stopped."
            )

            stop_background_monitors()
            break

        except Exception:

            print(
                traceback.format_exc()
            )

            time.sleep(3)
# ===================================================
# PART 2
# HEALING + LEARNING RUNTIME
# ===================================================

from analysis.learning_engine import (
    LearningEngine
)

from analysis.response_engine import (
    ResponseEngine
)

from logger.logger import (
    log_healing
)

# ===================================================
# ENGINE INIT
# ===================================================
learning_engine = (
    LearningEngine()
)

HEALING_SAFE_MODE = (
    os.environ.get(
        "SELF_HEALING_SAFE_MODE",
        os.environ.get(
            "HEALING_SAFE_MODE",
            "false"
        )
    )
    .strip()
    .lower()
    in {
    "1",
    "true",
    "yes"
    }
)

response_engine = (
    ResponseEngine(
        safe_mode=HEALING_SAFE_MODE
    )
)

if HEALING_SAFE_MODE:
    print("[SAFE_MODE] Healing actions disabled")

# Ensure the controller PID is protected explicitly
try:
    response_engine.add_protected_pid(os.getpid())
except:
    pass

# ===================================================
# DEAD PID TRACKER
# prevents memory leak
# ===================================================
active_pids = set()


# ===================================================
# SAFE CLEANUP
# ===================================================
def cleanup_dead_pids(
    live_processes
):

    global active_pids

    try:

        current_pids = {

            p["pid"]
            for p
            in live_processes
        }

        dead = (
            active_pids
            -
            current_pids
        )

        if len(dead):

            print(

                f"[CLEANUP] Cleaned "
                f"{len(dead)} "
                f"dead processes"
            )

            for pid in dead:
                remove_trust(pid)
                process_history.pop(pid, None)
                thread_history.pop(pid, None)
                connection_history.pop(pid, None)
                spawn_history.pop(pid, None)
                feature_history.pop(pid, None)
                persistence_engine.history.pop(pid, None)
                response_engine.response_history.pop(pid, None)
                entity_history.pop(pid, None)

        active_pids = (
            current_pids
        )

    except Exception as e:

        print(
            f"Cleanup error: {e}"
        )


# ===================================================
# HEALING EXECUTION
# ===================================================
def execute_healing(

    pid,

    process,

    features=None,

    classification=None,

    persistence_state=None,

    trust_state=None
):

    if features is None:
        features = {}

    if classification is None:
        classification = {}

    if persistence_state is None:
        persistence_state = {"stage": "observe"}

    if trust_state is None:
        trust_state = {"dynamic_trust": 1.0, "final_trust": 1.0}

    try:
        force_stage = (
            persistence_state.get("termination_ready")
            or
            persistence_state.get("catastrophic_ready")
        )

        # --------------------------------
        # LEARNING ADAPTATION
        # slide 17-18
        # --------------------------------
        recommended_stage = (

            learning_engine
            .recommend_stage(

                process_info=
                process,

                persistence_stage=
                persistence_state[
                    "stage"
                ]
            )
        )

        learned_stage = (
            learning_engine
            .recommend_from_knowledge(
                process_info=
                {
                    **process,
                    "process_category": features.get(
                        "process_category",
                        ""
                    )
                },

                classification=
                classification,

                persistence_stage=
                recommended_stage
            )
        )

        persistence_state[
            "stage"
        ] = (
            learned_stage
        )

        if force_stage:
            persistence_state["stage"] = "terminate"

        if persistence_state.get("catastrophic_ready"):
            persistence_state["force_terminate"] = True

        # --------------------------------
        # RESPONSE ENGINE
        # --------------------------------
        response_result = (

            response_engine
            .execute(

                pid=
                pid,

                process_info=
                process,

                persistence_state=
                persistence_state
            )
        )

        # --------------------------------
        # LEARNING UPDATE
        # --------------------------------
        learning_engine.update(

            pid=
            pid,

            process_info=
            process,

            classification=
            classification,

            response_result=
            response_result,

            trust_state=
            trust_state,

            features=
            features
        )

        learning_state = (

            learning_engine
            .get_learning_state(
                process
            )
        )

        # --------------------------------
        # HEALING LOGGER
        # dashboard aligned
        # --------------------------------
        log_healing({

            "pid":
                pid,

            "stage":
                response_result[
                    "stage"
                ],

            "action_taken":
                response_result[
                    "action_taken"
                ],

            "status":
                response_result[
                    "status"
                ]
        })

        return {

            "response":
                response_result,

            "learning":
                learning_state
        }

    except Exception as e:

        print(
            f"Healing error "
            f"{pid}: {e}"
        )

        return {

            "response": {

                "pid":
                    pid,

                "stage":
                    "observe",

                "action_taken":
                    False,

                "status":
                    str(e)
            },

            "learning": {

                "reputation":
                    0.5,

                "trust_level":
                    "uncertain"
            }
        }




# ===================================================
# ENTRYPOINT
# ===================================================
if __name__ == "__main__":

    start_background_monitors()
    start_rapid_lineage_monitor()

    monitor_loop()


