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
            "0.5"
        )
    )
except Exception:
    MONITOR_INTERVAL = 0.5

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
file_behavior_memory = defaultdict(list)
resource_burst_window = defaultdict(list)
last_console_events = {}
recent_process_cache = {}
dead_process_first_seen = {}
DEAD_PROCESS_GRACE_SECONDS = 12


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
                "0.025"
            )
        )
    except Exception:
        interval = 0.025

    while not rapid_lineage_stop.is_set():
        try:
            processes = _lightweight_process_snapshot()
            update_recent_process_cache(
                processes
            )

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

                network_data = (
                    network_monitor
                    .get_network_data()
                )
                connection_map = (
                    map_connections(
                        network_data
                    )
                )
                emergency_behavior_preflight(
                    processes,
                    connection_map
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
                0.025
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


def _descendant_tree_profile(
    pid,
    children_by_parent
):
    stack = [
        (
            child,
            1
        )
        for child in children_by_parent.get(
            pid,
            []
        )
    ]
    seen = set()
    signatures = Counter()
    young_count = 0
    total = 0
    max_depth = 0
    branching_parents = 0

    while stack:
        child, depth = stack.pop()
        child_pid = child.get(
            "pid"
        )

        if child_pid in seen:
            continue

        seen.add(
            child_pid
        )
        total += 1
        max_depth = max(
            max_depth,
            depth
        )

        signatures[
            _process_signature(
                child
            )
        ] += 1

        if child.get(
            "age_seconds",
            9999
        ) <= 120:
            young_count += 1

        grandchildren = children_by_parent.get(
            child_pid,
            []
        )

        if len(grandchildren) >= 2:
            branching_parents += 1

        stack.extend(
            (
                grandchild,
                depth + 1
            )
            for grandchild in grandchildren
        )

    repeated_descendant_count = (
        max(
            signatures.values()
        )
        if signatures
        else 0
    )

    similarity = (
        repeated_descendant_count
        /
        max(
            total,
            1
        )
    )

    young_ratio = (
        young_count
        /
        max(
            total,
            1
        )
    )

    return {
        "descendants": total,
        "max_depth": max_depth,
        "branching_parents": branching_parents,
        "repeated_descendant_count": repeated_descendant_count,
        "descendant_similarity": round(
            similarity,
            3
        ),
        "descendant_young_ratio": round(
            young_ratio,
            3
        )
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


def _descendant_pids(
    pid,
    children_by_parent
):
    descendants = []
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
        descendants.append(
            child_pid
        )
        stack.extend(
            children_by_parent.get(
                child_pid,
                []
            )
        )

    return descendants


def is_runtime_protected_process(
    process
):
    try:
        engine = globals().get(
            "response_engine",
            None
        )

        pid = process.get(
            "pid"
        )

        if (
            pid in SYSTEM_SAFE_PIDS
            or (
                pid is not None
                and int(pid) <= 10
            )
        ):
            return True

        if engine is not None and engine.is_protected_process(
            pid,
            process.get(
                "name",
                ""
            ),
            process.get(
                "cmdline",
                ""
            ),
            process.get(
                "exe",
                ""
            ),
            process.get(
                "cwd",
                ""
            )
        ):
            return True

        category = policy_engine.infer_category(
            process
        )

        return (
            policy_engine.is_hard_protected_category(
                category
            )
            or
            policy_engine.is_critical_process_hint(
                process
            )
        )

    except Exception:
        return True


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
            is_runtime_protected_process(
                process
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

        tree_profile = _descendant_tree_profile(
            pid,
            children_by_parent
        )
        observed_family_pids = _descendant_pids(
            pid,
            children_by_parent
        )

        learned_preflight_classification = {
            "label": "forkbomb",
            "severity": "critical",
            "worm_score": 0.88,
            "confidence": 88,
            "signals": {
                "combined_risk": 0.88,
                "correlated_signal_count": 5,
                "catastrophic_behavior": False,
                "forkbomb_detected": True,
                "replication_detected": False,
                "fanout_detected": False,
                "correlated_signals": {
                    "rapid_child_spawning": profile["direct_children"] >= 1,
                    "large_or_growing_tree": descendants >= 1,
                    "repeated_similar_children": profile["repeated_child_count"] >= 1,
                    "short_lived_recursive_children": profile["young_child_ratio"] >= 0.40,
                    "process_storm_burst": profile["direct_children"] >= 1,
                    "deep_recursive_tree": tree_profile["max_depth"] >= 3
                }
            }
        }

        learned_repeat_storm = (
            profile["direct_children"] >= 1
            and profile["repeated_child_count"] >= 1
            and profile["child_similarity"] >= 0.90
            and profile["young_child_ratio"] >= 0.80
            and descendants >= 1
            and learning_engine.is_learned_terminate_pattern(
                {
                    **process,
                    "process_category": policy_engine.infer_category(
                        process
                    )
                },
                learned_preflight_classification
            )
        )

        catastrophic_storm = (
            profile["direct_children"] >= 8
            and profile["repeated_child_count"] >= 6
            and profile["child_similarity"] >= 0.65
            and profile["young_child_ratio"] >= 0.65
            and descendants >= 8
        )

        emergency_storm = (
            profile["direct_children"] >= 12
            and profile["repeated_child_count"] >= 8
            and profile["child_similarity"] >= 0.70
            and profile["young_child_ratio"] >= 0.50
            and descendants >= 12
        )

        deep_recursive_storm = (
            tree_profile["descendants"] >= 28
            and tree_profile["max_depth"] >= 4
            and tree_profile["branching_parents"] >= 4
            and tree_profile["repeated_descendant_count"] >= 18
            and tree_profile["descendant_similarity"] >= 0.70
            and tree_profile["descendant_young_ratio"] >= 0.60
        )

        if not (
            catastrophic_storm
            or emergency_storm
            or deep_recursive_storm
            or learned_repeat_storm
        ):
            continue

        features = {
            "f_proc_spawn": profile["direct_children"],
            "f_proc_tree": descendants,
            "f_process_trend": max(
                profile["direct_children"],
                tree_profile["branching_parents"]
            ),
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
            "f_child_similarity": max(
                profile["child_similarity"],
                tree_profile["descendant_similarity"]
            ),
            "f_short_lived_child_ratio": max(
                profile["young_child_ratio"],
                tree_profile["descendant_young_ratio"]
            ),
            "f_recursive_depth": tree_profile[
                "max_depth"
            ],
            "f_branching_parents": tree_profile[
                "branching_parents"
            ],
            "f_repeated_descendant_count": tree_profile[
                "repeated_descendant_count"
            ],
            "file_events": 0,
            "worm_score": 95,
            "emergency_preflight": True,
            "learned_pattern_fast_path": learned_repeat_storm
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
                    "process_storm_burst": True,
                    "deep_recursive_tree": deep_recursive_storm,
                    "learned_pattern_fast_path": learned_repeat_storm
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
            "force_terminate": True,
            "kill_family": True
        }

        rate_limited_print(
            f"process_storm_{pid}",
            f"[EMERGENCY] process storm pid={pid} "
            f"children={profile['direct_children']} "
            f"repeated={profile['repeated_child_count']} "
            f"learned={int(learned_repeat_storm)} "
            f"similarity={profile['child_similarity']} "
            f"young_ratio={profile['young_child_ratio']} "
            f"tree={descendants} "
            f"depth={tree_profile['max_depth']} "
            f"branching={tree_profile['branching_parents']}",
            interval=3
        )

        healing_result = execute_healing(
            pid=pid,
            process={
                **process,
                "observed_family_pids": observed_family_pids
            },
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
            "signals": classification.get(
                "signals",
                {}
            ),
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

        normalized_posix = directory.replace(
            "\\",
            "/"
        ).lower()

        if _is_ignored_file_activity_path(
            directory
        ):
            continue

        totals[
            directory
        ] += int(
            count
        )

    return totals


def _update_file_behavior_memory(
    now,
    directory_totals,
    duplicate_file_hash_count,
    event_type_counts
):
    try:
        memory_seconds = float(
            os.getenv(
                "SELF_HEALING_FILE_MEMORY_SECONDS",
                "180"
            )
        )
    except Exception:
        memory_seconds = 180.0

    for directory, count in directory_totals.items():
        file_behavior_memory[
            directory
        ].append({
            "timestamp": now,
            "count": int(
                count
            ),
            "duplicate": int(
                duplicate_file_hash_count
            ),
            "create": int(
                event_type_counts.get(
                    "create",
                    0
                )
                or 0
            ),
            "modify": int(
                event_type_counts.get(
                    "modify",
                    0
                )
                or 0
            ),
            "rename": int(
                event_type_counts.get(
                    "rename",
                    0
                )
                or 0
            )
        })

    for directory in list(
        file_behavior_memory.keys()
    ):
        file_behavior_memory[
            directory
        ] = [
            sample
            for sample in file_behavior_memory[
                directory
            ]
            if now - sample.get(
                "timestamp",
                0
            ) <= memory_seconds
        ]

        if not file_behavior_memory[
            directory
        ]:
            file_behavior_memory.pop(
                directory,
                None
            )

    return {
        directory: {
            "events": sum(
                int(
                    sample.get(
                        "count",
                        0
                    )
                )
                for sample in samples
            ),
            "duplicate": sum(
                int(
                    sample.get(
                        "duplicate",
                        0
                    )
                )
                for sample in samples
            ),
            "create": sum(
                int(
                    sample.get(
                        "create",
                        0
                    )
                )
                for sample in samples
            ),
            "modify": sum(
                int(
                    sample.get(
                        "modify",
                        0
                    )
                )
                for sample in samples
            ),
            "rename": sum(
                int(
                    sample.get(
                        "rename",
                        0
                    )
                )
                for sample in samples
            )
        }
        for directory, samples in file_behavior_memory.items()
    }


def _is_ignored_file_activity_path(
    path
):
    normalized_posix = str(
        path
        or ""
    ).replace(
        "\\",
        "/"
    ).lower()

    return (
        "/logs" in normalized_posix
        or "/.git" in normalized_posix
        or "__pycache__" in normalized_posix
        or "/.pytest_cache" in normalized_posix
        or "/analysis/models" in normalized_posix
        or normalized_posix.endswith("/analysis/models")
        or "/.venv" in normalized_posix
        or normalized_posix.endswith("/.venv")
        or "/venv" in normalized_posix
        or normalized_posix.endswith("/venv")
        or "/env" in normalized_posix
        or normalized_posix.endswith("/env")
    )


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


PERSISTENCE_PATH_HINTS = (
    "startup",
    "start menu/programs/startup",
    "autorun",
    "autorun_registry",
    "runonce",
    "systemd/user",
    ".config/autostart",
    "autostart",
    "launchagents",
    "launch_agents",
    "launchdaemons",
    "launch_daemons",
    "cron",
    "crontab",
    "scheduled tasks",
    "scheduled_tasks",
    "services",
    "service",
    "relaunch",
    "fake_persistence"
)

SENSITIVE_PATH_HINTS = (
    ".env",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "secrets",
    "token",
    "tokens",
    "api_key",
    "apikey",
    "private_key",
    "id_rsa",
    "id_dsa",
    ".ssh",
    ".aws",
    ".azure",
    ".kube",
    "keychain",
    "wallet"
)


def _path_contains_any(
    path,
    hints
):
    normalized = str(
        path
        or ""
    ).replace(
        "\\",
        "/"
    ).lower()

    return any(
        hint in normalized
        for hint in hints
    )


def _file_behavior_evidence_for_process(
    process,
    file_map=None
):
    file_map = file_map or {}
    path_events = file_map.get(
        "__paths__",
        {}
    )

    try:
        pid = process.get(
            "pid"
        )
        direct_events = int(
            file_map.get(
                pid,
                0
            )
            or 0
        )
    except Exception:
        direct_events = 0

    cwd = process.get(
        "cwd",
        ""
    )
    cwd_abs = ""

    if cwd:
        try:
            cwd_abs = os.path.abspath(
                cwd
            )
        except Exception:
            cwd_abs = ""

    total_events = direct_events
    persistence_events = 0
    sensitive_events = 0

    for path, count in path_events.items():
        try:
            event_count = int(
                count
                or 0
            )
        except Exception:
            event_count = 0

        if event_count <= 0:
            continue

        try:
            path_abs = os.path.abspath(
                path
            )
        except Exception:
            path_abs = str(
                path
            )

        if _is_ignored_file_activity_path(
            path_abs
        ):
            continue

        belongs_to_process = (
            bool(cwd_abs)
            and not _is_broad_file_root(
                cwd_abs
            )
            and (
                _path_is_under(
                    path_abs,
                    cwd_abs
                )
                or _path_is_under(
                    cwd_abs,
                    path_abs
                )
            )
        )

        if belongs_to_process:
            total_events += event_count

        if belongs_to_process or direct_events:
            if _path_contains_any(
                path_abs,
                PERSISTENCE_PATH_HINTS
            ):
                persistence_events += event_count

            if _path_contains_any(
                path_abs,
                SENSITIVE_PATH_HINTS
            ):
                sensitive_events += event_count

    return {
        "file_events": total_events,
        "persistence_events": persistence_events,
        "sensitive_file_events": sensitive_events,
        "f_persistence_artifact": 1 if persistence_events else 0,
        "f_sensitive_file_access": 1 if sensitive_events else 0
    }


def _behavior_containment_enabled():
    return os.getenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true"
    ).lower() in (
        "1",
        "true",
        "yes",
        "y"
    )


def _is_safe_to_behavior_terminate(
    process
):
    if is_runtime_protected_process(
        process
    ):
        return False

    category = policy_engine.infer_category(
        process
    )

    if policy_engine.is_suppressed_category(
        category
    ):
        return False

    return True


def update_recent_process_cache(
    processes
):
    now = time.time()

    for process in processes:
        pid = process.get(
            "pid"
        )

        if pid is None:
            continue

        cached = dict(
            process
        )
        cached[
            "_last_seen"
        ] = now
        cached[
            "_exited"
        ] = False

        recent_process_cache[
            pid
        ] = cached
        dead_process_first_seen.pop(
            pid,
            None
        )


def _candidate_processes_with_recent(
    processes
):
    now = time.time()
    live_pids = {
        process.get(
            "pid"
        )
        for process in processes
    }
    candidates = [
        dict(
            process
        )
        for process in processes
    ]

    for pid, process in list(
        recent_process_cache.items()
    ):
        if pid in live_pids:
            continue

        last_seen = process.get(
            "_last_seen",
            0
        )

        if now - last_seen > DEAD_PROCESS_GRACE_SECONDS:
            continue

        candidate = dict(
            process
        )
        candidate[
            "_exited"
        ] = True
        candidate[
            "age_seconds"
        ] = min(
            candidate.get(
                "age_seconds",
                9999
            ),
            240
        )
        candidates.append(
            candidate
        )

    return candidates


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
    event_type_counts = (
        file_map
        or {}
    ).get(
        "__event_types__",
        {}
    )
    duplicate_file_hash_count = int(
        (
            file_map
            or {}
        ).get(
            "__duplicate_hash_count__",
            0
        )
        or 0
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

    memory_summary = _update_file_behavior_memory(
        now,
        directory_totals,
        duplicate_file_hash_count,
        event_type_counts
    )

    memory_totals = {
        directory: int(
            summary.get(
                "events",
                0
            )
        )
        for directory, summary in memory_summary.items()
    }

    combined_totals = dict(
        rolling_totals
    )

    for directory, count in memory_totals.items():
        combined_totals[
            directory
        ] = max(
            combined_totals.get(
                directory,
                0
            ),
            count
        )

    total_events = sum(
        rolling_totals.values()
    )
    memory_total_events = sum(
        memory_totals.values()
    )
    memory_fanout = sum(
        1
        for count in memory_totals.values()
        if count >= 2
    )
    duplicate_memory_count = sum(
        int(
            summary.get(
                "duplicate",
                0
            )
        )
        for summary in memory_summary.values()
    )

    duplicate_replication_burst = (
        duplicate_file_hash_count >= 8
        or duplicate_memory_count >= 8
    )
    rename_event_count = int(
        event_type_counts.get(
            "rename",
            0
        )
        or 0
    )
    rename_memory_count = sum(
        int(
            summary.get(
                "rename",
                0
            )
        )
        for summary in memory_summary.values()
    )
    suspicious_rename_burst = (
        rename_event_count >= 6
        or rename_memory_count >= 6
    )
    low_slow_replication_memory = (
        memory_total_events >= 30
        and memory_fanout >= 8
    )

    if (
        total_events < 25
        and not duplicate_replication_burst
        and not suspicious_rename_burst
        and not low_slow_replication_memory
    ):
        return set()

    active_directories = [
        directory
        for directory, count in combined_totals.items()
        if (
            count >= 20
            or (
                duplicate_replication_burst
                and count >= 2
            )
            or (
                suspicious_rename_burst
                and count >= 2
            )
            or (
                low_slow_replication_memory
                and count >= 2
            )
        )
    ]

    if not active_directories:
        return set()

    handled_pids = set()
    candidate_seen = False

    for process in sorted(
        _candidate_processes_with_recent(
            processes
        ),
        key=lambda p: p.get(
            "age_seconds",
            9999
        )
    ):
        pid = process.get(
            "pid"
        )

        if is_runtime_protected_process(
            process
        ):
            continue

        if process.get(
            "age_seconds",
            9999
        ) > 240:
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
            for directory, count in combined_totals.items():
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

        if (
            matched_events < 20
            and not duplicate_replication_burst
            and not suspicious_rename_burst
        ):
            continue

        candidate_seen = True
        matched_directories = [
            directory
            for directory, count in combined_totals.items()
            if (
                (
                    count >= 20
                    or (
                        low_slow_replication_memory
                        and count >= 2
                    )
                    or (
                        suspicious_rename_burst
                        and count >= 2
                    )
                )
                and (
                    _path_is_under(
                        directory,
                        cwd_abs
                    )
                    or _path_is_under(
                        cwd_abs,
                        directory
                    )
                )
            )
        ]
        subtree_fanout = len(
            matched_directories
        )
        low_slow_file_replication = (
            low_slow_replication_memory
            and matched_events >= 30
            and subtree_fanout >= 8
        )
        strong_file_replication = (
            matched_events >= 25
            or duplicate_replication_burst
            or suspicious_rename_burst
            or low_slow_file_replication
        )
        file_containment_enabled = os.getenv(
            "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
            "false"
        ).lower() in (
            "1",
            "true",
            "yes",
            "y"
        )
        behavior_file_containment = (
            _behavior_containment_enabled()
            and (
                matched_events >= 60
                or duplicate_replication_burst
                or suspicious_rename_burst
                or low_slow_file_replication
            )
            and (
                subtree_fanout >= 2
                or matched_events >= 45
                or duplicate_replication_burst
                or suspicious_rename_burst
                or low_slow_file_replication
            )
            and not process.get(
                "_exited",
                False
            )
        )
        confirmed_file_owner = (
            (
                matched_events >= 25
                or duplicate_replication_burst
                or suspicious_rename_burst
                or low_slow_file_replication
            )
            and not _is_broad_file_root(
                cwd_abs
            )
        )

        stage = "observe"

        if (
            not file_containment_enabled
            and not behavior_file_containment
            and not strong_file_replication
        ):
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
                    "containment_enabled": False,
                    "file_creation_rate": event_type_counts.get(
                        "create",
                        0
                    ),
                    "file_modification_rate": event_type_counts.get(
                        "modify",
                        0
                    ),
                    "file_rename_rate": event_type_counts.get(
                        "rename",
                        0
                    ),
                    "duplicate_file_hash_count": duplicate_file_hash_count,
                    "post_event_attribution": bool(
                        process.get(
                            "_exited",
                            False
                        )
                    )
                }
            })

            handled_pids.add(
                pid
            )
            continue

        if behavior_file_containment:
            stage = "terminate"
        elif file_containment_enabled and confirmed_file_owner:
            stage = "quarantine"

        features = {
            "f_proc_spawn": 0,
            "f_proc_tree": 1,
            "f_process_trend": 0,
            "f_young_process": 1,
            "file_events": matched_events,
            "file_creation_rate": event_type_counts.get(
                "create",
                0
            ),
            "file_modification_rate": event_type_counts.get(
                "modify",
                0
            ),
            "file_rename_rate": event_type_counts.get(
                "rename",
                0
            ),
            "duplicate_file_hash_count": duplicate_file_hash_count,
            "duplicate_file_hash_memory": duplicate_memory_count,
            "f_mass_file_modification": (
                1
                if (
                    matched_events >= 45
                    and not suspicious_rename_burst
                )
                else 0
            ),
            "f_suspicious_rename": (
                1
                if suspicious_rename_burst
                else 0
            ),
            "rename_events": max(
                rename_event_count,
                rename_memory_count
            ),
            "worm_score": 90,
            "emergency_preflight": True,
            "file_replication_preflight": True,
            "behavior_file_containment": behavior_file_containment,
            "subtree_fanout": subtree_fanout,
            "low_slow_file_replication": low_slow_file_replication,
            "file_memory_events": memory_total_events,
            "file_memory_fanout": memory_fanout,
            "post_event_attribution": bool(
                process.get(
                    "_exited",
                    False
                )
            )
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
                    "extreme_file_velocity": (
                        matched_events >= 60
                        or duplicate_replication_burst
                    ),
                    "mass_file_modification": matched_events >= 45,
                    "suspicious_rename": suspicious_rename_burst,
                    "duplicate_payload_replication": duplicate_replication_burst,
                    "low_slow_file_replication": low_slow_file_replication,
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
            "termination_ready": behavior_file_containment,
            "force_terminate": behavior_file_containment,
            "confirmed_behavior": (
                (
                    file_containment_enabled
                    or behavior_file_containment
                )
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
            "signals": classification.get(
                "signals",
                {}
            ),
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
        ) or (
            strong_file_replication
            and classification.get(
                "label"
            ) == "worm"
        ):
            handled_pids.add(
                pid
            )

        if response_result.get(
            "action_taken",
            False
        ):
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


def emergency_behavior_preflight(
    processes,
    connection_map=None,
    file_map=None
):
    if not _behavior_containment_enabled():
        return set()

    connection_map = connection_map or {}
    file_map = file_map or {}
    handled_pids = set()

    for process in _candidate_processes_with_recent(
        processes
    ):
        if process.get(
            "_exited",
            False
        ):
            continue

        if not _is_safe_to_behavior_terminate(
            process
        ):
            continue

        pid = process.get(
            "pid"
        )
        cmdline = str(
            process.get(
                "cmdline",
                ""
            )
        ).lower()
        cpu_usage = float(
            process.get(
                "cpu",
                0
            )
            or 0
        )
        memory_usage = float(
            process.get(
                "memory",
                0
            )
            or 0
        )
        thread_count = int(
            process.get(
                "threads",
                process.get(
                    "num_threads",
                    0
                )
            )
            or 0
        )
        category = policy_engine.infer_category(
            process
        )

        network_info = connection_map.get(
            pid,
            {}
        )
        loopback_connections = int(
            network_info.get(
                "loopback_connections",
                0
            )
            or 0
        )
        connection_velocity = int(
            network_info.get(
                "connection_velocity",
                0
            )
            or 0
        )
        connection_rate = float(
            network_info.get(
                "connection_rate",
                0
            )
            or 0
        )
        loopback_connection_rate = float(
            network_info.get(
                "loopback_connection_rate",
                0
            )
            or 0
        )
        network_event_count = int(
            network_info.get(
                "network_event_count",
                0
            )
            or 0
        )
        loopback_event_count = int(
            network_info.get(
                "loopback_event_count",
                0
            )
            or 0
        )
        active_connections = int(
            network_info.get(
                "connections",
                0
            )
            or 0
        )
        file_evidence = _file_behavior_evidence_for_process(
            process,
            file_map
        )

        beacon_like = (
            (
                loopback_event_count >= 8
                and loopback_connection_rate >= 0.65
            )
            or (
                loopback_connections >= 4
                and loopback_connection_rate >= 0.5
            )
            or connection_velocity >= 12
            or connection_rate >= 8
            or active_connections >= 30
        )

        persistence_like = bool(
            process.get(
                "f_persistence_artifact",
                0
            )
            or process.get(
                "persistence_events",
                0
            )
            or file_evidence.get(
                "f_persistence_artifact",
                0
            )
            or file_evidence.get(
                "persistence_events",
                0
            )
        )

        sensitive_access_like = bool(
            process.get(
                "f_sensitive_file_access",
                0
            )
            or process.get(
                "sensitive_file_events",
                0
            )
            or file_evidence.get(
                "f_sensitive_file_access",
                0
            )
            or file_evidence.get(
                "sensitive_file_events",
                0
            )
        )
        thread_storm_like = (
            thread_count >= 80
        )
        cpu_exhaustion_like = (
            cpu_usage >= 85
        )
        memory_spike_like = (
            memory_usage >= 35
            or int(
                process.get(
                    "memory_rss",
                    0
                )
                or 0
            ) >= 750 * 1024 * 1024
        )
        file_replication_like = (
            file_evidence.get(
                "file_events",
                0
            ) >= 5
        )
        behavior_signal_count = sum(
            1
            for active in (
                beacon_like,
                persistence_like,
                sensitive_access_like,
                file_replication_like,
                thread_storm_like,
                cpu_exhaustion_like,
                memory_spike_like
            )
            if active
        )
        learned_behavior_classification = {
            "label": "worm",
            "severity": "critical",
            "worm_score": 0.86,
            "confidence": 86,
            "signals": {
                "combined_risk": 0.86,
                "correlated_signal_count": behavior_signal_count,
                "catastrophic_behavior": False,
                "forkbomb_detected": False,
                "replication_detected": file_replication_like,
                "fanout_detected": beacon_like,
                "artifact_abuse_detected": (
                    persistence_like
                    or sensitive_access_like
                ),
                "thread_storm_detected": thread_storm_like,
                "worm_like_behavior": (
                    file_replication_like
                    and (
                        cpu_exhaustion_like
                        or thread_count >= 20
                        or beacon_like
                    )
                ),
                "correlated_signals": {
                    "file_replication": file_replication_like,
                    "localhost_beaconing": beacon_like,
                    "network_fanout": beacon_like,
                    "thread_explosion": thread_storm_like,
                    "cpu_memory_escalation": (
                        cpu_exhaustion_like
                        or memory_spike_like
                    ),
                    "resource_pressure": (
                        thread_storm_like
                        or cpu_exhaustion_like
                        or memory_spike_like
                    ),
                    "behavior_preflight": True
                }
            }
        }
        learned_behavior_pattern = (
            behavior_signal_count >= 2
            and learning_engine.is_learned_terminate_pattern(
                {
                    **process,
                    "process_category": category
                },
                learned_behavior_classification
            )
        )

        if not (
            (
                behavior_signal_count >= 2
                and (
                    file_replication_like
                    or beacon_like
                    or persistence_like
                    or sensitive_access_like
                    or thread_storm_like
                    or learned_behavior_pattern
                )
            )
            or persistence_like
            or sensitive_access_like
            or thread_storm_like
            or (
                file_replication_like
                and (
                    thread_count >= 20
                    or cpu_exhaustion_like
                    or beacon_like
                    or learned_behavior_pattern
                )
            )
            or (
                beacon_like
                and (
                    active_connections >= 10
                    or loopback_event_count >= 8
                    or network_event_count >= 12
                )
            )
            or (
                cpu_exhaustion_like
                and (
                    thread_count >= 45
                    or file_replication_like
                    or memory_spike_like
                    or active_connections >= 10
                    or learned_behavior_pattern
                )
            )
            or (
                memory_spike_like
                and (
                    thread_count >= 45
                    or file_replication_like
                    or cpu_exhaustion_like
                    or active_connections >= 10
                    or learned_behavior_pattern
                )
            )
        ):
            continue

        if beacon_like:
            behavior = "localhost_beaconing"
        elif persistence_like:
            behavior = "persistence_artifact"
        elif sensitive_access_like:
            behavior = "sensitive_file_access"
        elif file_replication_like:
            behavior = "file_replication_with_resource_pressure"
        elif thread_storm_like:
            behavior = "thread_storm"
        elif cpu_exhaustion_like:
            behavior = "cpu_exhaustion"
        else:
            behavior = "memory_spike"

        resource_like = (
            thread_storm_like
            or cpu_exhaustion_like
            or memory_spike_like
        )
        features = {
            "f_proc_spawn": 0,
            "f_proc_tree": 1,
            "f_process_trend": 0,
            "f_young_process": 1,
            "cpu": cpu_usage,
            "memory": memory_usage,
            "f_thread": thread_count,
            "file_events": 3 if (
                persistence_like
                or sensitive_access_like
            ) else file_evidence.get(
                "file_events",
                0
            ),
            "f_connection_velocity": connection_velocity,
            "f_loopback_connections": loopback_connections,
            "f_connection_rate": connection_rate,
            "f_loopback_connection_rate":
                loopback_connection_rate,
            "f_network_event_count": network_event_count,
            "f_loopback_event_count": loopback_event_count,
            "f_localhost_beaconing": 1 if beacon_like else 0,
            "f_persistence_artifact": 1 if persistence_like else 0,
            "f_sensitive_file_access": 1 if sensitive_access_like else 0,
            "f_file_replication": 1 if file_replication_like else 0,
            "persistence_events": file_evidence.get(
                "persistence_events",
                0
            ),
            "sensitive_file_events": file_evidence.get(
                "sensitive_file_events",
                0
            ),
            "f_thread_storm": 1 if thread_storm_like else 0,
            "f_cpu_exhaustion": 1 if cpu_exhaustion_like else 0,
            "f_memory_spike": 1 if memory_spike_like else 0,
            "worm_score": 92,
            "emergency_preflight": True,
            "behavior_preflight": True,
            "behavior": behavior,
            "learned_behavior_pattern": learned_behavior_pattern
        }

        classification = {
            "label": "worm",
            "severity": "critical",
            "worm_score": 0.94,
            "confidence": 94,
            "signals": {
                "combined_risk": 0.92,
                "correlated_signal_count": 4,
                "catastrophic_behavior": False,
                "forkbomb_detected": False,
                "replication_detected": file_replication_like,
                "fanout_detected": beacon_like,
                "artifact_abuse_detected": (
                    persistence_like
                    or sensitive_access_like
                ),
                "thread_storm_detected": thread_storm_like,
                "correlated_signals": {
                    "file_replication": file_replication_like,
                    "localhost_beaconing": beacon_like,
                    "network_fanout": beacon_like,
                    "persistence_artifact": persistence_like,
                    "sensitive_file_access": sensitive_access_like,
                    "thread_explosion": thread_storm_like,
                    "cpu_memory_escalation": (
                        cpu_exhaustion_like
                        or memory_spike_like
                    ),
                    "resource_pressure": resource_like,
                    "baseline_anomaly": True,
                    "behavior_preflight": True,
                    "learned_behavior_pattern": learned_behavior_pattern
                }
            }
        }

        trust_state = {
            "dynamic_trust": 0.30,
            "final_trust": 0.30,
            "static_trust": 0.78
        }

        persistence_state = {
            "persistent": True,
            "confidence": 0.94,
            "stage": "terminate",
            "avg_worm_score": 0.94,
            "avg_dynamic_trust": 0.30,
            "avg_final_trust": 0.30,
            "avg_confidence": 0.94,
            "avg_combined_risk": 0.92,
            "avg_correlated_signals": 4,
            "termination_ready": True,
            "force_terminate": True,
            "confirmed_behavior": True
        }

        rate_limited_print(
            f"behavior_preflight_{pid}",
            f"[EMERGENCY] behavior pid={pid} "
            f"type={behavior} stage=terminate "
            f"loopback={loopback_connections} "
            f"loopback_rate={loopback_connection_rate} "
            f"connections={active_connections}",
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
            "signals": classification.get(
                "signals",
                {}
            ),
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
            is_runtime_protected_process(
                process
            )
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
            "signals": classification.get(
                "signals",
                {}
            ),
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
            update_recent_process_cache(
                processes
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

            file_handled = emergency_file_activity_preflight(
                processes,
                file_map
            )
            emergency_handled.update(
                file_handled
            )

            behavior_handled = emergency_behavior_preflight(
                processes,
                connection_map,
                file_map
            )
            emergency_handled.update(
                behavior_handled
            )

            resource_handled = emergency_resource_preflight(
                processes
            )
            emergency_handled.update(
                resource_handled
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

                    protected_or_suppressed = (
                        response_engine.is_protected_process(
                            pid,
                            process.get(
                                "name",
                                ""
                            ),
                            process.get(
                                "cmdline",
                                ""
                            ),
                            process.get(
                                "exe",
                                ""
                            ),
                            process.get(
                                "cwd",
                                ""
                            )
                        )
                        or policy_engine.is_suppressed_category(
                            policy_engine.infer_category(
                                process
                            )
                        )
                    )

                    if (
                        not protected_or_suppressed
                        and (
                            classification.get(
                                "label"
                            )
                            !=
                            "normal"
                            or
                            low_trust
                        )
                    ):

                        rate_limited_print(
                            f"flagged_{pid}",
                            f"[FLAGGED] pid={pid} "
                            f"name={process_name} "
                            f"label={classification.get('label')} "
                            f"severity={classification.get('severity')} "
                            f"worm_score={classification.get('worm_score')} "
                            f"final_trust={trust_state.get('final_trust')} "
                            f"dynamic_trust={trust_state.get('dynamic_trust')} "
                            f"static_trust={trust_state.get('static_trust')}",
                            interval=10
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

                        "signals":
                            classification.get(
                                "signals",
                                {}
                            ),

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
    now = time.time()

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

            rate_limited_print(
                "cleanup_dead_pids",

                f"[CLEANUP] Cleaned "
                f"{len(dead)} "
                f"dead processes",
                interval=8
            )

            for pid in dead:
                dead_process_first_seen.setdefault(
                    pid,
                    now
                )

                cached = recent_process_cache.get(
                    pid
                )

                if cached is not None:
                    cached[
                        "_exited"
                    ] = True
                    cached.setdefault(
                        "_last_seen",
                        now
                    )

                if (
                    now
                    -
                    dead_process_first_seen.get(
                        pid,
                        now
                    )
                    <
                    DEAD_PROCESS_GRACE_SECONDS
                ):
                    continue

                remove_trust(pid)
                process_history.pop(pid, None)
                thread_history.pop(pid, None)
                connection_history.pop(pid, None)
                spawn_history.pop(pid, None)
                feature_history.pop(pid, None)
                persistence_engine.history.pop(pid, None)
                response_engine.response_history.pop(pid, None)
                entity_history.pop(pid, None)
                recent_process_cache.pop(pid, None)
                dead_process_first_seen.pop(pid, None)

        for pid, process in list(
            recent_process_cache.items()
        ):
            last_seen = process.get(
                "_last_seen",
                now
            )

            if (
                pid not in current_pids
                and now - last_seen > DEAD_PROCESS_GRACE_SECONDS
            ):
                recent_process_cache.pop(
                    pid,
                    None
                )
                dead_process_first_seen.pop(
                    pid,
                    None
                )

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

        if (
            learned_stage == "terminate"
            and not force_stage
        ):
            persistence_state[
                "termination_ready"
            ] = True
            persistence_state[
                "force_terminate"
            ] = True
            persistence_state[
                "kill_family"
            ] = True

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


