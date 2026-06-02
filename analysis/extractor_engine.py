# analysis/extractor_engine.py

import time
from collections import Counter, defaultdict, deque

from utils.file_event_mapper import (
    get_file_map
)
from analysis.policy_engine import policy_engine

# ---------------------------------------------------
# HISTORY STORE
# fixes review:
# temporal intelligence missing
# ---------------------------------------------------
process_history = defaultdict(
    lambda: deque(maxlen=20)
)

thread_history = defaultdict(
    lambda: deque(maxlen=20)
)

connection_history = defaultdict(
    lambda: deque(maxlen=20)
)

spawn_history = defaultdict(
    lambda: deque(maxlen=20)
)


class ExtractorEngine:
    """
    PPT + review aligned extractor engine

    Responsibilities:
    1. Feature extraction
    2. Temporal intelligence
    3. Process growth detection
    4. Thread analysis
    5. Connection analysis
    6. Young process detection
    """

    def extract(
        self,
        process,
        entity_map,
        connection_map,
        file_map=None
    ):

        pid = process["pid"]

        # -----------------------------------------
        # BASIC FEATURES
        # -----------------------------------------
        cpu = process.get(
            "cpu",
            0
        )

        memory = process.get(
            "memory",
            0
        )

        threads = process.get(
            "threads",
            1
        )

        create_time = process.get(
            "create_time",
            time.time()
        )

        cmdline = process.get(
            "cmdline",
            ""
        )

        process_name = (
            str(process.get(
                "name",
                "unknown"
            )).lower()
        )

        # -----------------------------------------
        # ENTITY FEATURES
        # lineage.py integration
        # -----------------------------------------
        entity = entity_map.get(
            pid,
            []
        )

        process_tree_size = self._descendant_count(
            pid,
            entity
        )

        child_profile = self._child_profile(
            pid,
            entity
        )

        # -----------------------------------------
        # FILE FEATURES
        # -----------------------------------------
        if file_map is None:
            file_map = get_file_map()

        file_events = file_map.get(
            pid,
            0
        )

        # fallback because monitor
        # currently logs PID 0
        if file_events == 0:
            file_events = file_map.get(
                0,
                0
            )

        # -----------------------------------------
        # NETWORK FEATURES
        # fixes review 3.3
        # upgraded mapper compatible
        # -----------------------------------------
        network_info = (
            connection_map.get(
                pid,
                {}
            )
        )

        connection_count = (
            network_info.get(
                "connections",
                0
            )
        )

        connection_velocity = (
            network_info.get(
                "connection_velocity",
                0
            )
        )

        port_spread = (
            network_info.get(
                "port_spread",
                0
            )
        )

        remote_ips = (
            network_info.get(
                "remote_ips",
                0
            )
        )

        scanning_score = (
            network_info.get(
                "scanning_score",
                0
            )
        )

        scanning_detected = (
            network_info.get(
                "scanning_detected",
                False
            )
        )

        connection_history[
            pid
        ].append(
            connection_count
        )
        # -----------------------------------------
        # PROCESS SPAWN
        # fixes review 3.1
        # -----------------------------------------
        spawn_history[
            pid
        ].append(
            process_tree_size
        )

        process_growth = 0

        if (
            len(
                spawn_history[
                    pid
                ]
            ) >= 2
        ):

            process_growth = (
                spawn_history[
                    pid
                ][-1]
                -
                spawn_history[
                    pid
                ][-2]
            )

        # -----------------------------------------
        # THREAD ANALYSIS
        # fixes review 3.4
        # -----------------------------------------
        thread_history[
            pid
        ].append(
            threads
        )

        thread_velocity = 0

        if (
            len(
                thread_history[
                    pid
                ]
            ) >= 2
        ):

            thread_velocity = (
                thread_history[
                    pid
                ][-1]
                -
                thread_history[
                    pid
                ][-2]
            )

        # -----------------------------------------
        # PROCESS AGE
        # fixes young process issue
        # -----------------------------------------
        age_seconds = (
            time.time()
            -
            create_time
        )

        young_process = (
            1
            if age_seconds < 60
            else 0
        )

        # -----------------------------------------
        # SIMPLE SYSCALL PROXY
        # review-compatible
        # -----------------------------------------
        syscall_proxy = (
            cpu
            +
            threads
            +
            connection_count
            +
            file_events
        )

        # -----------------------------------------
        # TEMPORAL TREND
        # -----------------------------------------
        process_history[
            pid
        ].append(cpu)

        process_trend = 0

        if (
            len(
                process_history[
                    pid
                ]
            ) >= 2
        ):

            process_trend = (
                process_history[
                    pid
                ][-1]
                -
                process_history[
                    pid
                ][-2]
            )

        # -----------------------------------------
        # POLICY CONTEXT
        # -----------------------------------------
        category = policy_engine.infer_category(
            process
        )

        false_positive_suppression = (
            1
            if policy_engine.is_suppressed_category(category)
            else 0
        )

        safe_process = bool(
            false_positive_suppression
        )

        tree_weight = (
            0.3
            if process_growth == 0
            and young_process == 0
            else 1.2
        )

        # Runtime-only behavioral worm pressure. Category context can suppress
        # low-confidence disruption later, but it cannot erase behavior.
        worm_score = (
            (process_growth * 24)
            + (process_trend * 28)
            + (young_process * 20)
            + (syscall_proxy * 0.35)
            + (connection_velocity * 3.5)
            + (remote_ips * 2.5)
            + (scanning_score * 8.0)
            + (min(process_tree_size, 40) * tree_weight)
            + (child_profile["similarity_ratio"] * 22)
            + (child_profile["short_lived_ratio"] * 14)
        )

        # If scanning was explicitly detected, strongly boost worm score
        try:
            if scanning_detected:
                worm_score += 40
        except:
            pass

        worm_score = round(
            max(
                0.0,
                worm_score
            ),
            2
        )

        # -----------------------------------------
        # RETURN FEATURES
        # -----------------------------------------
        return {

            # core ppt features
            "cpu": cpu,
            "memory": memory,
            "connections":
                connection_count,
            "file_events":
                file_events,

            # review requested
            "f_thread":
                threads,

            "f_thread_velocity":
                thread_velocity,

            "f_proc_spawn":
                process_growth,

            "f_proc_tree":
                process_tree_size,

            "f_child_similarity":
                child_profile["similarity_ratio"],

            "f_repeated_child_count":
                child_profile["repeated_child_count"],

            "f_short_lived_child_ratio":
                child_profile["short_lived_ratio"],

            "f_process_trend":
                process_trend,

            "f_young_process":
                young_process,

            "age_seconds":
                round(
                    age_seconds,
                    2
                ),

            "f_syscall_freq":
                syscall_proxy,

            "f_connection_velocity":
                connection_velocity,
            
            "f_port_spread":
                port_spread,

            "f_remote_ips":
                remote_ips,

            "f_scanning_score":
                scanning_score,

            "f_scanning_detected":
                scanning_detected,

            # heuristics
            "worm_score":
                worm_score,

            "safe_process":
                safe_process,

            "process_category":
                category,

            "false_positive_suppression":
                false_positive_suppression,

            # metadata
            "cmdline":
                cmdline
        }

    def _descendant_count(
        self,
        pid,
        entity
    ):
        children_by_parent = defaultdict(list)

        for proc in entity:
            try:
                child_pid = proc.get(
                    "pid"
                )

                parent_pid = proc.get(
                    "ppid"
                )

                if child_pid is None or parent_pid is None:
                    continue

                children_by_parent[
                    parent_pid
                ].append(
                    child_pid
                )
            except Exception:
                continue

        count = 1
        stack = list(
            children_by_parent.get(
                pid,
                []
            )
        )
        seen = set()

        while stack:
            child_pid = stack.pop()

            if child_pid in seen:
                continue

            seen.add(
                child_pid
            )
            count += 1

            stack.extend(
                children_by_parent.get(
                    child_pid,
                    []
                )
            )

        return count

    def _child_profile(
        self,
        pid,
        entity
    ):
        now = time.time()
        direct_children = []

        for proc in entity:
            try:
                if proc.get("ppid") == pid:
                    direct_children.append(proc)
            except Exception:
                continue

        if not direct_children:
            return {
                "similarity_ratio": 0.0,
                "repeated_child_count": 0,
                "short_lived_ratio": 0.0
            }

        signatures = []
        short_lived = 0

        for child in direct_children:
            name = str(child.get("name", "") or "").lower()
            exe = str(child.get("exe", "") or "").lower()
            signatures.append(
                (name, exe)
            )

            try:
                age = now - float(child.get("create_time", now))
                if age < 12:
                    short_lived += 1
            except Exception:
                pass

        counts = Counter(signatures)
        repeated_child_count = max(counts.values()) if counts else 0
        similarity_ratio = repeated_child_count / max(len(direct_children), 1)
        short_lived_ratio = short_lived / max(len(direct_children), 1)

        return {
            "similarity_ratio": round(similarity_ratio, 3),
            "repeated_child_count": repeated_child_count,
            "short_lived_ratio": round(short_lived_ratio, 3)
        }
