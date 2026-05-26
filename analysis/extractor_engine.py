# analysis/extractor_engine.py

import time
from collections import defaultdict, deque

from utils.file_event_mapper import (
    get_file_map
)

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
        connection_map
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

        # -----------------------------------------
        # ENTITY FEATURES
        # lineage.py integration
        # -----------------------------------------
        entity = entity_map.get(
            pid,
            []
        )

        process_tree_size = len(
            entity
        )

        # -----------------------------------------
        # FILE FEATURES
        # -----------------------------------------
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
        # -----------------------------------------
        connection_count = (
            connection_map.get(
                pid,
                0
            )
        )

        connection_history[
            pid
        ].append(
            connection_count
        )

        connection_velocity = 0

        if (
            len(
                connection_history[
                    pid
                ]
            ) >= 2
        ):

            connection_velocity = (
                connection_history[
                    pid
                ][-1]
                -
                connection_history[
                    pid
                ][-2]
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

            "f_process_trend":
                process_trend,

            "f_young_process":
                young_process,

            "f_syscall_freq":
                syscall_proxy,

            "f_connection_velocity":
                connection_velocity,

            # metadata
            "cmdline":
                cmdline
        }