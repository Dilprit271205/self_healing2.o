# monitor/lineage.py

import psutil
import time
from collections import (
    defaultdict,
    deque
)

entity_history = defaultdict(
    lambda: deque(maxlen=20)
)


class ProcessLineageTracker:
    """
    PPT + review aligned
    lineage tracker

    Supports:
    - entity grouping
    - process growth
    - worm propagation
    - tree explosion
    - temporal entity growth
    """

    def __init__(self):

        self.entities = defaultdict(
            list
        )

        self.pid_map = {}

    # -----------------------------------------
    # LIVE PROCESS COLLECTION
    # -----------------------------------------
    def get_processes(self):

        processes = []

        for proc in psutil.process_iter([

            "pid",
            "ppid",
            "name",
            "exe",
            "create_time",
            "cpu_percent",
            "memory_percent",
            "num_threads"

        ]):

            try:

                with proc.oneshot():

                    info = proc.info

                    if not info.get("exe"):
                        info["exe"] = (
                            info["name"]
                        )

                    processes.append(
                        info
                    )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):

                continue

        return processes

    # -----------------------------------------
    # BUILD PID MAP
    # -----------------------------------------
    def build_pid_map(
        self,
        processes
    ):

        self.pid_map = {
            p["pid"]: p
            for p in processes
        }

    # -----------------------------------------
    # ROOT PARENT
    # safe lineage traversal
    # cycle protected
    # -----------------------------------------
    def find_root_parent(
        self,
        pid
    ):

        visited = set()

        current = pid

        max_depth = 25
        depth = 0

        while current in self.pid_map:

            # -------------------------
            # CYCLE PROTECTION
            # -------------------------
            if current in visited:

                break

            visited.add(
                current
            )

            # -------------------------
            # DEPTH LIMIT
            # -------------------------
            if depth >= max_depth:

                break

            process = self.pid_map.get(
                current,
                {}
            )

            parent = process.get(
                "ppid",
                0
            )

            # -------------------------
            # ROOT FOUND
            # -------------------------
            if (
                parent == 0
                or
                parent
                not in self.pid_map
            ):

                return current

            # -------------------------
            # SELF LOOP
            # -------------------------
            if parent == current:

                break

            current = parent
            depth += 1

        # fallback
        return current

    # -----------------------------------------
    # ENTITY BUILDING
    # -----------------------------------------
    def build_entities(
        self,
        processes=None
    ):

        self.entities.clear()

        if processes is None:
            processes = (
                self.get_processes()
            )

        self.build_pid_map(
            processes
        )

        for proc in processes:

            root = (
                self.find_root_parent(
                    proc["pid"]
                )
            )

            self.entities[
                root
            ].append(proc)

        return dict(
            self.entities
        )

    # -----------------------------------------
    # ENTITY SUMMARY
    # -----------------------------------------
    def get_entity_summary(
        self,
        processes=None
    ):

        summaries = []

        entities = (
            self.build_entities(processes)
        )

        for (
            root_pid,
            members
        ) in entities.items():

            total_cpu = sum(
                p.get(
                    "cpu_percent",
                    0
                )
                or 0
                for p in members
            )

            total_memory = sum(
                p.get(
                    "memory_percent",
                    0
                )
                or 0
                for p in members
            )

            total_threads = sum(
                p.get(
                    "num_threads",
                    1
                )
                or 1
                for p in members
            )

            children_count = len(
                members
            )

            entity_history[
                root_pid
            ].append(
                children_count
            )

            growth_velocity = 0

            if (
                len(
                    entity_history[
                        root_pid
                    ]
                )
                >= 2
            ):

                growth_velocity = (

                    entity_history[
                        root_pid
                    ][-1]

                    -

                    entity_history[
                        root_pid
                    ][-2]
                )

            root_proc = (
                self.pid_map.get(
                    root_pid,
                    {}
                )
            )

            summaries.append({

                "entity_root":
                    root_pid,

                "name":
                    root_proc.get(
                        "name",
                        "unknown"
                    ),

                "children_count":
                    children_count,

                "growth_velocity":
                    growth_velocity,

                "total_cpu":
                    round(
                        total_cpu,
                        2
                    ),

                "total_memory":
                    round(
                        total_memory,
                        2
                    ),

                "total_threads":
                    total_threads,

                "members":
                    members
            })

        return summaries

    # -----------------------------------------
    # WORM-LIKE ENTITY DETECTION
    # -----------------------------------------
    def detect_large_entities(
        self,
        threshold=10
    ):

        suspicious = []

        entities = (
            self.get_entity_summary()
        )

        for entity in entities:

            if (
                entity[
                    "children_count"
                ]
                >= threshold
            ):

                suspicious.append(
                    entity
                )

        return suspicious