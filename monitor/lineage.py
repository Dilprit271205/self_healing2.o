# monitor/lineage.py

import psutil
import time
from collections import defaultdict


class ProcessLineageTracker:
    """
    Tracks parent-child process relationships and groups them
    into logical entities using root ancestor PID.
    """

    def __init__(self):
        self.entities = defaultdict(list)
        self.pid_map = {}

    # ---------------------------------------------------
    # Collect live processes
    # ---------------------------------------------------
    def get_processes(self):
        processes = []

        for proc in psutil.process_iter(
            ['pid', 'ppid', 'name', 'exe', 'create_time', 'cpu_percent', 'memory_percent']
        ):
            try:
                info = proc.info

                # fallback if exe unavailable
                if not info["exe"]:
                    info["exe"] = info["name"]

                processes.append(info)

            except (psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess):
                continue

        return processes

    # ---------------------------------------------------
    # Build quick PID lookup map
    # ---------------------------------------------------
    def build_pid_map(self, processes):
        self.pid_map = {proc["pid"]: proc for proc in processes}

    # ---------------------------------------------------
    # Find root ancestor of process tree
    # ---------------------------------------------------
    def find_root_parent(self, pid):
        visited = set()
        current = pid

        while current in self.pid_map:

            if current in visited:
                # circular safety
                return pid

            visited.add(current)

            parent = self.pid_map[current]["ppid"]

            if parent == 0 or parent not in self.pid_map:
                return current

            current = parent

        return pid

    # ---------------------------------------------------
    # Group all processes into entities
    # ---------------------------------------------------
    def build_entities(self):
        self.entities.clear()

        processes = self.get_processes()
        self.build_pid_map(processes)

        for proc in processes:
            root = self.find_root_parent(proc["pid"])
            self.entities[root].append(proc)

        return dict(self.entities)

    # ---------------------------------------------------
    # Get summarized entity information
    # ---------------------------------------------------
    def get_entity_summary(self):
        summaries = []

        entities = self.build_entities()

        for root_pid, members in entities.items():

            total_cpu = sum(p["cpu_percent"] or 0 for p in members)
            total_mem = sum(p["memory_percent"] or 0 for p in members)

            root_proc = self.pid_map.get(root_pid, {})
            root_name = root_proc.get("name", "unknown")

            summaries.append({
                "entity_root": root_pid,
                "name": root_name,
                "children_count": len(members),
                "total_cpu": round(total_cpu, 2),
                "total_memory": round(total_mem, 2),
                "members": members
            })

        return summaries

    # ---------------------------------------------------
    # Detect suspicious rapid growth entities
    # ---------------------------------------------------
    def detect_large_entities(self, threshold=10):
        suspicious = []

        summaries = self.get_entity_summary()

        for entity in summaries:
            if entity["children_count"] >= threshold:
                suspicious.append(entity)

        return suspicious


# -------------------------------------------------------
# Standalone Test Run
# -------------------------------------------------------
if __name__ == "__main__":

    tracker = ProcessLineageTracker()

    while True:
        print("\n========== ACTIVE ENTITIES ==========\n")

        entities = tracker.get_entity_summary()

        for entity in entities:
            print(
                f"Root PID: {entity['entity_root']} | "
                f"Name: {entity['name']} | "
                f"Processes: {entity['children_count']} | "
                f"CPU: {entity['total_cpu']}% | "
                f"MEM: {entity['total_memory']}%"
            )

        print("\nSuspicious Large Trees:\n")

        threats = tracker.detect_large_entities()

        for t in threats:
            print(
                f"[!] Entity {t['entity_root']} "
                f"({t['name']}) has {t['children_count']} processes"
            )

        time.sleep(3)