import time
import threading
import psutil
import getpass

from monitor.process_monitor import get_process_data
from monitor.network_monitor import NetworkMonitor
from monitor.file_monitor import start_file_monitor
from monitor.lineage import ProcessLineageTracker

from utils.connection_mapper import map_connections
from utils.file_event_mapper import get_file_map

from analysis.feature_extractor import extract_features

from analysis.anomaly.cpu_anomaly import cpu_anomaly
from analysis.anomaly.file_anomaly import file_anomaly
from analysis.anomaly.network_anomaly import network_anomaly

from analysis.trust.trust_vector import (
    initialize_trust,
    get_trust,
    trust_db
)

from analysis.trust.trust_update import update_trust

from analysis.decision.decision_engine import decide_action

from logger.logger import log_process, log_entity


# =====================================================
# SAFE CONFIG
# =====================================================
CURRENT_USER = getpass.getuser()

SAFE_SYSTEM = [
    "systemd", "kthreadd", "kworker",
    "plasmashell", "gnome-shell",
    "xorg", "sddm", "gdm",
    "dbus-daemon", "networkmanager",
    "pipewire", "pulseaudio",
    "chrome", "firefox", "code",
    "kdeconnectd", "streamlit"
]

TARGET_FILES = [
    "worm_sim.py",
    "stress.py",
    "Test_Worm.py"
]


# =====================================================
# TERMINATE TREE
# =====================================================
def terminate_process_tree(pid):
    try:
        parent = psutil.Process(pid)

        children = parent.children(recursive=True)

        for child in children:
            try:
                child.kill()
            except:
                pass

        for child in children:
            try:
                child.wait(timeout=1)
            except:
                pass

        try:
            parent.kill()
        except:
            pass

        return True

    except:
        return False


# =====================================================
# SAFE DEFENCE POLICY
# =====================================================
def should_kill_process(pid, proc_name, cmdline, worm_score):

    # Never touch kernel/system pids
    if pid in [0, 1, 2]:
        return False

    # Never kill trusted apps
    explicit = any(
        x.lower() in cmdline.lower()
        for x in TARGET_FILES
    )

    for safe in SAFE_SYSTEM:

        # Allow test worms to bypass safe list
        if safe in proc_name and not explicit:
            return False

    # Must belong to current user
    try:
        proc = psutil.Process(pid)

        owner = proc.username()

        if CURRENT_USER not in owner:
            return False

        # ==================================
        # NEW: detect child explosion
        # ==================================
        child_count = len(
            proc.children(recursive=True)
        )

        # Only suspicious if explicitly a test worm
        explicit = any(
            x.lower() in cmdline.lower()
            for x in TARGET_FILES
        )

        if explicit and child_count >= 15:
            print(
                f"[SELF-HEAL] "
                f"Fork-bomb behavior "
                f"detected ({child_count} children)"
            )
            return True

    except:
        return False

    # Must explicitly be simulator file
    explicit = any(
        x in cmdline
        for x in TARGET_FILES
    )

    if not explicit:
        return False

    # Must actually look malicious
    if worm_score < 8:
        return False
    
    if child_count < 15:
        return False

    return True


# =====================================================
# IGNORE BACKGROUND / IDLE PROCESSES
# prevents trust collapse on sleeping daemons
# =====================================================
def is_idle_process(process):
    cpu = process.get("cpu", 0)
    mem = process.get("memory", 0)

    if cpu <= 0.0 and mem < 0.08:
        return True

    return False


# =====================================================
# MAIN LOOP
# =====================================================
def monitor_loop():

    tracker = ProcessLineageTracker()
    network_monitor = NetworkMonitor()

    while True:

        try:
            processes = get_process_data()
            network = network_monitor.get_network_data()

            process_map = {p["pid"]: p for p in processes}
            entities = tracker.build_entities()

            active_pids = set(process_map.keys())

            # clean dead trust states
            for pid in list(trust_db.keys()):
                if pid not in active_pids:
                    del trust_db[pid]

            connection_map = map_connections(network)
            file_map = get_file_map()

            for root_pid, members in entities.items():

                member_pids = [m["pid"] for m in members]

                log_entity({
                    "entity_root": root_pid,
                    "children_count": len(members),
                    "member_pids": member_pids
                })

                for member in members:

                    pid = member["pid"]

                    if pid not in process_map:
                        continue

                    process = process_map[pid]

                    process["children_count"] = len(members)
                    process["threads"] = len(members)

                    initialize_trust(pid)

                    features = extract_features(
                        process,
                        connection_map,
                        file_map
                    )

                    current_trust = get_trust(pid)

                    # -------------------------------------
                    # Skip idle daemons (heal naturally)
                    # -------------------------------------
                    if is_idle_process(process):

                        actions = {
                            "level": "normal",
                            "action": "monitor",
                            "message": "Idle process"
                        }

                        log_process({
                            **features,
                            "pid": pid,
                            "name": process["name"],
                            "entity_root": root_pid,
                            "children_count": len(members),
                            "anomalies": {},
                            "trust": current_trust,
                            "actions": actions
                        })

                        continue

                    # -------------------------------------
                    # REAL ANOMALIES
                    # -------------------------------------
                    anomalies = {
                        "cpu": cpu_anomaly(features["cpu"]),
                        "file": file_anomaly(features["file_events"]),
                        "net": network_anomaly(features["connections"]),
                        "spawn": 1 if features["f_proc_spawn"] > 3 else 0,
                        "tree": 1 if features["f_proc_tree"] > 20 else 0,
                        "trend": 1 if features["f_process_trend"] > 0 else 0
                    }

                    updated_trust = update_trust(
                        pid=pid,
                        current_trust=current_trust,
                        anomalies=anomalies,
                        static_score=features["static_trust"]
                    )

                    proc_name = str(process["name"]).lower()
                    cmdline = str(features.get("cmdline", "")).lower()
                    worm_score = float(features.get("worm_score", 0))

                    # -------------------------------------
                    # AUTO RESPONSE
                    # -------------------------------------
                    if should_kill_process(
                        pid,
                        proc_name,
                        cmdline,
                        worm_score
                    ):

                        killed = terminate_process_tree(pid)

                        print(
                            f"[SELF-HEAL] "
                            f"Killed PID {pid} "
                            f"({proc_name}) -> {killed}"
                        )

                        updated_trust["final_trust"] = 0.0

                        actions = {
                            "level": "critical",
                            "action": "terminate_process_tree",
                            "message": "Simulator worm neutralized"
                        }

                        log_process({
                            **features,
                            "pid": pid,
                            "name": process["name"],
                            "entity_root": root_pid,
                            "children_count": len(members),
                            "anomalies": anomalies,
                            "trust": updated_trust,
                            "actions": actions,
                            "auto_defence": (
                                "SUCCESS"
                                if killed else
                                "FAILED"
                            )
                        })

                        continue

                    # -------------------------------------
                    # NORMAL DECISION
                    # -------------------------------------
                    actions = decide_action(updated_trust)

                    log_process({
                        **features,
                        "pid": pid,
                        "name": process["name"],
                        "entity_root": root_pid,
                        "children_count": len(members),
                        "anomalies": anomalies,
                        "trust": updated_trust,
                        "actions": actions
                    })

            time.sleep(1)

        except KeyboardInterrupt:
            print("Stopped by user.")
            break

        except Exception as e:
            print("Loop Error:", e)
            time.sleep(1)


# =====================================================
# START
# =====================================================
if __name__ == "__main__":

    file_thread = threading.Thread(
        target=start_file_monitor,
        args=(".",),
        daemon=True
    )

    file_thread.start()

    monitor_loop()