import time
import threading

from monitor.process_monitor import get_process_data
from monitor.network_monitor import get_network_data
from monitor.file_monitor import start_file_monitor

from utils.connection_mapper import map_connections
from utils.file_event_mapper import get_file_map

from analysis.feature_extractor import extract_features

from analysis.anomaly.cpu_anomaly import cpu_anomaly
from analysis.anomaly.file_anomaly import file_anomaly
from analysis.anomaly.network_anomaly import network_anomaly

from analysis.trust.trust_vector import initialize_trust, get_trust, trust_db
from analysis.trust.trust_update import update_trust

from analysis.decision.decision_engine import decide_action

from logger.logger import log_data


def monitor_loop():
    while True:
        processes = get_process_data()
        network = get_network_data()

        # 🔹 Clean dead processes from trust_db
        active_pids = set(p["pid"] for p in processes)

        for pid in list(trust_db.keys()):
            if pid not in active_pids:
                del trust_db[pid]

        connection_map = map_connections(network)
        file_map = get_file_map()

        for process in processes:
            pid = process["pid"]

            # 🔹 Initialize trust
            initialize_trust(pid)

            # 🔹 Extract hybrid features (dynamic + static)
            features = extract_features(process, connection_map, file_map)

            # 🔹 Detect anomalies (dynamic)
            anomalies = {
                "cpu": cpu_anomaly(features["cpu"]),
                "file": file_anomaly(features["file_events"]),
                "net": network_anomaly(features["connections"])
            }

            # 🔹 Get current trust
            current_trust = get_trust(pid)

            # 🔹 UPDATE TRUST (NEW HYBRID VERSION)
            updated_trust = update_trust(
                pid=pid,
                current_trust=current_trust,
                anomalies=anomalies,
                static_score=features["static_trust"]   # 🔥 KEY ADDITION
            )

            # 🔹 Decision engine uses FINAL trust
            actions = decide_action(updated_trust)

            # 🔹 Logging everything
            log_data({
                **features,
                "anomalies": anomalies,
                "trust": updated_trust,
                "actions": actions
            })

        time.sleep(2)


if __name__ == "__main__":
    file_thread = threading.Thread(
        target=start_file_monitor,
        args=(".",),
        daemon=True
    )
    file_thread.start()

    monitor_loop()