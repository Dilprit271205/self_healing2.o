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

from analysis.trust.trust_vector import initialize_trust, get_trust
from analysis.trust.trust_update import update_trust

from analysis.decision.decision_engine import decide_action

from logger.logger import log_data


def monitor_loop():
    while True:
        processes = get_process_data()
        network = get_network_data()

        # ✅ ADD IT HERE
        active_pids = set(p["pid"] for p in processes)

        from analysis.trust.trust_vector import trust_db

        for pid in list(trust_db.keys()):
            if pid not in active_pids:
                del trust_db[pid]

        connection_map = map_connections(network)
        file_map = get_file_map()

        for process in processes:
            pid = process["pid"]

            initialize_trust(pid)

            features = extract_features(process, connection_map, file_map)

            anomalies = {
                "cpu": cpu_anomaly(features["cpu"]),
                "file": file_anomaly(features["file_events"]),
                "net": network_anomaly(features["connections"])
            }

            trust = get_trust(pid)
            trust = update_trust(trust, anomalies)

            actions = decide_action(trust)

            log_data({
                **features,
                "anomalies": anomalies,
                "trust": trust,
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