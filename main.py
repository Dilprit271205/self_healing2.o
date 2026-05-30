# main.py

import time
import threading
import traceback

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
    ProcessLineageTracker
)

from monitor.network_monitor import (
    NetworkMonitor
)

from monitor.file_monitor import (
    start_file_monitor
)

# ===================================================
# UTILITIES
# ===================================================
from utils.connection_mapper import (
    map_connections
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
MONITOR_INTERVAL = 10
SYSTEM_SAFE_PIDS = {
    0,
    1
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
# ===================================================
# FILE MONITOR THREAD
# ===================================================
def start_background_monitors():

    try:

        observer = start_file_monitor(
            paths=[
                "/home/suyash-anand/Downloads",
                "/tmp",
                "/var/tmp"
            ]
        )

        if observer is None:
            print(
                "📂 File monitor skipped (watchdog unavailable or paths missing)"
            )
            return

        print(
            "📂 File monitor started"
        )

    except Exception as e:

        print(
            f"File monitor failed: {e}"
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
# MAIN LOOP
# ===================================================
def monitor_loop():

    print(
        "\n🛡 Self-Healing Cyber Defense Started"
    )

    while True:
        print(
            "\n[NEW LOOP]"
        )
        try:

            # =====================================
            # LIVE DATA COLLECTION
            # =====================================
            processes = (
                get_process_data()
            )
            print(
                f"[PROCESS COUNT] "
                f"{len(processes)}"
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

            # =====================================
            # BUILD ENTITY MAP
            # =====================================
            entity_map = {}

            entities = (

                lineage_tracker
                .build_entities(
                    processes
                )
            )
            print(
                f"[ENTITIES] "
                f"{len(entities)}"
            )

            for (
                root,
                members
            ) in entities.items():

                for proc in members:

                    entity_map[
                        proc["pid"]
                    ] = members

            # =====================================
            # ENTITY LOGGING
            # =====================================
            log_entities(
                processes
            )

            # =====================================
            # PROCESS PIPELINE
            # =====================================
            print(
                "[PROCESS LOOP START]"
            )
            for process in processes:

                try:

                    pid = process.get(
                        "pid"
                    )

                    if (
                        pid
                        in
                        SYSTEM_SAFE_PIDS
                    ):

                        continue

                    # -------------------------
                    # SUSPECT FILTER
                    # lightweight early exclusion
                    # -------------------------
                    process_name = (
                        process.get(
                            "name",
                            ""
                        ).lower()
                    )

                    cmdline = (
                        process.get(
                            "cmdline",
                            ""
                        ).lower()
                    )

                    process_tree_size = len(
                        entity_map.get(
                            pid,
                            []
                        )
                    )

                    strong_suspicion = (
                        process["cpu"] > 18
                        or
                        process["connections"] > 10
                        or
                        process["open_files"] > 50
                    )

                    moderate_signals = [
                        process["cpu"] > 8,
                        process["connections"] > 6,
                        process["open_files"] > 20,
                        process_tree_size > 12,
                        process["age_seconds"] < 20
                    ]

                    suspicious_candidate = (
                        ("worm" in process_name)
                        or
                        ("python" in process_name and "worm" in cmdline)
                        or
                        strong_suspicion
                        or
                        sum(moderate_signals) >= 2
                    )

                    if not suspicious_candidate:

                        static_score = 0.95

                        trust_state = (
                            trust_engine
                            .update(

                                pid=
                                pid,

                                anomaly_vector={
                                    "cpu": 0,
                                    "memory": 0,
                                    "threads": 0,
                                    "connections": 0,
                                    "file_events": 0
                                },

                                static_score=
                                static_score
                            )
                        )

                        classification = {
                            "label": "normal",
                            "severity": "low",
                            "worm_score": 0.0,
                            "confidence": 0.0,
                            "dynamic_trust": trust_state["dynamic_trust"],
                            "final_trust": trust_state["final_trust"]
                        }

                        persistence_engine.update(

                            pid=
                            pid,

                            classification=
                            classification,

                            trust_state=
                            trust_state
                        )

                        log_process({

                            "pid":
                                pid,

                            "name":
                                process.get(
                                    "name",
                                    "unknown"
                                ),

                            "entity_root":
                                process.get(
                                    "ppid",
                                    0
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
                                "observe",

                            "response":
                                "skipped",

                            "learning_state":
                                {
                                    "reputation": 1.0,
                                    "trust_level": "trusted"
                                },

                            "anomalies":
                                {},

                            "features":
                                {
                                    "cpu": process["cpu"],
                                    "memory": process["memory"],
                                    "connections": process["connections"],
                                    "threads": process["threads"],
                                    "open_files": process["open_files"]
                                }
                        })

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
                            connection_map
                        )
                    )
                    print(
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
                    # STATIC TRUST
                    # safer fallback
                    # until static analyzer
                    # fully integrated
                    # -------------------------
                    try:

                        process_name = (
                            process.get(
                                "name",
                                ""
                            ).lower()
                        )

                        trusted_processes = {

                            "systemd",
                            "init",
                            "dbus-daemon",
                            "networkmanager",
                            "chrome",
                            "firefox",
                            "code",
                            "sudo",
                            "bash",
                            "zsh",
                            "gnome-shell"
                        }

                        cmdline = (
                            process.get(
                                "cmdline",
                                ""
                            )
                            .lower()
                        )

                        # trusted binaries
                        if process_name in trusted_processes:

                            static_score = 0.95

                        elif process_name in {"python", "python3"}:

                            if (
                                "worm_sim.py" in cmdline
                                or
                                "test_worm.py" in cmdline
                            ):
                                static_score = 0.35
                            else:
                                static_score = 0.75

                        # young / unknown process
                        elif features.get(
                            "f_young_process",
                            0
                        ):

                            static_score = 0.65

                        # normal fallback
                        else:

                            static_score = 0.85

                    except:

                        static_score = 0.70

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
                    healing_result = (

                        execute_healing(

                            pid=
                            pid,

                            process=
                            process,

                            classification=
                            classification,

                            persistence_state=
                            persistence_state,

                            trust_state=
                            trust_state
                        )
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
                            process.get(
                                "ppid",
                                0
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
                    print(
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
                "\n🛑 System stopped."
            )

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

response_engine = (
    ResponseEngine()
)

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

                f"🧹 Cleaned "
                f"{len(dead)} "
                f"dead processes"
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

    classification,

    persistence_state,

    trust_state
):

    try:

        # --------------------------------
        # LEARNING ADAPTATION
        # slide 17–18
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

        persistence_state[
            "stage"
        ] = (
            recommended_stage
        )

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
            trust_state
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

    monitor_loop()


