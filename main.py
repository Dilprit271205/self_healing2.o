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
    get_network_data
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
MONITOR_INTERVAL = 6
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

# ===================================================
# FILE MONITOR THREAD
# ===================================================
def start_background_monitors():

    try:

        thread = threading.Thread(

            target=start_file_monitor,

            kwargs={
                "path": "."
            },

            daemon=True
        )

        thread.start()

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
def log_entities():

    try:

        entity_summary = (

            lineage_tracker
            .get_entity_summary()
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

        try:

            # =====================================
            # LIVE DATA COLLECTION
            # =====================================
            processes = (
                get_process_data()
            )

            network_data = (
                get_network_data()
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
                .build_entities()
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
            log_entities()

            # =====================================
            # PROCESS PIPELINE
            # =====================================
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
                    # temporary fallback
                    # until static analyzer
                    # fully integrated
                    # -------------------------
                    static_score = (
                        1.0
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

                except Exception as e:

                    print(
                        f"Process error "
                        f"{process.get('pid')}: "
                        f"{e}"
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


