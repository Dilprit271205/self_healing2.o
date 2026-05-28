# analysis/trust_engine.py

from analysis.trust.trust_vector import (
    initialize_trust,
    get_trust,
    trust_db
)

# ===================================================
# PPT PARAMETERS
# slide 24
#
# stabilized for real systems
# ===================================================

EMA_ALPHA = 0.9

STATIC_WEIGHT = 0.4
DYNAMIC_WEIGHT = 0.6


class TrustEngine:
    """
    PPT + REVIEW ALIGNED
    stable trust engine

    Responsibilities:
    1. EMA trust evolution
    2. Dynamic trust aggregation
    3. Final trust computation
    4. Threshold classification
    """

    # ===================================================
    # MAIN TRUST UPDATE
    # ===================================================
    def update(
        self,
        pid,
        anomaly_vector,
        static_score
    ):

        initialize_trust(pid)

        current = get_trust(pid)

        # -----------------------------------------
        # SAFE ANOMALY ACCESS
        # prevents crashes
        # -----------------------------------------
        cpu_anomaly = anomaly_vector.get(
            "cpu",
            0
        )

        memory_anomaly = anomaly_vector.get(
            "memory",
            0
        )

        thread_anomaly = anomaly_vector.get(
            "threads",
            0
        )

        connection_anomaly = anomaly_vector.get(
            "connections",
            0
        )

        file_anomaly = anomaly_vector.get(
            "file_events",
            0
        )

        # -----------------------------------------
        # PREVIOUS TRUST
        # slide 24
        # -----------------------------------------
        prev_cpu = current.get(
            "cpu",
            1.0
        )

        prev_memory = current.get(
            "memory",
            1.0
        )

        prev_threads = current.get(
            "threads",
            1.0
        )

        prev_connections = current.get(
            "connections",
            1.0
        )

        prev_files = current.get(
            "files",
            1.0
        )

        # -----------------------------------------
        # EMA TRUST UPDATE
        #
        # T = αTprev + (1-α)(1-A)
        #
        # slide 24
        # stabilized
        # -----------------------------------------
        updated_cpu = (

            EMA_ALPHA
            * prev_cpu

            +

            (
                1
                -
                EMA_ALPHA
            )

            *
            (
                1
                -
                cpu_anomaly
            )
        )

        updated_memory = (

            EMA_ALPHA
            * prev_memory

            +

            (
                1
                -
                EMA_ALPHA
            )

            *
            (
                1
                -
                memory_anomaly
            )
        )

        updated_threads = (

            EMA_ALPHA
            * prev_threads

            +

            (
                1
                -
                EMA_ALPHA
            )

            *
            (
                1
                -
                thread_anomaly
            )
        )

        updated_connections = (

            EMA_ALPHA
            * prev_connections

            +

            (
                1
                -
                EMA_ALPHA
            )

            *
            (
                1
                -
                connection_anomaly
            )
        )

        updated_files = (

            EMA_ALPHA
            * prev_files

            +

            (
                1
                -
                EMA_ALPHA
            )

            *
            (
                1
                -
                file_anomaly
            )
        )

        # -----------------------------------------
        # CLAMP VALUES
        # prevents trust overflow
        # -----------------------------------------
        trust_vector = {

            "cpu":
                round(
                    max(
                        0.0,
                        min(
                            1.0,
                            updated_cpu
                        )
                    ),
                    3
                ),

            "memory":
                round(
                    max(
                        0.0,
                        min(
                            1.0,
                            updated_memory
                        )
                    ),
                    3
                ),

            "threads":
                round(
                    max(
                        0.0,
                        min(
                            1.0,
                            updated_threads
                        )
                    ),
                    3
                ),

            "connections":
                round(
                    max(
                        0.0,
                        min(
                            1.0,
                            updated_connections
                        )
                    ),
                    3
                ),

            "files":
                round(
                    max(
                        0.0,
                        min(
                            1.0,
                            updated_files
                        )
                    ),
                    3
                )
        }

        # -----------------------------------------
        # DYNAMIC TRUST
        # Td
        # slide 24
        # -----------------------------------------
        dynamic_trust = round(

            sum(
                trust_vector.values()
            )

            /

            len(
                trust_vector
            ),

            3
        )

        # -----------------------------------------
        # FINAL TRUST
        #
        # T(p,t)
        #
        # stabilized weights
        # -----------------------------------------
        final_trust = round(

            (
                STATIC_WEIGHT
                *
                max(
                    0,
                    min(
                        1,
                        static_score
                    )
                )
            )

            +

            (
                DYNAMIC_WEIGHT
                *
                dynamic_trust
            ),

            3
        )

        # -----------------------------------------
        # STORE TRUST
        # -----------------------------------------
        trust_db[pid] = {

            **trust_vector,

            "static_trust":
                round(
                    static_score,
                    3
                ),

            "dynamic_trust":
                dynamic_trust,

            "final_trust":
                final_trust
        }

        return trust_db[pid]

    # ===================================================
    # TRUST CLASSIFICATION
    # slide 24
    # ===================================================
    def classify(
        self,
        trust_state
    ):

        td = trust_state.get(
            "dynamic_trust",
            1.0
        )

        if td >= 0.75:

            return {

                "level":
                    "normal",

                "severity":
                    0
            }

        elif td >= 0.5:

            return {

                "level":
                    "suspicious",

                "severity":
                    1
            }

        return {

            "level":
                "critical",

            "severity":
                2
        }