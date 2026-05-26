# analysis/trust_engine.py

from analysis.trust.trust_vector import (
    initialize_trust,
    get_trust,
    trust_db
)

# ---------------------------------------------------
# PPT PARAMETERS
# slide 24
# ---------------------------------------------------

EMA_ALPHA = 0.7

STATIC_WEIGHT = 0.3
DYNAMIC_WEIGHT = 0.7


class TrustEngine:
    """
    PPT-aligned trust engine

    Responsibilities:
    1. Trust evolution
    2. EMA smoothing
    3. Dynamic trust aggregation
    4. Final trust computation
    5. Threshold classification
    """

    def update(
        self,
        pid,
        anomaly_vector,
        static_score
    ):

        initialize_trust(pid)

        current = get_trust(pid)

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
        # T = αTprev + (1-α)(1-A)
        # slide 24
        # -----------------------------------------
        updated_cpu = (
            EMA_ALPHA * prev_cpu
            +
            (1 - EMA_ALPHA)
            *
            (
                1
                -
                anomaly_vector["cpu"]
            )
        )

        updated_memory = (
            EMA_ALPHA * prev_memory
            +
            (1 - EMA_ALPHA)
            *
            (
                1
                -
                anomaly_vector["memory"]
            )
        )

        updated_threads = (
            EMA_ALPHA * prev_threads
            +
            (1 - EMA_ALPHA)
            *
            (
                1
                -
                anomaly_vector["threads"]
            )
        )

        updated_connections = (
            EMA_ALPHA
            * prev_connections
            +
            (1 - EMA_ALPHA)
            *
            (
                1
                -
                anomaly_vector[
                    "connections"
                ]
            )
        )

        updated_files = (
            EMA_ALPHA
            * prev_files
            +
            (1 - EMA_ALPHA)
            *
            (
                1
                -
                anomaly_vector[
                    "file_events"
                ]
            )
        )

        # -----------------------------------------
        # CLAMP VALUES
        # -----------------------------------------
        trust_vector = {
            "cpu":
                round(
                    max(
                        0,
                        min(1,
                            updated_cpu
                        )
                    ),
                    3
                ),

            "memory":
                round(
                    max(
                        0,
                        min(1,
                            updated_memory
                        )
                    ),
                    3
                ),

            "threads":
                round(
                    max(
                        0,
                        min(1,
                            updated_threads
                        )
                    ),
                    3
                ),

            "connections":
                round(
                    max(
                        0,
                        min(1,
                            updated_connections
                        )
                    ),
                    3
                ),

            "files":
                round(
                    max(
                        0,
                        min(1,
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
            (
                sum(
                    trust_vector.values()
                )
            )
            /
            len(trust_vector),
            3
        )

        # -----------------------------------------
        # FINAL TRUST
        # T(p,t)
        # slide 24
        # ws=0.3 wd=0.7
        # -----------------------------------------
        final_trust = round(
            (
                STATIC_WEIGHT
                *
                static_score
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
        # STORE TRUST STATE
        # -----------------------------------------
        trust_db[pid] = {

            # trust vector
            **trust_vector,

            # static
            "static_trust":
                round(
                    static_score,
                    3
                ),

            # Td
            "dynamic_trust":
                dynamic_trust,

            # T(p,t)
            "final_trust":
                final_trust
        }

        return trust_db[pid]

    # -----------------------------------------
    # THRESHOLD EVALUATION
    # slide 24
    # -----------------------------------------
    def classify(
        self,
        trust_state
    ):

        td = trust_state.get(
            "dynamic_trust",
            1.0
        )

        if td > 0.7:

            return {
                "level": "normal",
                "severity": 0
            }

        elif 0.4 < td <= 0.7:

            return {
                "level":
                    "suspicious",
                "severity": 1
            }

        return {
            "level":
                "critical",
            "severity": 2
        }