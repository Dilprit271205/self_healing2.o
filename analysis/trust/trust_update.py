# analysis/trust/trust_update.py

"""
Compatibility wrapper
for Batch 1 trust architecture.

Purpose:
Maintain legacy imports while
routing trust computation to
the new trust_engine.

Prevents:
- duplicate trust logic
- legacy penalties
- schema conflicts
"""

from analysis.trust.trust_vector import (
    initialize_trust,
    get_trust
)

from analysis.trust_engine import (
    TrustEngine
)

from analysis.baseline_engine import (
    BaselineEngine
)

# -----------------------------------------
# singleton engine
# -----------------------------------------
trust_engine = TrustEngine()

baseline_engine = BaselineEngine()


# -----------------------------------------
# LEGACY COMPATIBILITY
# -----------------------------------------
def update_trust(

    pid,

    current_trust=None,

    anomalies=None,

    static_score=1.0,

    features=None
):
    """
    Batch 2 compatibility layer.

    Supports both:

    OLD:
    update_trust(
        pid,
        current_trust,
        anomalies,
        static_score
    )

    NEW:
    update_trust(
        pid,
        features=features,
        static_score=x
    )
    """

    initialize_trust(pid)

    # -----------------------------------------
    # Legacy compatibility
    # reconstruct features
    # -----------------------------------------
    if features is None:

        anomalies = (
            anomalies
            or {}
        )

        anomaly_vector = {

            "cpu":
                float(
                    anomalies.get(
                        "cpu",
                        0
                    )
                ),

            "memory":
                float(
                    anomalies.get(
                        "memory",
                        0
                    )
                ),

            "threads":
                float(
                    anomalies.get(
                        "threads",
                        0
                    )
                ),

            "connections":
                float(
                    anomalies.get(
                        "connections",
                        anomalies.get(
                            "net",
                            0
                        )
                    )
                ),

            "file_events":
                float(
                    anomalies.get(
                        "file_events",
                        anomalies.get(
                            "file",
                            0
                        )
                    )
                )
        }

    else:

        raw_features = {

            "cpu":
                float(
                    features.get(
                        "cpu",
                        0
                    )
                ),

            "memory":
                float(
                    features.get(
                        "memory",
                        0
                    )
                ),

            "threads":
                float(
                    features.get(
                        "threads",
                        features.get(
                            "f_thread",
                            0
                        )
                    )
                ),

            "connections":
                float(
                    features.get(
                        "connections",
                        0
                    )
                ),

            "file_events":
                float(
                    features.get(
                        "file_events",
                        0
                    )
                )
        }

        anomaly_vector = {}

        for feature, value in raw_features.items():
            base = baseline_engine.get_baseline(
                feature
            )

            anomaly_vector[feature] = (
                baseline_engine.anomaly_score(
                    feature=feature,
                    value=value,
                    mu=base["mu"],
                    sigma=base["sigma"]
                )
            )

    # -----------------------------------------
    # Route to Batch 1 engine
    # -----------------------------------------
    trust_state = (
        trust_engine.update(
            pid=pid,
            anomaly_vector=anomaly_vector,
            static_score=
                static_score
        )
    )

    return trust_state


# -----------------------------------------
# compatibility helper
# -----------------------------------------
def get_updated_trust(
    pid
):

    return get_trust(pid)
