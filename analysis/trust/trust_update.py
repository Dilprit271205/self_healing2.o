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

# -----------------------------------------
# singleton engine
# -----------------------------------------
trust_engine = TrustEngine()


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

        features = {

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

            "f_thread":
                float(
                    anomalies.get(
                        "threads",
                        0
                    )
                ),

            "connections":
                float(
                    anomalies.get(
                        "net",
                        0
                    )
                ),

            "file_events":
                float(
                    anomalies.get(
                        "file",
                        0
                    )
                )
        }

    # -----------------------------------------
    # Route to Batch 1 engine
    # -----------------------------------------
    trust_state = (
        trust_engine.update(
            pid=pid,
            features=features,
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