# analysis/worm_classifier.py

from analysis.ml_threat_model import load_autonomous_model


class WormClassifier:
    """
    ML-backed process threat classifier.

    The public API stays compatible with the old dashboard/healing pipeline,
    but inference no longer uses hand-written threshold branches. Labels,
    confidence, and worm score come from the persisted ML model.
    """

    def __init__(self, model=None):
        self.model = model or load_autonomous_model()

    def classify(
        self,
        features,
        anomaly_data,
        trust_state
    ):
        prediction = self.model.predict(
            features=features,
            anomaly_data=anomaly_data,
            trust_state=trust_state
        )
        model_status = (
            self.model.status()
            if hasattr(self.model, "status")
            else {}
        )

        dynamic_trust = round(
            float(
                trust_state.get(
                    "dynamic_trust",
                    1.0
                )
            ),
            3
        )

        final_trust = round(
            float(
                trust_state.get(
                    "final_trust",
                    1.0
                )
            ),
            3
        )

        behavior = prediction.behavior_signals
        correlated_signals = {
            "rapid_child_spawning":
                behavior.get("rapid_child_spawning", False),
            "large_or_growing_tree":
                behavior.get("large_or_growing_tree", False),
            "repeated_similar_children":
                behavior.get("repeated_similar_children", False),
            "short_lived_recursive_children":
                behavior.get("short_lived_recursive_children", False),
            "thread_explosion":
                behavior.get("thread_explosion", False),
            "cpu_memory_escalation":
                behavior.get("cpu_memory_escalation", False),
            "file_replication":
                behavior.get("file_replication", False),
            "network_fanout":
                behavior.get("network_fanout", False),
            "process_storm_burst":
                behavior.get("process_storm_burst", False),
            "resource_pressure":
                behavior.get("resource_pressure", False),
            "high_file_velocity":
                behavior.get("high_file_velocity", False),
            "extreme_file_velocity":
                behavior.get("extreme_file_velocity", False),
            "mass_file_modification":
                behavior.get("mass_file_modification", False),
            "suspicious_rename":
                behavior.get("suspicious_rename", False),
            "persistence_artifact":
                behavior.get("persistence_artifact", False),
            "sensitive_file_access":
                behavior.get("sensitive_file_access", False),
            "localhost_beaconing":
                behavior.get("localhost_beaconing", False),
            "trust_anomaly_pattern":
                behavior.get("trust_anomaly_pattern", False),
            "worm_like_behavior":
                behavior.get("worm_like_behavior", False),
        }
        correlated_signal_count = sum(
            1 for active in correlated_signals.values() if active
        )
        replication_detected = any(
            [
                behavior.get("file_replication", False),
                behavior.get("mass_file_modification", False),
                behavior.get("suspicious_rename", False),
            ]
        )
        fanout_detected = behavior.get("network_fanout", False)
        artifact_abuse_detected = any(
            [
                behavior.get("persistence_artifact", False),
                behavior.get("sensitive_file_access", False),
            ]
        )
        thread_storm_detected = behavior.get("thread_explosion", False)
        catastrophic_behavior = behavior.get("catastrophic_behavior", False)
        trust_anomaly_pattern = behavior.get(
            "trust_anomaly_pattern",
            False
        )
        worm_like_behavior = behavior.get(
            "worm_like_behavior",
            False
        )

        return {
            "label":
                prediction.label,

            "severity":
                prediction.severity,

            "worm_score":
                prediction.worm_score,

            "confidence":
                prediction.confidence,

            "dynamic_trust":
                dynamic_trust,

            "final_trust":
                final_trust,

            "signals": {
                "ml_model":
                    "random_forest_plus_isolation_forest",

                "ml_probabilities":
                    prediction.probabilities,

                "ml_anomaly_probability":
                    prediction.anomaly_probability,

                "ml_behavior_probabilities":
                    prediction.behavior_probabilities,

                "ml_top_drivers":
                    prediction.top_drivers,

                "ml_status":
                    {
                        "autotrain":
                            model_status.get("autotrain", False),

                        "retraining":
                            model_status.get("retraining", False),

                        "trained_rows":
                            (
                                model_status
                                .get("metadata", {})
                                .get("rows", 0)
                            ),
                    },

                "forkbomb_detected":
                    prediction.label == "forkbomb",

                "combined_risk":
                    prediction.worm_score,

                "correlated_signal_count":
                    correlated_signal_count,

                "correlated_signals":
                    correlated_signals,

                "catastrophic_behavior":
                    catastrophic_behavior,

                "trust_anomaly_pattern":
                    trust_anomaly_pattern,

                "worm_like_behavior":
                    worm_like_behavior,

                "replication_detected":
                    replication_detected,

                "fanout_detected":
                    fanout_detected,

                "artifact_abuse_detected":
                    artifact_abuse_detected,

                "thread_storm_detected":
                    thread_storm_detected,

                "category_suppressed":
                    False,
            }
        }
