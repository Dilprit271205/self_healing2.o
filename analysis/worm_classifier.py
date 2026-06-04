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
        file_events = float(
            features.get(
                "file_events",
                0
            )
            or 0
        )
        connection_velocity = float(
            features.get(
                "f_connection_velocity",
                0
            )
            or 0
        )
        remote_ips = float(
            features.get(
                "f_remote_ips",
                0
            )
            or 0
        )
        loopback_connections = float(
            features.get(
                "f_loopback_connections",
                0
            )
            or 0
        )
        thread_count = float(
            features.get(
                "f_thread",
                features.get(
                    "threads",
                    0
                )
            )
            or 0
        )
        source_worm_score = float(
            features.get(
                "worm_score",
                0
            )
            or 0
        )

        direct_behavior = {
            "file_replication":
                file_events >= 25
                or bool(
                    features.get(
                        "file_replication_preflight",
                        False
                    )
                ),
            "high_file_velocity":
                file_events >= 25,
            "extreme_file_velocity":
                file_events >= 60,
            "mass_file_modification":
                file_events >= 45
                or bool(
                    features.get(
                        "f_mass_file_modification",
                        0
                    )
                ),
            "suspicious_rename":
                bool(
                    features.get(
                        "f_suspicious_rename",
                        0
                    )
                )
                or float(
                    features.get(
                        "rename_events",
                        0
                    )
                    or 0
                ) >= 8,
            "network_fanout":
                connection_velocity >= 10
                or remote_ips >= 10
                or loopback_connections >= 8,
            "localhost_beaconing":
                bool(
                    features.get(
                        "f_localhost_beaconing",
                        0
                    )
                )
                or (
                    loopback_connections >= 8
                    and connection_velocity >= 8
                ),
            "thread_explosion":
                thread_count >= 80
                or float(
                    features.get(
                        "f_thread_velocity",
                        0
                    )
                    or 0
                ) >= 50,
            "persistence_artifact":
                bool(
                    features.get(
                        "f_persistence_artifact",
                        0
                    )
                )
                or float(
                    features.get(
                        "persistence_events",
                        0
                    )
                    or 0
                ) > 0,
            "sensitive_file_access":
                bool(
                    features.get(
                        "f_sensitive_file_access",
                        0
                    )
                )
                or float(
                    features.get(
                        "sensitive_file_events",
                        0
                    )
                    or 0
                ) > 0,
            "rapid_child_spawning":
                float(
                    features.get(
                        "f_proc_spawn",
                        0
                    )
                    or 0
                ) >= 4,
            "large_or_growing_tree":
                float(
                    features.get(
                        "f_proc_tree",
                        0
                    )
                    or 0
                ) >= 8,
            "repeated_similar_children":
                float(
                    features.get(
                        "f_repeated_child_count",
                        0
                    )
                    or 0
                ) >= 4,
            "short_lived_recursive_children":
                float(
                    features.get(
                        "f_short_lived_child_ratio",
                        0
                    )
                    or 0
                ) >= 0.40,
        }

        direct_behavior[
            "process_storm_burst"
        ] = (
            direct_behavior["rapid_child_spawning"]
            and direct_behavior["large_or_growing_tree"]
        )
        direct_behavior[
            "resource_pressure"
        ] = (
            float(
                features.get(
                    "cpu",
                    0
                )
                or 0
            ) >= 85
            or float(
                features.get(
                    "memory",
                    0
                )
                or 0
            ) >= 35
            or direct_behavior["thread_explosion"]
        )
        direct_behavior[
            "cpu_memory_escalation"
        ] = direct_behavior["resource_pressure"]
        direct_behavior[
            "worm_like_behavior"
        ] = (
            direct_behavior["file_replication"]
            and (
                direct_behavior["network_fanout"]
                or direct_behavior["resource_pressure"]
                or source_worm_score >= 70
            )
        )

        for name, active in direct_behavior.items():
            if active:
                behavior[
                    name
                ] = True

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

        process_category = str(
            features.get(
                "process_category",
                ""
            )
            or
            ""
        )
        suppressed_category = bool(
            features.get(
                "false_positive_suppression",
                0
            )
        )
        if not suppressed_category and process_category:
            try:
                from analysis.policy_engine import policy_engine

                suppressed_category = (
                    policy_engine.is_suppressed_category(
                        process_category
                    )
                    or
                    policy_engine.is_hard_protected_category(
                        process_category
                    )
                )
            except Exception:
                suppressed_category = False

        confirmed_worm_behavior = any(
            [
                catastrophic_behavior,
                replication_detected,
                fanout_detected,
                artifact_abuse_detected,
                thread_storm_detected,
                worm_like_behavior,
            ]
        )

        label = prediction.label
        severity = prediction.severity
        worm_score = prediction.worm_score
        confidence = prediction.confidence

        direct_replication_worm = (
            replication_detected
            and (
                bool(
                    features.get(
                        "file_replication_preflight",
                        False
                    )
                )
                or file_events >= 45
                or source_worm_score >= 60
            )
        )
        direct_network_worm = (
            fanout_detected
            and (
                source_worm_score >= 55
                or connection_velocity >= 10
                or remote_ips >= 10
            )
        )
        direct_correlated_worm = (
            worm_like_behavior
            or (
                confirmed_worm_behavior
                and correlated_signal_count >= 2
                and source_worm_score >= 65
            )
        )

        if (
            label not in {
                "worm",
                "forkbomb"
            }
            and (
                direct_replication_worm
                or direct_network_worm
                or direct_correlated_worm
            )
        ):
            label = "worm"
            severity = "critical"
            worm_score = max(
                float(
                    worm_score
                ),
                0.82
            )
            confidence = max(
                float(
                    confidence
                ),
                82.0
            )

        if (
            label in {"worm", "forkbomb"}
            and not confirmed_worm_behavior
        ):
            label = "suspicious"
            severity = "medium"
            worm_score = min(
                worm_score,
                0.69
            )
            confidence = min(
                confidence,
                65.0
            )

        if (
            suppressed_category
            and not catastrophic_behavior
        ):
            if confirmed_worm_behavior and correlated_signal_count >= 3:
                label = "suspicious"
                severity = "medium"
                worm_score = min(
                    worm_score,
                    0.74
                )
                confidence = min(
                    confidence,
                    72.0
                )
            else:
                label = "normal"
                severity = "low"
                worm_score = min(
                    worm_score,
                    0.30
                )
                confidence = min(
                    confidence,
                    55.0
                )

        return {
            "label":
                label,

            "severity":
                severity,

            "worm_score":
                round(
                    float(
                        worm_score
                    ),
                    3
                ),

            "confidence":
                round(
                    float(
                        confidence
                    ),
                    2
                ),

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
                    label == "forkbomb",

                "combined_risk":
                    round(
                        float(
                            worm_score
                        ),
                        3
                    ),

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
                    suppressed_category,
            }
        }
