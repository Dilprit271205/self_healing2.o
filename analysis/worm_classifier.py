# analysis/worm_classifier.py

from analysis.policy_engine import policy_engine
import re

class WormClassifier:
    """
    PPT + reviewer aligned
    worm classification engine

    Responsibilities:
    1. Worm likelihood estimation
    2. Trust + anomaly fusion
    3. Propagation intelligence
    4. Severity classification
    5. Stable low false-positive detection
    """

    def classify(
        self,
        features,
        anomaly_data,
        trust_state
    ):

        anomalies = anomaly_data.get(
            "anomalies",
            {}
        )

        temporal = anomaly_data.get(
            "temporal",
            {}
        )

        # =====================================
        # TRUST STATE
        # slide 24
        # PRIMARY SIGNAL
        # =====================================
        dynamic_trust = (
            trust_state.get(
                "dynamic_trust",
                1.0
            )
        )

        final_trust = (
            trust_state.get(
                "final_trust",
                1.0
            )
        )

        # =====================================
        # ANOMALY SIGNAL
        # =====================================
        aggregate_anomaly = (
            anomalies.get(
                "aggregate",
                0
            )
        )

        # =====================================
        # PROPAGATION SIGNAL
        # reviewer requirement
        # =====================================
        process_growth = abs(
            features.get(
                "f_proc_spawn",
                0
            )
        )

        process_tree = abs(
            features.get(
                "f_proc_tree",
                0
            )
        )

        # Avoid flagging stable services that have a large static
        # process tree but are not actively forking.
        tree_pressure = 0
        if process_growth > 0 or features.get("f_young_process", 0):
            tree_pressure = max(
                process_tree - 8,
                0
            ) * 0.35

        propagation_signal = min(
            (
                process_growth * 4
                +
                tree_pressure
                +
                features.get(
                    "f_process_trend",
                    0
                ) * 4
                +
                features.get(
                    "f_young_process",
                    0
                ) * 4
                +
                features.get(
                    "f_child_similarity",
                    0
                ) * 5
                +
                features.get(
                    "f_short_lived_child_ratio",
                    0
                ) * 4
            )
            / 30,
            1
        )

        # =====================================
        # THREAD ABUSE
        # reviewer requirement
        # =====================================
        thread_signal = min(
            abs(
                features.get(
                    "f_thread_velocity",
                    0
                )
            )
            / 8,
            1
        )

        # =====================================
        # NETWORK SPREAD
        # reviewer requirement
        # =====================================
        network_signal = min(
            (
                abs(
                    features.get(
                        "f_connection_velocity",
                        0
                    )
                )
                / 10
                +
                min(
                    features.get(
                        "f_remote_ips",
                        0
                    )
                    / 10,
                    1
                )
            ),
            1
        )

        # =====================================
        # TEMPORAL INSTABILITY
        # reviewer requirement
        # =====================================
        cpu_accel = abs(
            temporal.get(
                "cpu_acceleration",
                0
            )
        )

        memory_accel = abs(
            temporal.get(
                "memory_acceleration",
                0
            )
        )

        temporal_signal = min(
            (
                cpu_accel
                +
                memory_accel
            )
            / 2,
            1
        )

        worm_heuristic = min(
            features.get(
                "worm_score",
                0
            )
            / 50,
            1
        )

        # Fork-bomb / rapid propagation behavior.
        fork_rate = abs(features.get("f_proc_spawn", 0))
        tree_size = abs(features.get("f_proc_tree", 0))
        tree_growth = max(0, fork_rate)
        young = features.get("f_young_process", 0)
        file_events = features.get("file_events", 0)
        threads = features.get("f_thread", 0)
        thread_velocity_raw = abs(features.get("f_thread_velocity", 0))
        repeated_child_count = features.get("f_repeated_child_count", 0)
        child_similarity = features.get("f_child_similarity", 0)
        short_lived_children = features.get("f_short_lived_child_ratio", 0)
        cmdline = str(features.get("cmdline", "") or "").lower()
        category_suppressed = bool(
            features.get("false_positive_suppression", 0)
        )

        process_storm_burst = (
            tree_size >= 10
            and repeated_child_count >= 6
            and child_similarity >= 0.50
            and short_lived_children >= 0.50
        )

        file_burst = file_events >= 25
        extreme_file_burst = file_events >= 75
        mass_file_modification = features.get(
            "f_mass_file_modification",
            0
        ) or file_events >= 80
        suspicious_rename_activity = bool(
            features.get("f_suspicious_rename", 0)
            or features.get("rename_events", 0) >= 12
            or re.search(
                r"\\.(locked|encrypted|crypt|enc| ransom|pay)$",
                cmdline
            )
        )
        persistence_artifact_activity = bool(
            features.get("f_persistence_artifact", 0)
            or features.get("persistence_events", 0) >= 1
            or any(
                token in cmdline
                for token in (
                    "startup",
                    "autorun",
                    "autostart",
                    "crontab",
                    "systemd",
                    "launchagent",
                    "run key",
                    "registry run"
                )
            )
        )
        sensitive_file_access = bool(
            features.get("f_sensitive_file_access", 0)
            or features.get("sensitive_file_events", 0) >= 1
            or any(
                token in cmdline
                for token in (
                    ".env",
                    "password",
                    "passwd",
                    "credential",
                    "secret",
                    "token"
                )
            )
        )
        thread_burst = (
            threads >= 80
            or thread_velocity_raw >= 40
        )
        cpu_burst = features.get("cpu", 0) >= 85
        memory_burst = features.get("memory", 0) >= 45
        resource_pressure = (
            cpu_burst
            or memory_burst
            or thread_burst
        )
        network_burst = (
            features.get("f_connection_velocity", 0) >= 8
            or features.get("f_remote_ips", 0) >= 8
            or features.get("f_port_spread", 0) >= 12
            or features.get("f_scanning_detected", False)
        )
        localhost_beaconing = bool(
            features.get("f_localhost_beaconing", 0)
            or (
                features.get("f_connection_velocity", 0) >= 6
                and features.get("f_remote_ips", 0) <= 2
                and (
                    "127.0.0.1" in cmdline
                    or "localhost" in cmdline
                    or features.get("f_loopback_connections", 0) >= 6
                )
            )
        )

        correlated_signals = {
            "rapid_child_spawning": fork_rate >= 3 or process_storm_burst,
            "large_or_growing_tree": tree_size >= 12 or tree_growth >= 6,
            "repeated_similar_children": (
                repeated_child_count >= 3 and child_similarity >= 0.60
            ),
            "short_lived_recursive_children": (
                short_lived_children >= 0.60 and tree_size >= 5
            ),
            "thread_explosion": thread_signal >= 0.45 or thread_burst,
            "cpu_memory_escalation": (
                temporal_signal >= 0.45
                or cpu_burst
                or memory_burst
            ),
            "file_replication": file_burst or (file_events >= 20 and fork_rate >= 1),
            "network_fanout": (
                network_signal >= 0.45
                or network_burst
                or localhost_beaconing
            ),
            "baseline_anomaly": aggregate_anomaly >= 0.45,
            "trust_collapse": final_trust <= 0.55 or dynamic_trust <= 0.55,
            "process_storm_burst": process_storm_burst,
            "resource_pressure": resource_pressure,
            "high_file_velocity": file_events >= 25,
            "extreme_file_velocity": extreme_file_burst,
            "mass_file_modification": bool(mass_file_modification),
            "suspicious_rename": suspicious_rename_activity,
            "persistence_artifact": persistence_artifact_activity,
            "sensitive_file_access": sensitive_file_access,
            "localhost_beaconing": localhost_beaconing,
            "behavioral_heuristic_pressure": worm_heuristic >= 0.45,
        }

        correlated_signal_count = sum(
            1 for active in correlated_signals.values() if active
        )

        thresholds = policy_engine.catastrophic_thresholds()
        catastrophic_behavior = (
            (
                fork_rate >= thresholds.get("spawn_rate", 40)
                and tree_size >= thresholds.get("process_tree", 120)
            )
            or tree_growth >= thresholds.get("tree_growth", 60)
            or (
                file_events >= thresholds.get("file_events", 300)
                and fork_rate >= 5
            )
            or (
                extreme_file_burst
                and correlated_signal_count >= 2
            )
            or (
                network_burst
                and correlated_signal_count >= 3
            )
            or (
                thread_burst
                and resource_pressure
                and correlated_signal_count >= 3
            )
            or (
                process_storm_burst
                and tree_size >= 20
            )
            or (
                features.get("cpu", 0) >= thresholds.get("cpu_percent", 95)
                and features.get("memory", 0) >= thresholds.get("memory_percent", 85)
                and correlated_signal_count >= 4
            )
        )

        replication_detected = (
            (
                file_burst
                or mass_file_modification
                or suspicious_rename_activity
            )
            and (
                aggregate_anomaly >= 0.25
                or worm_heuristic >= 0.45
                or correlated_signal_count >= 2
            )
        )

        fanout_detected = (
            (
                network_burst
                or localhost_beaconing
            )
            and (
                network_signal >= 0.35
                or aggregate_anomaly >= 0.25
                or correlated_signal_count >= 2
            )
        )

        artifact_abuse_detected = (
            (
                persistence_artifact_activity
                or sensitive_file_access
            )
            and (
                file_events >= 3
                or aggregate_anomaly >= 0.25
                or correlated_signal_count >= 2
            )
        )

        thread_storm_detected = (
            thread_burst
            and (
                aggregate_anomaly >= 0.25
                or worm_heuristic >= 0.45
                or correlated_signal_count >= 2
            )
        )

        forkbomb_detected = (
            correlated_signal_count >= 3
            and propagation_signal >= 0.35
            and (
                process_storm_burst
                or
                correlated_signals["repeated_similar_children"]
                or correlated_signals["short_lived_recursive_children"]
                or catastrophic_behavior
            )
        )

        # =====================================
        # WORM LIKELIHOOD
        #
        # Trust = primary
        # anomaly = secondary
        # propagation = tertiary
        # =====================================
        worm_likelihood = round(

            (
                (
                    1
                    -
                    dynamic_trust
                )
                * 0.06

                +

                (
                    1
                    -
                    final_trust
                )
                * 0.06

                +

                aggregate_anomaly
                * 0.18

                +

                propagation_signal
                * 0.30

                +

                thread_signal
                * 0.10

                +

                network_signal
                * 0.06

                +

                temporal_signal
                * 0.08

                +

                worm_heuristic
                * 0.16

                +

                min(correlated_signal_count / 6, 1)
                * 0.18
            ),

            3
        )

        # strong propagation / anomaly boost for spreading behavior
        if (
            propagation_signal >= 0.7
            and
            aggregate_anomaly >= 0.45
        ):
            worm_likelihood = round(
                min(
                    1.0,
                    worm_likelihood + 0.22
                ),
                3
            )

        if (
            worm_heuristic >= 0.5
            and
            aggregate_anomaly >= 0.35
        ):
            worm_likelihood = round(
                min(
                    1.0,
                    worm_likelihood + 0.12
                ),
                3
            )

        if forkbomb_detected:
            worm_likelihood = round(max(worm_likelihood, 0.82), 3)

        if replication_detected or fanout_detected or artifact_abuse_detected:
            worm_likelihood = round(max(worm_likelihood, 0.80), 3)

        if thread_storm_detected:
            worm_likelihood = round(max(worm_likelihood, 0.72), 3)

        if resource_pressure and correlated_signal_count >= 2:
            worm_likelihood = round(max(worm_likelihood, 0.48), 3)

        if catastrophic_behavior and correlated_signal_count >= 5:
            worm_likelihood = round(max(worm_likelihood, 0.94), 3)

        if category_suppressed and not catastrophic_behavior:
            if correlated_signal_count < 4:
                worm_likelihood = round(min(worm_likelihood, 0.58), 3)


        confidence = round(
            worm_likelihood * 100,
            2
        )

        # =====================================
        # COMBINED RISK
        #
        # prevents false positives
        # =====================================
        combined_risk = round(

            (
                propagation_signal
                * 0.35

                +

                network_signal
                * 0.18

                +

                thread_signal
                * 0.12

                +

                temporal_signal
                * 0.12

                +

                aggregate_anomaly
                * 0.08

                +

                worm_heuristic
                * 0.10

                +

                min(correlated_signal_count / 6, 1)
                * 0.15
            ),

            3
        )

        if forkbomb_detected:
            combined_risk = round(
                max(combined_risk, 0.86),
                3
            )

        if replication_detected or fanout_detected or artifact_abuse_detected:
            combined_risk = round(
                max(combined_risk, 0.84),
                3
            )

        if thread_storm_detected:
            combined_risk = round(
                max(combined_risk, 0.72),
                3
            )

        if resource_pressure and correlated_signal_count >= 2:
            combined_risk = round(
                max(combined_risk, 0.50),
                3
            )

        if catastrophic_behavior and correlated_signal_count >= 5:
            combined_risk = round(
                max(combined_risk, 0.94),
                3
            )

        # =====================================
        # FINAL CLASSIFICATION
        #
        # Stable + reviewer safe
        # =====================================

        # -----------------------------
        # NORMAL
        # -----------------------------
        if (
            worm_likelihood < 0.28
            and
            aggregate_anomaly < 0.30
            and
            propagation_signal < 0.45
            and
            correlated_signal_count < 2
        ):

            label = "normal"
            severity = "low"

        # -----------------------------
        # WORM
        # -----------------------------
        elif (
            (
                worm_likelihood >= 0.74
                and combined_risk >= 0.62
                and correlated_signal_count >= 4
            )
            or
            (
                propagation_signal >= 0.70
                and aggregate_anomaly >= 0.45
                and correlated_signal_count >= 4
            )
        ):

            label = "worm"
            severity = "critical"

        elif forkbomb_detected:
            label = "forkbomb"
            severity = "critical"

        elif replication_detected or fanout_detected or artifact_abuse_detected:
            label = "worm"
            severity = "critical"

        elif thread_storm_detected:
            label = "suspicious"
            severity = "high"

        # -----------------------------
        # SUSPICIOUS / ANOMALOUS
        # -----------------------------
        else:

            if (
                worm_likelihood >= 0.30
                or
                propagation_signal >= 0.45
                or
                aggregate_anomaly >= 0.35
                or
                correlated_signal_count >= 2
            ):

                label = "suspicious"
                severity = "medium"

            else:

                label = "normal"
                severity = "low"

        # =====================================
        # OUTPUT
        # =====================================
        return {

            "label":
                label,

            "severity":
                severity,

            "worm_score":
                worm_likelihood,

            "confidence":
                confidence,

            "dynamic_trust":
                round(
                    dynamic_trust,
                    3
                ),

            "final_trust":
                round(
                    final_trust,
                    3
                ),

            "signals": {

                "propagation":
                    round(
                        propagation_signal,
                        3
                    ),

                "network":
                    round(
                        network_signal,
                        3
                    ),

                "thread":
                    round(
                        thread_signal,
                        3
                    ),

                "temporal":
                    round(
                        temporal_signal,
                        3
                    ),

                "forkbomb_detected":
                    forkbomb_detected,

                "combined_risk":
                    combined_risk,

                "correlated_signal_count":
                    correlated_signal_count,

                "correlated_signals":
                    correlated_signals,

                "catastrophic_behavior":
                    catastrophic_behavior,

                "replication_detected":
                    replication_detected,

                "fanout_detected":
                    fanout_detected,

                "artifact_abuse_detected":
                    artifact_abuse_detected,

                "thread_storm_detected":
                    thread_storm_detected,

                "category_suppressed":
                    category_suppressed
            }
        }
