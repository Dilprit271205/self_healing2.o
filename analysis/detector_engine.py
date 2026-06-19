# analysis/detector_engine.py

from analysis.baseline_engine import (
    BaselineEngine
)

baseline = BaselineEngine()


class DetectorEngine:
    """
    PPT-aligned detector engine

    Responsibilities:
    1. Baseline comparison
    2. Statistical anomaly detection
    3. Temporal feature utilization
    4. Aggregate anomaly vector

    DOES NOT:
    - classify worms
    - trigger healing
    - update trust
    """

    def detect(
        self,
        pid,
        features
    ):

        # -----------------------------------------
        # UPDATE TEMPORAL HISTORY
        # fixes review 3.2
        # -----------------------------------------
        baseline.update_history(
            pid,
            features
        )

        anomaly_vector = {}

        # -----------------------------------------
        # PPT DYNAMIC FEATURES
        # slide 21 + 23
        # -----------------------------------------
        tracked_features = {

            # required PPT features
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
                        "f_thread",
                        0
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
                ),

            "spawn":
                float(
                    features.get(
                        "f_proc_spawn",
                        0
                    )
                ),

            "tree":
                float(
                    features.get(
                        "f_proc_tree",
                        0
                    )
                ),

            "remote_ips":
                float(
                    features.get(
                        "f_remote_ips",
                        0
                    )
                ),

            "child_similarity":
                float(
                    features.get(
                        "f_child_similarity",
                        0
                    )
                )
        }

        # -----------------------------------------
        # BASELINE COMPARISON
        # slide 23
        #
        # A=min(1, |f-μ| / kσ)
        # -----------------------------------------
        for feature, value in tracked_features.items():

            base = baseline.get_baseline(
                feature
            )

            anomaly = baseline.anomaly_score(
                feature=feature,
                value=value,
                mu=base["mu"],
                sigma=base["sigma"]
            )

            anomaly_vector[
                feature
            ] = anomaly

        # -----------------------------------------
        # TEMPORAL INTELLIGENCE
        # fixes review:
        # moving avg / velocity /
        # acceleration missing
        # -----------------------------------------
        temporal_features = {}

        for feature in tracked_features:

            temporal_features[
                f"{feature}_avg"
            ] = baseline.moving_average(
                pid,
                feature
            )

            temporal_features[
                f"{feature}_velocity"
            ] = baseline.rate_of_change(
                pid,
                feature
            )

            temporal_features[
                f"{feature}_acceleration"
            ] = baseline.acceleration(
                pid,
                feature
            )
        
        # -----------------------------------------
        # FORK BOMB EARLY WARNING
        # Detect rapid PID creation by age ratio
        # -----------------------------------------
        try:
            # If a young process (age < 5s) already has 8+ PIDs, it's forking rapidly
            proc_age = float(features.get("age_seconds", 60))
            tree_size = int(features.get("f_proc_tree", 0))
            
            if proc_age > 0 and proc_age < 5:
                fork_rate_per_sec = tree_size / proc_age
                temporal_features["fork_rate_per_sec"] = round(fork_rate_per_sec, 2)
                # Flag if forking >3 children per second in first 5 seconds
                if fork_rate_per_sec > 3:
                    temporal_features["fork_bomb_early_warning"] = True
            else:
                temporal_features["fork_rate_per_sec"] = 0
                temporal_features["fork_bomb_early_warning"] = False
        except:
            temporal_features["fork_rate_per_sec"] = 0
            temporal_features["fork_bomb_early_warning"] = False

        # -----------------------------------------
        # AGGREGATE ANOMALY
        #
        # used by trust engine
        # -----------------------------------------
        aggregate_score = round(
            (
                sum(
                    anomaly_vector.values()
                )
            )
            /
            len(
                anomaly_vector
            ),
            3
        )

        anomaly_vector[
            "aggregate"
        ] = aggregate_score

        process_anomaly = max(
            anomaly_vector.get("spawn", 0),
            anomaly_vector.get("tree", 0),
            anomaly_vector.get("child_similarity", 0)
        )

        network_anomaly = max(
            anomaly_vector.get("connections", 0),
            anomaly_vector.get("remote_ips", 0)
        )

        behavior_correlation = self._worm_behavior_correlation(
            features,
            anomaly_vector
        )

        anomaly_vector[
            "process"
        ] = round(process_anomaly, 3)

        anomaly_vector[
            "network"
        ] = round(network_anomaly, 3)

        anomaly_vector[
            "worm_pattern"
        ] = round(behavior_correlation, 3)

        # -----------------------------------------
        # RETURN
        # detector only returns
        # anomaly information
        # -----------------------------------------
        return {
            "anomalies":
                anomaly_vector,

            "temporal":
                temporal_features
        }

    def _worm_behavior_correlation(
        self,
        features,
        anomaly_vector
    ):
        """
        Scores correlated worm-like behavior across process lineage, network
        fanout, file replication, persistence, and resource pressure.
        """

        process_pressure = max(
            anomaly_vector.get("spawn", 0),
            anomaly_vector.get("tree", 0),
            anomaly_vector.get("child_similarity", 0),
            1.0 if float(features.get("f_proc_tree", 0)) >= 12 else 0.0,
            1.0 if float(features.get("f_proc_spawn", 0)) >= 4 else 0.0,
            1.0 if float(features.get("f_repeated_child_count", 0)) >= 8 else 0.0,
        )

        network_pressure = max(
            anomaly_vector.get("connections", 0),
            anomaly_vector.get("remote_ips", 0),
            1.0 if float(features.get("f_connection_velocity", 0)) >= 10 else 0.0,
            1.0 if float(features.get("f_remote_ips", 0)) >= 10 else 0.0,
            1.0 if float(features.get("f_loopback_connections", 0)) >= 8 else 0.0,
            1.0 if float(features.get("f_scanning_score", 0)) >= 0.8 else 0.0,
            1.0 if features.get("f_scanning_detected", 0) else 0.0,
        )

        file_pressure = max(
            anomaly_vector.get("file_events", 0),
            1.0 if float(features.get("file_events", 0)) >= 45 else 0.0,
            1.0 if features.get("f_mass_file_modification", 0) else 0.0,
            1.0 if features.get("f_suspicious_rename", 0) else 0.0,
        )

        persistence_pressure = max(
            1.0 if features.get("f_persistence_artifact", 0) else 0.0,
            1.0 if features.get("f_sensitive_file_access", 0) else 0.0,
        )

        resource_pressure = max(
            anomaly_vector.get("cpu", 0),
            anomaly_vector.get("memory", 0),
            anomaly_vector.get("threads", 0),
            1.0 if float(features.get("f_thread", 0)) >= 80 else 0.0,
            1.0 if float(features.get("cpu", 0)) >= 85 else 0.0,
            1.0 if float(features.get("memory", 0)) >= 35 else 0.0,
        )

        pressures = [
            process_pressure,
            network_pressure,
            file_pressure,
            persistence_pressure,
            resource_pressure,
        ]

        active_domains = sum(
            1
            for pressure in pressures
            if pressure >= 0.45
        )

        if active_domains == 0:
            return 0.0

        weighted = (
            process_pressure * 0.30
            + network_pressure * 0.22
            + file_pressure * 0.22
            + persistence_pressure * 0.16
            + resource_pressure * 0.10
        )

        correlation_bonus = min(
            active_domains / 5,
            1.0
        ) * 0.25

        return max(
            0.0,
            min(
                1.0,
                weighted + correlation_bonus
            )
        )
