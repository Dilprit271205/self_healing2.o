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
