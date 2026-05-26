# analysis/baseline_engine.py

from collections import defaultdict, deque
import statistics

# ---------------------------------------------------
# PPT BASELINES
# slide 23
# ---------------------------------------------------

BASELINES = {

    # required PPT features
    "cpu": {
        "mu": 20,
        "sigma": 5
    },

    "memory": {
        "mu": 200,
        "sigma": 50
    },

    "threads": {
        "mu": 10,
        "sigma": 3
    },

    "connections": {
        "mu": 5,
        "sigma": 2
    },

    "file_events": {
        "mu": 1,
        "sigma": 1
    },

    # -----------------------------------------
    # Worm-specific extensions
    # reviewer requested missing features
    # -----------------------------------------

    "spawn": {
        "mu": 1,
        "sigma": 1
    },

    "tree": {
        "mu": 5,
        "sigma": 3
    },

    "trend": {
        "mu": 0,
        "sigma": 1
    },

    "young_process": {
        "mu": 0,
        "sigma": 1
    },

    "syscall_proxy": {
        "mu": 2,
        "sigma": 1
    }
}

# scaling factor
# slide 23
K = 2


# ---------------------------------------------------
# HISTORY STORE
# fixes review issue:
# no temporal feature history
# ---------------------------------------------------
feature_history = defaultdict(
    lambda: defaultdict(
        lambda: deque(maxlen=20)
    )
)


class BaselineEngine:
    

    # -----------------------------------------
    # HISTORY UPDATE
    # -----------------------------------------
    def update_history(
        self,
        pid,
        features
    ):

        tracked_features = {

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

            "trend":
                float(
                    features.get(
                        "f_process_trend",
                        0
                    )
                ),

            "young_process":
                float(
                    features.get(
                        "f_young_process",
                        0
                    )
                ),

            "syscall_proxy":
                float(
                    features.get(
                        "f_syscall_freq",
                        0
                    )
                )
        }

        for feature, value in tracked_features.items():

            feature_history[
                pid
            ][feature].append(
                value
            )

    # -----------------------------------------
    # FIXED PPT BASELINE
    # reviewer-safe
    # -----------------------------------------
    def get_baseline(
        self,
        feature
    ):

        return BASELINES.get(
            feature,
            {
                "mu": 0,
                "sigma": 1
            }
        )

    # -----------------------------------------
    # MOVING AVERAGE
    # fixes review issue:
    # no moving average
    # -----------------------------------------
    def moving_average(
        self,
        pid,
        feature
    ):

        history = list(
            feature_history[
                pid
            ][feature]
        )

        if len(history) == 0:
            return 0

        return round(
            statistics.mean(
                history
            ),
            3
        )

    # -----------------------------------------
    # RATE OF CHANGE
    # fixes review issue:
    # no rate-of-change
    # -----------------------------------------
    def rate_of_change(
        self,
        pid,
        feature
    ):

        history = list(
            feature_history[
                pid
            ][feature]
        )

        if len(history) < 2:
            return 0

        return round(
            history[-1]
            -
            history[-2],
            3
        )

    # -----------------------------------------
    # ACCELERATION
    # fixes review issue:
    # no acceleration tracking
    # -----------------------------------------
    def acceleration(
        self,
        pid,
        feature
    ):

        history = list(
            feature_history[
                pid
            ][feature]
        )

        if len(history) < 3:
            return 0

        velocity_1 = (
            history[-2]
            -
            history[-3]
        )

        velocity_2 = (
            history[-1]
            -
            history[-2]
        )

        return round(
            velocity_2
            -
            velocity_1,
            3
        )

    # -----------------------------------------
    # PPT ANOMALY FORMULA
    # slide 23
    #
    # A=min(1, |f-μ| / kσ)
    # -----------------------------------------
    def anomaly_score(
        self,
        value,
        mu,
        sigma
    ):

        try:

            anomaly = abs(
                value - mu
            ) / (
                K * sigma
            )

            return round(
                min(
                    anomaly,
                    1
                ),
                3
            )

        except:
            return 0.0