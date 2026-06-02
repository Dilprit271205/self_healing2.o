# analysis/baseline_engine.py

from collections import (
    defaultdict,
    deque
)

import statistics
import os


# ===================================================
# REALISTIC KALI / LINUX BASELINES
# PPT + REVIEW ALIGNED
# slide 23
# ===================================================

BASELINES = {

    # -----------------------------------------
    # PER-PROCESS NORMALS
    # tuned for typical benign Linux processes
    # -----------------------------------------

    "cpu": {
        "mu": 5.0,
        "sigma": 15.0
    },

    "memory": {
        "mu": 3.0,
        "sigma": 8.0
    },

    "threads": {
        "mu": 8,
        "sigma": 16
    },

    "connections": {
        "mu": 2.0,
        "sigma": 4.0
    },

    "file_events": {
        "mu": 15.0,
        "sigma": 35.0
    },

    # -----------------------------------------
    # WORM FEATURES
    # reviewer required
    # -----------------------------------------

    "spawn": {
        "mu": 0,
        "sigma": 1
    },

    "tree": {
        "mu": 3,
        "sigma": 5
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
        "mu": 4,
        "sigma": 3
    },

    "remote_ips": {
        "mu": 2,
        "sigma": 4
    },

    "child_similarity": {
        "mu": 0.25,
        "sigma": 0.30
    }
}


# ===================================================
# PPT SCALING FACTOR
#
# A = min(1, |f-μ| / kσ)
#
# lower K = more sensitive to normal deviations
# higher K = more tolerant
# ===================================================

try:
    K = float(
        os.getenv(
            "SELF_HEALING_BASELINE_K",
            "4.0"
        )
    )
except Exception:
    K = 4.0

BASELINE_LEARNING_LIMITS = {
    "cpu": 75,
    "memory": 45,
    "threads": 90,
    "connections": 60,
    "file_events": 120,
    "spawn": 8,
    "tree": 40,
    "trend": 30,
    "young_process": 1,
    "syscall_proxy": 140,
    "remote_ips": 20,
    "child_similarity": 0.95
}


# ===================================================
# HISTORY STORE
#
# reviewer fix:
# temporal feature history
# ===================================================

feature_history = defaultdict(

    lambda: defaultdict(

        lambda: deque(
            maxlen=20
        )
    )
)

global_feature_history = defaultdict(
    lambda: deque(
        maxlen=500
    )
)


class BaselineEngine:

    # ===================================================
    # HISTORY UPDATE
    # ===================================================
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

        for feature, value in tracked_features.items():

            feature_history[
                pid
            ][feature].append(
                value
            )

            limit = BASELINE_LEARNING_LIMITS.get(
                feature
            )

            if (
                limit is None
                or value <= limit
            ):
                global_feature_history[
                    feature
                ].append(
                    value
                )

    # ===================================================
    # BASELINE LOOKUP
    # ===================================================
    def get_baseline(

        self,
        feature
    ):

        static = BASELINES.get(

            feature,

            {
                "mu": 0,
                "sigma": 1
            }
        )

        history = list(
            global_feature_history[
                feature
            ]
        )

        if len(history) < 30:
            return static

        try:
            mu = statistics.median(
                history
            )
            sigma = statistics.pstdev(
                history
            )

            sigma = max(
                sigma,
                static.get(
                    "sigma",
                    1
                )
            )

            mu = max(
                mu,
                static.get(
                    "mu",
                    0
                )
            )

            return {
                "mu": round(
                    mu,
                    3
                ),
                "sigma": round(
                    sigma,
                    3
                )
            }

        except Exception:
            return static

    # ===================================================
    # MOVING AVERAGE
    #
    # reviewer requirement
    # ===================================================
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

        if not history:
            return 0

        return round(

            statistics.mean(
                history
            ),

            3
        )

    # ===================================================
    # RATE OF CHANGE
    #
    # reviewer requirement
    # ===================================================
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

    # ===================================================
    # ACCELERATION
    #
    # reviewer requirement
    # ===================================================
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

    # ===================================================
    # PPT ANOMALY FORMULA
    #
    # slide 23
    #
    # A=min(1, |f-μ| / kσ)
    #
    # reviewer-safe
    # stable
    # ===================================================
    def anomaly_score(

        self,
        feature,
        value,
        mu,
        sigma
    ):

        try:

            if sigma <= 0:
                sigma = 1

            # Avoid penalizing quiet benign behavior.
            # Only above-normal activity should drive trust loss for most process metrics.
            if value <= mu:
                return 0.0

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

        except Exception:

            return 0.0
