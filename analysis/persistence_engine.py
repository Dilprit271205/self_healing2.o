# analysis/persistence_engine.py

import time
import os
from collections import (
    defaultdict,
    deque
)
import os
from analysis.policy_engine import policy_engine


class PersistenceEngine:
    """
    PPT + review aligned
    persistence engine

    Slide 15–16

    Purpose:
    Verify anomaly persistence
    before adaptive healing.

    Healing Flow:
    observe
    → restrict
    → isolate
    → block_resources
    → terminate
    """

    def __init__(self):

        # -----------------------------------------
        # rolling behavioral history
        # -----------------------------------------
        self.history = defaultdict(
            lambda: deque(maxlen=10)
        )

        # -----------------------------------------
        # persistence window δ
        # slide 15
        # -----------------------------------------
        # default delta (entries required to evaluate persistence)
        self.delta = policy_engine.get(
            "persistence.default_loops",
            2
        )

        # allow override from environment for tuning
        try:
            env_delta = int(os.getenv(
                "SELF_HEALING_PERSISTENCE_DELTA",
                str(policy_engine.get("persistence.default_loops", 3))
            ))
            if env_delta >= 1:
                self.delta = env_delta
        except:
            pass

    # -----------------------------------------
    # UPDATE HISTORY
    # -----------------------------------------
    def update(
        self,
        pid,
        classification,
        trust_state
    ):

        timestamp = time.time()

        label = classification.get(
            "label",
            "normal"
        )

        severity = classification.get(
            "severity",
            "low"
        )

        worm_score = classification.get(
            "worm_score",
            0
        )

        confidence = classification.get(
            "confidence",
            0
        ) / 100

        signals = classification.get(
            "signals",
            {}
        )

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

        self.history[pid].append({

            "timestamp":
                timestamp,

            "label":
                label,

            "severity":
                severity,

            "worm_score":
                worm_score,

            "dynamic_trust":
                dynamic_trust,

            "final_trust":
                final_trust,

            "confidence":
                confidence,

            "combined_risk":
                signals.get("combined_risk", 0),

            "correlated_signal_count":
                signals.get("correlated_signal_count", 0),

            "catastrophic_behavior":
                signals.get("catastrophic_behavior", False),

            "category_suppressed":
                signals.get("category_suppressed", False)
        })

    # -----------------------------------------
    # PERSISTENCE CHECK
    # slide 15
    # -----------------------------------------
    def check_persistence(
        self,
        pid
    ):

        history = self.history.get(
            pid,
            []
        )

        if history:
            latest = history[-1]
            if (
                latest.get("catastrophic_behavior", False)
                and latest.get("combined_risk", 0) >= 0.94
                and latest.get("confidence", 0) >= 0.90
                and latest.get("correlated_signal_count", 0) >= 4
            ):
                return {
                    "persistent": True,
                    "confidence": latest.get("confidence", 0),
                    "stage": "terminate",
                    "avg_worm_score": latest.get("worm_score", 0),
                    "avg_dynamic_trust": latest.get("dynamic_trust", 1.0),
                    "avg_final_trust": latest.get("final_trust", 1.0),
                    "avg_confidence": latest.get("confidence", 0),
                    "avg_combined_risk": latest.get("combined_risk", 0),
                    "avg_correlated_signals": latest.get(
                        "correlated_signal_count",
                        0
                    ),
                    "termination_ready": True,
                    "catastrophic_ready": True
                }

        # -----------------------------------------
        # insufficient evidence
        # -----------------------------------------
        if len(history) < self.delta:

            return {

                "persistent":
                    False,

                "confidence":
                    0,

                "stage":
                    "observe"
            }

        recent = list(
            history
        )[-self.delta:]

        # -----------------------------------------
        # PERSISTENT SIGNALS
        # -----------------------------------------
        suspicious_count = sum(

            1

            for x in recent

            if x["label"]
            in [
                "worm",
                "forkbomb",
                "suspicious",
                "anomalous"
            ]
        )

        # -----------------------------------------
        # WORM SCORE TREND
        # -----------------------------------------
        avg_worm_score = round(

            sum(
                x["worm_score"]
                for x in recent
            )

            / self.delta,

            3
        )

        # Exponential moving average smoothing for worm score to reduce
        # sensitivity to single spikes. Configurable via env var.
        try:
            ema_alpha = float(os.getenv("SELF_HEALING_EMA_ALPHA", "0.6"))
            ema_alpha = max(0.01, min(0.99, ema_alpha))
        except:
            ema_alpha = 0.6

        ema = None
        for x in recent:
            if ema is None:
                ema = x["worm_score"]
            else:
                ema = ema_alpha * x["worm_score"] + (1 - ema_alpha) * ema

        ema_worm_score = round(ema if ema is not None else avg_worm_score, 3)

        # -----------------------------------------
        # TRUST COLLAPSE
        # slide 24
        # -----------------------------------------
        avg_dynamic_trust = round(

            sum(
                x[
                    "dynamic_trust"
                ]
                for x in recent
            )

            / self.delta,

            3
        )

        avg_final_trust = round(

            sum(
                x[
                    "final_trust"
                ]
                for x in recent
            )

            / self.delta,

            3
        )

        # -----------------------------------------
        # SEVERITY TREND
        # -----------------------------------------
        severity_score = {

            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0
        }

        avg_severity = round(

            sum(
                severity_score.get(
                    x["severity"],
                    0
                )
                for x in recent
            )

            / self.delta,

            3
        )

        worm_count = sum(
            1
            for x in recent
            if x["label"] in {"worm", "forkbomb"}
        )

        avg_confidence = round(
            sum(x.get("confidence", 0) for x in recent) / self.delta,
            3
        )

        avg_combined_risk = round(
            sum(x.get("combined_risk", 0) for x in recent) / self.delta,
            3
        )

        avg_correlated_signals = round(
            sum(x.get("correlated_signal_count", 0) for x in recent)
            / self.delta,
            3
        )

        catastrophic_count = sum(
            1 for x in recent if x.get("catastrophic_behavior", False)
        )

        category_suppressed = any(
            x.get("category_suppressed", False)
            for x in recent
        )

        # -----------------------------------------
        # PERSISTENCE CONFIDENCE
        #
        # statistical fusion
        #
        # fixes:
        # confidence bug
        # severity ignored
        # trust persistence
        # -----------------------------------------
        confidence = round(

            (

                (
                    suspicious_count
                    /
                    self.delta
                )

                +

                avg_worm_score

                +

                (
                    1
                    -
                    avg_dynamic_trust
                )

                +

                (
                    1
                    -
                    avg_final_trust
                )

                +

                avg_severity

            )

            / 5,

            3
        )

        persistent = (
            confidence >= 0.45
        )

        
        # -----------------------------------------
        # PPT TRUST-GUIDED ESCALATION
        # slide 24 + slide 16
        # -----------------------------------------

        thresholds = policy_engine.response_thresholds()
        throttle = thresholds.get("throttle", {})
        quarantine = thresholds.get("quarantine", {})
        terminate = thresholds.get("terminate", {})
        catastrophic = thresholds.get("catastrophic_terminate", {})

        stage = "observe"

        if (
            persistent
            and avg_combined_risk >= throttle.get("risk", 0.45)
            and avg_confidence >= throttle.get("confidence", 0.40)
        ):
            stage = "throttle"

        if (
            persistent
            and avg_combined_risk >= quarantine.get("risk", 0.68)
            and avg_confidence >= quarantine.get("confidence", 0.62)
            and avg_correlated_signals >= 3
        ):
            stage = "quarantine"

        propagation_terminate_ready = (
            persistent
            and worm_count >= max(2, self.delta - 1)
            and avg_combined_risk >= 0.84
            and avg_confidence >= 0.78
            and avg_correlated_signals >= 3
        )

        high_confidence_terminate_ready = (
            persistent
            and worm_count >= max(2, self.delta - 1)
            and avg_combined_risk >= terminate.get("risk", 0.86)
            and avg_confidence >= terminate.get("confidence", 0.82)
            and avg_correlated_signals >= terminate.get("min_correlated_signals", 4)
        )

        terminate_ready = (
            propagation_terminate_ready
            or
            high_confidence_terminate_ready
        )

        catastrophic_ready = (
            catastrophic_count >= policy_engine.get(
                "persistence.catastrophic_loops",
                1
            )
            and avg_combined_risk >= catastrophic.get("risk", 0.94)
            and avg_confidence >= catastrophic.get("confidence", 0.90)
            and avg_correlated_signals >= catastrophic.get(
                "min_correlated_signals",
                5
            )
        )

        confirmed_catastrophic_ready = (
            persistent
            and catastrophic_count >= policy_engine.get(
                "persistence.catastrophic_loops",
                1
            )
            and worm_count >= max(2, self.delta - 1)
            and avg_worm_score >= 0.85
            and avg_correlated_signals >= 4
        )

        if (
            terminate_ready
            or catastrophic_ready
            or confirmed_catastrophic_ready
        ):
            stage = "terminate"

        if (
            category_suppressed
            and not terminate_ready
            and not catastrophic_ready
            and stage == "quarantine"
        ):
            stage = policy_engine.get(
                "false_positive_suppression.max_stage_without_confirmed_behavior",
                "throttle"
            )

        return {

            "persistent":
                persistent,

            "confidence":
                confidence,

            "stage":
                stage,

            "avg_worm_score":
                avg_worm_score,

            "avg_dynamic_trust":
                avg_dynamic_trust,

            "avg_final_trust":
                avg_final_trust,

            "avg_confidence":
                avg_confidence,

            "avg_combined_risk":
                avg_combined_risk,

            "avg_correlated_signals":
                avg_correlated_signals,

            "termination_ready":
                (
                    terminate_ready
                    or confirmed_catastrophic_ready
                ),

            "catastrophic_ready":
                (
                    catastrophic_ready
                    or confirmed_catastrophic_ready
                )
        }
