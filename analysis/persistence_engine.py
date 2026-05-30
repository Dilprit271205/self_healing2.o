# analysis/persistence_engine.py

import time
from collections import (
    defaultdict,
    deque
)


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
        self.delta = 3

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
                final_trust
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

        if avg_dynamic_trust > 0.7:

            stage = "observe"

        elif 0.4 < avg_dynamic_trust <= 0.7:

            if avg_worm_score < 0.5:
                stage = "restrict"
            else:
                stage = "isolate"

        else:

            # critical trust collapse
            if avg_severity < 0.8:
                stage = "block_resources"
            else:
                stage = "terminate"

        # If the worm classifier is strongly confident, escalate to
        # termination even if trust has not completely collapsed.
        if (
            avg_worm_score >= 0.7
            and
            avg_severity >= 0.8
            and
            persistent
        ):
            stage = "terminate"

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
                avg_final_trust
        }