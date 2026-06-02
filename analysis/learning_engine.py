# analysis/learning_engine.py

from collections import (
    defaultdict,
    deque
)

import hashlib


class LearningEngine:
    """
    PPT + review aligned
    adaptive learning engine

    Slide 17–18

    Purpose:
    Learn from healing outcomes
    and adapt future responses.

    Responsibilities:
    1. Feedback loop
    2. False positive reduction
    3. Adaptive escalation
    4. Trust recovery learning
    5. Behavioral memory
    """

    def __init__(self):

        # -----------------------------------------
        # historical outcomes
        # -----------------------------------------
        self.learning_memory = (
            defaultdict(
                lambda: deque(
                    maxlen=20
                )
            )
        )

        # -----------------------------------------
        # process reputation
        # normalized trust
        # -----------------------------------------
        self.process_reputation = (
            defaultdict(
                lambda: 0.5
            )
        )

    # -----------------------------------------
    # SAFE PROCESS IDENTITY
    # prevents spoofing
    # -----------------------------------------
    def get_process_identity(
        self,
        process_info
    ):

        process_name = (
            process_info.get(
                "name",
                "unknown"
            )
        )

        exe_path = (
            process_info.get(
                "exe",
                "unknown"
            )
        )

        identity = (
            f"{process_name}|"
            f"{exe_path}"
        )

        return hashlib.md5(
            identity.encode()
        ).hexdigest()

    # -----------------------------------------
    # STORE OUTCOME
    # -----------------------------------------
    def update(
        self,
        pid,
        process_info,
        classification,
        response_result,
        trust_state
    ):

        process_id = (
            self.get_process_identity(
                process_info
            )
        )

        label = classification.get(
            "label",
            "normal"
        )

        severity = (
            classification.get(
                "severity",
                "low"
            )
        )

        worm_score = (
            classification.get(
                "worm_score",
                0
            )
        )

        final_trust = (
            trust_state.get(
                "final_trust",
                1.0
            )
        )

        dynamic_trust = (
            trust_state.get(
                "dynamic_trust",
                1.0
            )
        )

        stage = response_result.get(
            "stage",
            "observe"
        )

        action_taken = (
            response_result.get(
                "action_taken",
                False
            )
        )

        # -----------------------------------------
        # HEALING SUCCESS
        #
        # PPT TRUST MODEL
        # slide 24
        #
        # no hardcoded thresholds
        # -----------------------------------------
        healing_success = (

            label == "normal"

            and

            dynamic_trust
            >
            final_trust

            and

            severity
            in [
                "low",
                "medium"
            ]
        )

        # -----------------------------------------
        # STORE EXPERIENCE
        # -----------------------------------------
        self.learning_memory[
            process_id
        ].append({

            "label":
                label,

            "severity":
                severity,

            "worm_score":
                worm_score,

            "stage":
                stage,

            "trust":
                final_trust,

            "dynamic_trust":
                dynamic_trust,

            "action_taken":
                action_taken,

            "success":
                healing_success
        })

        # -----------------------------------------
        # TRUST-BASED REPUTATION
        # -----------------------------------------
        history = list(
            self.learning_memory[
                process_id
            ]
        )

        if len(history):

            trust_average = (

                sum(
                    h["trust"]
                    for h in history
                )

                /

                len(history)
            )

            success_rate = (

                sum(
                    1
                    for h in history
                    if h["success"]
                )

                /

                len(history)
            )

            reputation = round(

                (
                    trust_average
                    +
                    success_rate
                )

                / 2,

                3
            )

            self.process_reputation[
                process_id
            ] = reputation

    # -----------------------------------------
    # RESPONSE ADAPTATION
    # slide 18
    # -----------------------------------------
    def recommend_stage(
        self,
        process_info,
        persistence_stage
    ):

        process_id = (
            self.get_process_identity(
                process_info
            )
        )

        reputation = (
            self.process_reputation[
                process_id
            ]
        )

        # -----------------------------------------
        # TRUST-DRIVEN ADAPTATION
        # PPT thresholds
        # -----------------------------------------
        if reputation > 0.7:

            downgrade_map = {

                "terminate":
                    "quarantine",

                "quarantine":
                    "throttle",

                "block_resources":
                    "quarantine",

                "isolate":
                    "throttle",

                "restrict":
                    "observe",

                "throttle":
                    "observe"
            }

            return downgrade_map.get(
                persistence_stage,
                persistence_stage
            )

        elif (
            0.4
            <
            reputation
            <=
            0.7
        ):

            return persistence_stage

        else:

            upgrade_map = {

                "observe":
                    "throttle",

                "restrict":
                    "quarantine",

                "throttle":
                    "quarantine",

                "isolate":
                    (
                        "quarantine"
                    ),

                "block_resources":
                    "terminate",

                "quarantine":
                    "terminate"
            }

            return upgrade_map.get(
                persistence_stage,
                persistence_stage
            )

    # -----------------------------------------
    # LEARNING SUMMARY
    # -----------------------------------------
    def get_learning_state(
        self,
        process_info
    ):

        process_id = (
            self.get_process_identity(
                process_info
            )
        )

        reputation = (
            self.process_reputation.get(
                process_id,
                0.5
            )
        )

        # PPT trust ranges
        if reputation > 0.7:

            level = "trusted"

        elif (
            0.4
            <
            reputation
            <=
            0.7
        ):

            level = "uncertain"

        else:

            level = "risky"

        return {

            "identity":
                process_id,

            "reputation":
                reputation,

            "trust_level":
                level
        }
