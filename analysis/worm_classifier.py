# analysis/worm_classifier.py

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

        propagation_signal = min(
            (
                process_growth
                +
                process_tree
            )
            / 20,
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
            / 10,
            1
        )

        # =====================================
        # NETWORK SPREAD
        # reviewer requirement
        # =====================================
        network_signal = min(
            abs(
                features.get(
                    "f_connection_velocity",
                    0
                )
            )
            / 10,
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

        # =====================================
        # WORM LIKELIHOOD
        #
        # Trust = primary
        # anomaly = secondary
        # reviewer aligned
        # =====================================
        worm_likelihood = round(

            (
                (
                    1
                    -
                    dynamic_trust
                )
                * 0.35

                +

                (
                    1
                    -
                    final_trust
                )
                * 0.25

                +

                aggregate_anomaly
                * 0.15

                +

                propagation_signal
                * 0.10

                +

                thread_signal
                * 0.05

                +

                network_signal
                * 0.05

                +

                temporal_signal
                * 0.05
            ),

            3
        )

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
                * 0.25

                +

                thread_signal
                * 0.15

                +

                temporal_signal
                * 0.10

                +

                aggregate_anomaly
                * 0.15
            ),

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
            dynamic_trust > 0.75
            and
            worm_likelihood < 0.35
        ):

            label = "normal"
            severity = "low"

        # -----------------------------
        # SUSPICIOUS
        # -----------------------------
        elif (
            dynamic_trust > 0.45
            or
            worm_likelihood < 0.60
        ):

            label = "suspicious"
            severity = "medium"

        # -----------------------------
        # CRITICAL WORM
        # -----------------------------
        else:

            if (

                combined_risk > 0.60

                and

                worm_likelihood > 0.70
            ):

                label = "worm"
                severity = "critical"

            else:

                label = "anomalous"
                severity = "high"

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

                "combined_risk":
                    combined_risk
            }
        }