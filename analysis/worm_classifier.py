# analysis/worm_classifier.py

class WormClassifier:
    """
    PPT + review aligned
    worm classification engine

    Responsibilities:
    1. Compute worm likelihood
    2. Fuse trust + anomaly
    3. Statistical classification
    4. Severity estimation

    DOES NOT:
    - heal
    - terminate
    - update trust
    """

    def classify(
        self,
        features,
        anomaly_data,
        trust_state
    ):

        anomalies = anomaly_data[
            "anomalies"
        ]

        temporal = anomaly_data[
            "temporal"
        ]

        # -----------------------------------------
        # TRUST STATE
        # PPT PRIMARY SIGNAL
        # slide 24
        # -----------------------------------------
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

        # -----------------------------------------
        # ANOMALY SIGNAL
        # -----------------------------------------
        aggregate_anomaly = (
            anomalies.get(
                "aggregate",
                0
            )
        )

        # -----------------------------------------
        # ENTITY PROPAGATION SIGNAL
        # reviewer issue:
        # worm propagation
        # -----------------------------------------
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

        # -----------------------------------------
        # THREAD ABUSE
        # reviewer issue:
        # thread explosion
        # -----------------------------------------
        thread_signal = min(
            abs(
                features.get(
                    "f_thread_velocity",
                    0
                )
            )
            / 5,
            1
        )

        # -----------------------------------------
        # NETWORK SPREAD
        # reviewer issue:
        # scanning/lateral movement
        # -----------------------------------------
        network_signal = min(
            abs(
                features.get(
                    "f_connection_velocity",
                    0
                )
            )
            / 5,
            1
        )

        # -----------------------------------------
        # TEMPORAL INSTABILITY
        # review:
        # trend intelligence
        # -----------------------------------------
        temporal_signal = min(

            (
                abs(
                    temporal.get(
                        "cpu_acceleration",
                        0
                    )
                )

                +

                abs(
                    temporal.get(
                        "memory_acceleration",
                        0
                    )
                )
            )
            / 2,

            1
        )

        # -----------------------------------------
        # STATISTICAL FUSION
        #
        # trust is PRIMARY
        # anomaly is SECONDARY
        #
        # fixes review:
        # trust exists but
        # classification missing
        # -----------------------------------------
        worm_likelihood = round(

            (
                (
                    1
                    -
                    dynamic_trust
                )

                +

                (
                    1
                    -
                    final_trust
                )

                +

                aggregate_anomaly

                +

                propagation_signal

                +

                thread_signal

                +

                network_signal

                +

                temporal_signal
            )

            / 7,

            3
        )

        confidence = round(
            worm_likelihood * 100,
            2
        )

        # -----------------------------------------
        # PPT TRUST THRESHOLDS
        # slide 24
        # -----------------------------------------
        if dynamic_trust > 0.7:

            label = "normal"

            severity = "low"

        elif (
            0.4
            <
            dynamic_trust
            <=
            0.7
        ):

            label = "suspicious"

            severity = "medium"

        else:

            # critical trust
            # propagation-aware classification

            if (
                propagation_signal > 0
                or
                network_signal > 0
                or
                thread_signal > 0
            ):

                label = "worm"
                severity = "critical"

            else:

                label = "anomalous"
                severity = "high"

        # -----------------------------------------
        # OUTPUT
        # -----------------------------------------
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
                )
        }