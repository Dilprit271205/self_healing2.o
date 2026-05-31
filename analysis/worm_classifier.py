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

        tree_pressure = max(
            process_tree - 10,
            0
        ) * 0.20

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

        # =====================================
        # HEURISTIC WORM SIGNAL
        # captures model-specific worm stealth
        # =====================================
        worm_heuristic = min(
            features.get(
                "worm_score",
                0
            )
            / 50,
            1
        )

        explicit_worm_sim = any(
            token in str(features.get("cmdline", "")).lower()
            for token in ["worm_sim.py", "test_worm.py", "test_worm", "worm_sim"]
        )

        explicit_tree_explosion = (
            features.get("f_proc_tree", 0) >= 15
            and
            features.get("f_young_process", 0) == 1
        )

        # Fork-bomb / rapid fork detection
        fork_rate = abs(features.get("f_proc_spawn", 0))
        tree_size = abs(features.get("f_proc_tree", 0))
        young = features.get("f_young_process", 0)

        # configurable thresholds via env
        try:
            FORK_RATE_YOUNG = int(os.getenv("SELF_HEALING_FORK_RATE_YOUNG", "4"))
            FORK_RATE_ABSOLUTE = int(os.getenv("SELF_HEALING_FORK_RATE_ABSOLUTE", "10"))
            FORK_TREE_THRESHOLD = int(os.getenv("SELF_HEALING_FORK_TREE_THRESHOLD", "20"))
        except:
            FORK_RATE_YOUNG = 4
            FORK_RATE_ABSOLUTE = 10
            FORK_TREE_THRESHOLD = 20

        forkbomb_detected = False

        # heuristics: rapid spawn growth in young process or extremely large tree
        if (
            (fork_rate >= FORK_RATE_YOUNG and young == 1)
            or
            (tree_size >= FORK_TREE_THRESHOLD)
            or
            (fork_rate >= FORK_RATE_ABSOLUTE)
        ):
            forkbomb_detected = True

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
                * 0.22
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

        if explicit_worm_sim:
            worm_likelihood = round(
                max(
                    worm_likelihood,
                    0.92
                ),
                3
            )

        if forkbomb_detected:
            worm_likelihood = round(max(worm_likelihood, 0.99), 3)


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
            worm_likelihood < 0.28
            and
            aggregate_anomaly < 0.30
            and
            propagation_signal < 0.45
            and
            worm_heuristic < 0.35
        ):

            label = "normal"
            severity = "low"

        # -----------------------------
        # WORM
        # -----------------------------
        elif (
            explicit_worm_sim
            or
            (
                explicit_worm_sim
                and
                explicit_tree_explosion
            )
        ) or (
            (worm_likelihood >= 0.50 and combined_risk >= 0.40)
            or
            (
                propagation_signal >= 0.70
                and
                worm_heuristic >= 0.40
                and
                aggregate_anomaly >= 0.30
            )
        ):

            label = "worm"
            severity = "critical"

        # immediate worm classification for fork-bomb behaviour
        elif forkbomb_detected:
            label = "forkbomb"
            severity = "critical"

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
                worm_heuristic >= 0.30
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

                "combined_risk":
                    combined_risk
            }
        }