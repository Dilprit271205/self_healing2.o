# analysis/learning_engine.py

from collections import (
    defaultdict,
    deque
)

import hashlib
import json
import os
import time


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

        self.kb_path = os.getenv(
            "SELF_HEALING_KB_PATH",
            os.path.join(
                "logs",
                "learning_kb.json"
            )
        )

        self.knowledge_base = self._load_knowledge_base()

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

    def _load_knowledge_base(self):
        try:
            with open(
                self.kb_path,
                "r",
                encoding="utf-8"
            ) as handle:
                loaded = json.load(handle)

            if isinstance(
                loaded,
                dict
            ):
                return loaded

        except Exception:
            pass

        return {}

    def _save_knowledge_base(self):
        try:
            os.makedirs(
                os.path.dirname(
                    self.kb_path
                ),
                exist_ok=True
            )

            tmp_path = (
                self.kb_path
                + ".tmp"
            )

            with open(
                tmp_path,
                "w",
                encoding="utf-8"
            ) as handle:
                json.dump(
                    self.knowledge_base,
                    handle,
                    indent=2,
                    sort_keys=True,
                    default=str
                )

            os.replace(
                tmp_path,
                self.kb_path
            )

        except Exception:
            pass

    def _active_signals(
        self,
        classification
    ):
        signals = (
            classification.get(
                "signals",
                {}
            )
            or {}
        )

        correlated = (
            signals.get(
                "correlated_signals",
                {}
            )
            or {}
        )

        return sorted(
            name
            for name, active in correlated.items()
            if active
        )

    def _attack_family(
        self,
        active_signals,
        classification
    ):
        signals = classification.get(
            "signals",
            {}
        ) or {}

        if signals.get(
            "forkbomb_detected"
        ):
            return "process_storm"

        if signals.get(
            "worm_like_behavior"
        ):
            return "correlated_worm_behavior"

        if signals.get(
            "trust_anomaly_pattern"
        ):
            return "trust_score_anomaly"

        if signals.get(
            "replication_detected"
        ):
            if "suspicious_rename" in active_signals:
                return "ransomware_like_file_rename"
            return "file_replication"

        if signals.get(
            "fanout_detected"
        ):
            return "network_beacon_or_fanout"

        if signals.get(
            "artifact_abuse_detected"
        ):
            return "persistence_or_sensitive_access"

        if signals.get(
            "thread_storm_detected"
        ):
            return "thread_storm"

        if "resource_pressure" in active_signals:
            return "resource_pressure"

        return classification.get(
            "label",
            "normal"
        )

    def _pattern_key(
        self,
        process_info,
        classification
    ):
        active = self._active_signals(
            classification
        )

        family = self._attack_family(
            active,
            classification
        )

        category = str(
            process_info.get(
                "process_category",
                process_info.get(
                    "category",
                    ""
                )
            )
            or
            ""
        )

        if not category:
            try:
                from analysis.policy_engine import policy_engine

                category = policy_engine.infer_category(
                    process_info
                )
            except Exception:
                category = "unknown"

        material = "|".join([
            family,
            classification.get(
                "label",
                "normal"
            ),
            category,
            ",".join(
                active[:8]
            )
        ])

        digest = hashlib.sha256(
            material.encode(
                "utf-8",
                errors="ignore"
            )
        ).hexdigest()[:16]

        return digest, family, active, category

    def _merge_evidence(
        self,
        existing,
        active_signals
    ):
        evidence = set(
            existing.get(
                "evidence",
                []
            )
        )

        evidence.update(
            active_signals
        )

        return sorted(
            evidence
        )

    def recommend_from_knowledge(
        self,
        process_info,
        classification,
        persistence_stage
    ):
        key, family, active, category = self._pattern_key(
            process_info,
            classification
        )

        entry = self.knowledge_base.get(
            key
        )

        if not entry:
            entry = self._best_similar_pattern(
                family=family,
                active_signals=active,
                category=category,
                disposition=None
            )

        if not entry:
            return persistence_stage

        confidence = float(
            entry.get(
                "confidence",
                0
            )
        )

        recommended = entry.get(
            "recommended_stage",
            persistence_stage
        )

        disposition = entry.get(
            "disposition",
            "unknown"
        )

        if disposition == "false_positive":
            return "observe"

        if (
            disposition == "malicious"
            and confidence >= 0.50
        ):
            return self._more_severe_stage(
                persistence_stage,
                recommended
            )

        return persistence_stage

    def _best_similar_pattern(
        self,
        family,
        active_signals,
        category,
        disposition="malicious"
    ):
        active = set(
            active_signals
            or []
        )
        best_entry = None
        best_score = 0.0

        for entry in self.knowledge_base.values():
            if not isinstance(
                entry,
                dict
            ):
                continue

            entry_disposition = entry.get(
                "disposition"
            )

            if (
                disposition is not None
                and entry_disposition != disposition
            ):
                continue

            if entry.get(
                "attack_family"
            ) != family:
                continue

            evidence = set(
                entry.get(
                    "evidence",
                    []
                )
                or []
            )

            if active or evidence:
                overlap = (
                    len(active & evidence)
                    /
                    max(
                        len(active | evidence),
                        1
                    )
                )
            else:
                overlap = 0.0

            category_score = (
                1.0
                if entry.get(
                    "process_category",
                    "unknown"
                )
                in {
                    category,
                    "unknown",
                    ""
                }
                else 0.45
            )

            confidence = float(
                entry.get(
                    "confidence",
                    0
                )
                or 0
            )

            observations = min(
                float(
                    entry.get(
                        "observations",
                        0
                    )
                    or 0
                )
                / 3,
                1.0
            )

            score = (
                overlap * 0.55
                + category_score * 0.15
                + confidence * 0.20
                + observations * 0.10
            )

            min_overlap = (
                0.35
                if entry_disposition == "false_positive"
                else 0.45
            )

            if (
                overlap >= min_overlap
                and score > best_score
            ):
                best_score = score
                best_entry = entry

        return best_entry

    def _stage_rank(self, stage):
        order = {
            "observe": 0,
            "restrict": 1,
            "throttle": 1,
            "isolate": 2,
            "quarantine": 2,
            "block_resources": 3,
            "terminate": 4
        }

        return order.get(
            stage,
            0
        )

    def _more_severe_stage(
        self,
        current,
        learned
    ):
        if self._stage_rank(
            learned
        ) > self._stage_rank(
            current
        ):
            return learned

        return current

    def update_knowledge_base(
        self,
        process_info,
        classification,
        response_result,
        trust_state,
        features=None
    ):
        features = features or {}
        feature_category = features.get(
            "process_category",
            ""
        )

        key, family, active_signals, category = self._pattern_key(
            {
                **process_info,
                "process_category": feature_category
            },
            classification
        )

        now = int(
            time.time()
        )

        entry = self.knowledge_base.get(
            key,
            {
                "pattern_id": key,
                "attack_family": family,
                "process_category": category,
                "observations": 0,
                "action_count": 0,
                "false_positive_count": 0,
                "first_seen": now,
                "last_seen": now,
                "confidence": 0.5,
                "recommended_stage": "observe",
                "disposition": "unknown",
                "evidence": [],
                "pattern_strength_total": 0.0,
                "avg_pattern_strength": 0.0,
                "avg_trust_anomaly_pressure": 0.0,
                "avg_trust_drop_risk": 0.0
            }
        )

        action_taken = bool(
            response_result.get(
                "action_taken",
                False
            )
        )

        stage = response_result.get(
            "stage",
            "observe"
        )

        label = classification.get(
            "label",
            "normal"
        )

        severity = classification.get(
            "severity",
            "low"
        )

        signals = classification.get(
            "signals",
            {}
        ) or {}

        pattern_strength = max(
            float(
                features.get(
                    "behavior_correlation_score",
                    0
                )
                or
                0
            ),
            float(
                features.get(
                    "worm_pattern_anomaly",
                    0
                )
                or
                0
            ),
            float(
                signals.get(
                    "ml_anomaly_probability",
                    0
                )
                or
                0
            ),
            min(
                1.0,
                len(active_signals) / 6
            )
        )

        trust_anomaly_pressure = float(
            trust_state.get(
                "trust_anomaly_pressure",
                features.get(
                    "trust_anomaly_pressure",
                    0
                )
            )
            or
            0
        )

        trust_drop_risk = max(
            0.0,
            float(
                trust_state.get(
                    "static_trust",
                    features.get(
                        "static_trust",
                        1.0
                    )
                )
                or
                1.0
            )
            -
            float(
                trust_state.get(
                    "dynamic_trust",
                    features.get(
                        "dynamic_trust",
                        1.0
                    )
                )
                or
                1.0
            )
        )

        suppressed_or_protected = (
            stage in {
                "observe",
                "protected"
            }
            and label in {
                "normal",
                "suspicious"
            }
        )

        entry[
            "observations"
        ] += 1
        entry[
            "last_seen"
        ] = now
        entry[
            "last_label"
        ] = label
        entry[
            "last_severity"
        ] = severity
        entry[
            "last_stage"
        ] = stage
        entry[
            "last_process_name"
        ] = process_info.get(
            "name",
            "unknown"
        )
        entry[
            "last_pid"
        ] = process_info.get(
            "pid"
        )
        entry[
            "evidence"
        ] = self._merge_evidence(
            entry,
            active_signals
        )

        if action_taken:
            entry[
                "action_count"
            ] += 1

        if suppressed_or_protected:
            entry[
                "false_positive_count"
            ] += 1

        observations = max(
            entry[
                "observations"
            ],
            1
        )

        entry[
            "pattern_strength_total"
        ] = round(
            float(
                entry.get(
                    "pattern_strength_total",
                    0
                )
            )
            + pattern_strength,
            4
        )

        entry[
            "trust_anomaly_pressure_total"
        ] = round(
            float(
                entry.get(
                    "trust_anomaly_pressure_total",
                    0
                )
            )
            + trust_anomaly_pressure,
            4
        )

        entry[
            "trust_drop_risk_total"
        ] = round(
            float(
                entry.get(
                    "trust_drop_risk_total",
                    0
                )
            )
            + trust_drop_risk,
            4
        )

        entry[
            "avg_pattern_strength"
        ] = round(
            entry["pattern_strength_total"] / observations,
            3
        )

        entry[
            "avg_trust_anomaly_pressure"
        ] = round(
            entry["trust_anomaly_pressure_total"] / observations,
            3
        )

        entry[
            "avg_trust_drop_risk"
        ] = round(
            entry["trust_drop_risk_total"] / observations,
            3
        )

        action_rate = (
            entry[
                "action_count"
            ]
            /
            observations
        )

        false_positive_rate = (
            entry[
                "false_positive_count"
            ]
            /
            observations
        )

        risk_signal = max(
            float(
                classification.get(
                    "worm_score",
                    0
                )
            ),
            float(
                classification.get(
                    "confidence",
                    0
                )
            )
            /
            100
        )

        confidence = (
            risk_signal * 0.50
            + action_rate * 0.25
            + min(
                observations / 4,
                1
            ) * 0.15
            + entry["avg_pattern_strength"] * 0.25
            + entry["avg_trust_anomaly_pressure"] * 0.20
            + entry["avg_trust_drop_risk"] * 0.10
            - false_positive_rate * 0.45
        )

        confidence = max(
            0,
            min(
                1,
                confidence
            )
        )

        entry[
            "confidence"
        ] = round(
            confidence,
            3
        )

        if false_positive_rate >= 0.5:
            entry[
                "disposition"
            ] = "false_positive"
            entry[
                "recommended_stage"
            ] = "observe"
        elif label in {
            "worm",
            "forkbomb"
        } or severity in {
            "high",
            "critical"
        }:
            entry[
                "disposition"
            ] = "malicious"

            if family in {
                "process_storm",
                "file_replication",
                "ransomware_like_file_rename",
                "correlated_worm_behavior"
            } and confidence >= 0.62:
                entry[
                    "recommended_stage"
                ] = "terminate"
            elif (
                family == "trust_score_anomaly"
                and confidence >= 0.65
            ):
                entry[
                    "recommended_stage"
                ] = "quarantine"
            elif confidence >= 0.50:
                entry[
                    "recommended_stage"
                ] = "quarantine"
            else:
                entry[
                    "recommended_stage"
                ] = "throttle"
        else:
            entry[
                "disposition"
            ] = "unknown"
            entry[
                "recommended_stage"
            ] = "observe"

        entry[
            "summary"
        ] = self._knowledge_summary(
            entry
        )

        self.knowledge_base[
            key
        ] = entry
        self._save_knowledge_base()

        return entry

    def _knowledge_summary(
        self,
        entry
    ):
        family = entry.get(
            "attack_family",
            "behavior"
        ).replace(
            "_",
            " "
        )

        evidence = ", ".join(
            entry.get(
                "evidence",
                []
            )[:4]
        )

        disposition = entry.get(
            "disposition",
            "unknown"
        )

        if disposition == "false_positive":
            return (
                f"Learned to suppress {family} pattern; "
                f"evidence: {evidence or 'low-risk runtime behavior'}."
            )

        if disposition == "malicious":
            return (
                f"Learned {family} attack pattern; "
                f"evidence: {evidence or 'correlated anomalous behavior'}."
            )

        return (
            f"Tracking {family} behavior; "
            f"evidence: {evidence or 'insufficient repeated evidence'}."
        )

    # -----------------------------------------
    # STORE OUTCOME
    # -----------------------------------------
    def update(
        self,
        pid,
        process_info,
        classification,
        response_result,
        trust_state,
        features=None
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

        kb_entry = self.update_knowledge_base(
            process_info=process_info,
            classification=classification,
            response_result=response_result,
            trust_state=trust_state,
            features=features
        )

        return kb_entry

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
                level,

            "knowledge_patterns":
                len(
                    self.knowledge_base
                )
        }
