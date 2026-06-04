"""
Evidence-gated self-healing policy.

The detector/classifier can be aggressive; the healing policy should be
conservative. This module turns raw risk into a reversible response ladder:
observe -> throttle -> quarantine -> terminate -> trust_recovery.
"""

from analysis.policy_engine import policy_engine


DESTRUCTIVE_STAGE = "terminate"


def _truthy(value):
    return bool(value)


def _stage_rank(stage):
    return {
        "observe": 0,
        "trust_recovery": 0,
        "restrict": 1,
        "throttle": 1,
        "isolate": 2,
        "quarantine": 2,
        "block_resources": 3,
        "terminate": 4,
    }.get(stage, 0)


def _cap_stage(stage, max_stage):
    if _stage_rank(stage) <= _stage_rank(max_stage):
        return stage
    return max_stage


def _normalized_score(value):
    try:
        number = float(value or 0)
    except Exception:
        return 0.0
    if number > 1:
        number = number / 100.0
    return max(0.0, min(1.0, number))


def evidence_domains(classification=None, features=None, trust_state=None):
    classification = classification or {}
    features = features or {}
    trust_state = trust_state or {}
    signals = classification.get("signals", {}) or {}
    correlated = signals.get("correlated_signals", {}) or {}

    domains = set()

    if any(
        _truthy(correlated.get(name))
        for name in (
            "rapid_child_spawning",
            "large_or_growing_tree",
            "repeated_similar_children",
            "short_lived_recursive_children",
            "process_storm_burst",
        )
    ):
        domains.add("process")

    if any(
        _truthy(correlated.get(name))
        for name in (
            "file_replication",
            "high_file_velocity",
            "extreme_file_velocity",
            "mass_file_modification",
            "suspicious_rename",
            "low_slow_file_replication",
        )
    ) or _truthy(signals.get("replication_detected")):
        domains.add("file")

    if any(
        _truthy(correlated.get(name))
        for name in (
            "network_fanout",
            "localhost_beaconing",
        )
    ) or _truthy(signals.get("fanout_detected")):
        domains.add("network")

    if any(
        _truthy(correlated.get(name))
        for name in (
            "thread_explosion",
            "cpu_memory_escalation",
            "resource_pressure",
        )
    ) or _truthy(signals.get("thread_storm_detected")):
        domains.add("resource")

    if _truthy(correlated.get("persistence_artifact")):
        domains.add("persistence")

    if _truthy(correlated.get("sensitive_file_access")):
        domains.add("sensitive_access")

    trust_pressure = max(
        _normalized_score(features.get("trust_anomaly_pressure")),
        _normalized_score(trust_state.get("trust_anomaly_pressure")),
        1.0 - _normalized_score(trust_state.get("dynamic_trust", 1.0)),
    )
    if trust_pressure >= 0.45 or _truthy(signals.get("trust_anomaly_pattern")):
        domains.add("trust")

    if _truthy(signals.get("learned_behavior_pattern")) or _truthy(
        correlated.get("learned_pattern_fast_path")
    ):
        domains.add("learned")

    if _truthy(signals.get("catastrophic_behavior")) or _truthy(
        signals.get("forkbomb_detected")
    ):
        domains.add("catastrophic")

    return domains


def apply_self_healing_policy(
    process_info,
    classification,
    persistence_state,
    features=None,
    trust_state=None,
):
    process_info = process_info or {}
    classification = classification or {}
    persistence_state = dict(persistence_state or {})
    features = features or {}
    trust_state = trust_state or {}

    stage = persistence_state.get("stage", "observe")
    domains = evidence_domains(classification, features, trust_state)
    concrete_domains = domains - {"trust", "learned"}
    category = policy_engine.infer_category(process_info)

    risk = max(
        _normalized_score(classification.get("worm_score")),
        _normalized_score(classification.get("confidence")),
        _normalized_score(persistence_state.get("avg_combined_risk")),
    )
    final_trust = _normalized_score(
        trust_state.get(
            "final_trust",
            persistence_state.get("avg_final_trust", 1.0),
        )
    )

    catastrophic = (
        "catastrophic" in domains
        and persistence_state.get("catastrophic_ready", False)
    )

    termination_allowed = (
        catastrophic
        or (
            persistence_state.get("termination_ready", False)
            and risk >= 0.86
            and final_trust <= 0.75
            and len(concrete_domains) >= 3
            and not policy_engine.is_suppressed_category(category)
        )
    )

    if stage == DESTRUCTIVE_STAGE and not termination_allowed:
        if len(concrete_domains) >= 2 and risk >= 0.68:
            stage = "quarantine"
        elif concrete_domains and risk >= 0.45:
            stage = "throttle"
        else:
            stage = "observe"

    if (
        policy_engine.is_suppressed_category(category)
        and not catastrophic
    ):
        stage = _cap_stage(
            stage,
            policy_engine.get(
                "false_positive_suppression.max_stage_without_confirmed_behavior",
                "throttle",
            ),
        )

    if (
        stage in {"throttle", "quarantine"}
        and risk < 0.35
        and final_trust >= 0.90
    ):
        stage = "trust_recovery"

    persistence_state["stage"] = stage
    persistence_state["evidence_domains"] = sorted(domains)
    persistence_state["termination_allowed"] = termination_allowed
    persistence_state["self_healing_policy"] = "evidence_gated_v1"
    return persistence_state
