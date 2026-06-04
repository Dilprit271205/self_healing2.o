import json

from analysis.learning_engine import LearningEngine


def test_learning_engine_persists_attack_knowledge(tmp_path, monkeypatch):
    kb_path = tmp_path / "learning_kb.json"
    monkeypatch.setenv("SELF_HEALING_KB_PATH", str(kb_path))

    engine = LearningEngine()
    process = {
        "pid": 123,
        "name": "python",
        "cmdline": "python process storm",
        "exe": "/usr/bin/python",
    }
    classification = {
        "label": "forkbomb",
        "severity": "critical",
        "worm_score": 0.96,
        "confidence": 96,
        "signals": {
            "forkbomb_detected": True,
            "correlated_signals": {
                "rapid_child_spawning": True,
                "large_or_growing_tree": True,
                "repeated_similar_children": True,
                "process_storm_burst": True,
            },
        },
    }

    entry = engine.update(
        pid=123,
        process_info=process,
        classification=classification,
        response_result={
            "stage": "terminate",
            "action_taken": True,
        },
        trust_state={
            "dynamic_trust": 0.25,
            "final_trust": 0.25,
        },
        features={
            "process_category": "unknown",
        },
    )

    assert entry["disposition"] == "malicious"
    assert entry["attack_family"] == "process_storm"
    assert "rapid_child_spawning" in entry["evidence"]
    assert kb_path.exists()

    stored = json.loads(kb_path.read_text(encoding="utf-8"))
    assert len(stored) == 1


def test_learning_engine_recommends_known_malicious_stage(tmp_path, monkeypatch):
    kb_path = tmp_path / "learning_kb.json"
    monkeypatch.setenv("SELF_HEALING_KB_PATH", str(kb_path))

    engine = LearningEngine()
    process = {
        "pid": 123,
        "name": "python",
        "cmdline": "python file replication",
        "exe": "/usr/bin/python",
    }
    classification = {
        "label": "worm",
        "severity": "critical",
        "worm_score": 0.9,
        "confidence": 90,
        "signals": {
            "replication_detected": True,
            "correlated_signals": {
                "file_replication": True,
                "high_file_velocity": True,
                "extreme_file_velocity": True,
                "baseline_anomaly": True,
            },
        },
    }

    for _ in range(4):
        engine.update(
            pid=123,
            process_info=process,
            classification=classification,
            response_result={
                "stage": "terminate",
                "action_taken": True,
            },
            trust_state={
                "dynamic_trust": 0.3,
                "final_trust": 0.3,
            },
            features={
                "process_category": "unknown",
            },
        )

    recommended = engine.recommend_from_knowledge(
        process,
        classification,
        "throttle",
    )

    assert recommended in {"quarantine", "terminate"}


def test_learning_engine_suppresses_false_positive_pattern(tmp_path, monkeypatch):
    kb_path = tmp_path / "learning_kb.json"
    monkeypatch.setenv("SELF_HEALING_KB_PATH", str(kb_path))

    engine = LearningEngine()
    process = {
        "pid": 321,
        "name": "streamlit",
        "cmdline": "streamlit run dashboard.py",
        "exe": "/usr/bin/streamlit",
    }
    classification = {
        "label": "suspicious",
        "severity": "medium",
        "worm_score": 0.42,
        "confidence": 42,
        "signals": {
            "correlated_signals": {
                "resource_pressure": True,
                "baseline_anomaly": True,
            },
        },
    }

    for _ in range(3):
        engine.update(
            pid=321,
            process_info=process,
            classification=classification,
            response_result={
                "stage": "observe",
                "action_taken": False,
            },
            trust_state={
                "dynamic_trust": 0.8,
                "final_trust": 0.82,
            },
            features={
                "process_category": "dashboard",
            },
        )

    assert (
        engine.recommend_from_knowledge(
            process,
            classification,
            "quarantine",
        )
        == "observe"
    )


def test_learning_engine_learns_trust_score_anomaly_pattern(tmp_path, monkeypatch):
    kb_path = tmp_path / "learning_kb.json"
    monkeypatch.setenv("SELF_HEALING_KB_PATH", str(kb_path))

    engine = LearningEngine()
    process = {
        "pid": 456,
        "name": "python",
        "cmdline": "python worm-like fanout replication",
        "exe": "/usr/bin/python",
    }
    classification = {
        "label": "worm",
        "severity": "critical",
        "worm_score": 0.93,
        "confidence": 93,
        "signals": {
            "worm_like_behavior": True,
            "trust_anomaly_pattern": True,
            "correlated_signals": {
                "network_fanout": True,
                "file_replication": True,
                "trust_anomaly_pattern": True,
                "worm_like_behavior": True,
            },
        },
    }

    for _ in range(3):
        entry = engine.update(
            pid=456,
            process_info=process,
            classification=classification,
            response_result={
                "stage": "quarantine",
                "action_taken": True,
            },
            trust_state={
                "static_trust": 0.82,
                "dynamic_trust": 0.42,
                "final_trust": 0.48,
                "trust_anomaly_pressure": 0.72,
            },
            features={
                "process_category": "unknown",
                "behavior_correlation_score": 0.82,
                "worm_pattern_anomaly": 0.82,
            },
        )

    assert entry["disposition"] == "malicious"
    assert entry["attack_family"] == "correlated_worm_behavior"
    assert entry["avg_pattern_strength"] >= 0.8
    assert entry["avg_trust_anomaly_pressure"] >= 0.7

    assert engine.recommend_from_knowledge(
        process,
        classification,
        "throttle",
    ) in {"quarantine", "terminate"}


def test_learning_engine_terminates_repeated_strong_pattern_after_one_observation(tmp_path, monkeypatch):
    kb_path = tmp_path / "learning_kb.json"
    monkeypatch.setenv("SELF_HEALING_KB_PATH", str(kb_path))

    engine = LearningEngine()
    process = {
        "pid": 789,
        "name": "python",
        "cmdline": "python repeated file replication fanout",
        "exe": "/usr/bin/python",
    }
    classification = {
        "label": "worm",
        "severity": "critical",
        "worm_score": 0.95,
        "confidence": 95,
        "signals": {
            "worm_like_behavior": True,
            "replication_detected": True,
            "trust_anomaly_pattern": True,
            "correlated_signals": {
                "file_replication": True,
                "network_fanout": True,
                "trust_anomaly_pattern": True,
                "worm_like_behavior": True,
            },
        },
    }

    entry = engine.update(
        pid=789,
        process_info=process,
        classification=classification,
        response_result={
            "stage": "quarantine",
            "action_taken": True,
        },
        trust_state={
            "static_trust": 0.84,
            "dynamic_trust": 0.35,
            "final_trust": 0.42,
            "trust_anomaly_pressure": 0.88,
        },
        features={
            "process_category": "unknown",
            "behavior_correlation_score": 0.9,
            "worm_pattern_anomaly": 0.9,
        },
    )

    assert entry["recommended_stage"] == "terminate"

    assert engine.recommend_from_knowledge(
        process,
        classification,
        "throttle",
    ) == "terminate"


def test_learning_engine_reuses_similar_pattern_with_overlapping_evidence(tmp_path, monkeypatch):
    kb_path = tmp_path / "learning_kb.json"
    monkeypatch.setenv("SELF_HEALING_KB_PATH", str(kb_path))

    engine = LearningEngine()
    learned_process = {
        "pid": 1001,
        "name": "python",
        "cmdline": "python replicate and fanout",
        "exe": "/usr/bin/python",
    }
    learned_classification = {
        "label": "worm",
        "severity": "critical",
        "worm_score": 0.94,
        "confidence": 94,
        "signals": {
            "worm_like_behavior": True,
            "replication_detected": True,
            "correlated_signals": {
                "file_replication": True,
                "network_fanout": True,
                "trust_anomaly_pattern": True,
                "worm_like_behavior": True,
            },
        },
    }

    engine.update(
        pid=1001,
        process_info=learned_process,
        classification=learned_classification,
        response_result={
            "stage": "quarantine",
            "action_taken": True,
        },
        trust_state={
            "static_trust": 0.84,
            "dynamic_trust": 0.34,
            "final_trust": 0.40,
            "trust_anomaly_pressure": 0.9,
        },
        features={
            "process_category": "unknown",
            "behavior_correlation_score": 0.9,
            "worm_pattern_anomaly": 0.9,
        },
    )

    similar_process = {
        "pid": 1002,
        "name": "node",
        "cmdline": "node fanout replication variant",
        "exe": "/usr/bin/node",
    }
    similar_classification = {
        "label": "worm",
        "severity": "critical",
        "worm_score": 0.91,
        "confidence": 91,
        "signals": {
            "worm_like_behavior": True,
            "fanout_detected": True,
            "correlated_signals": {
                "file_replication": True,
                "network_fanout": True,
                "worm_like_behavior": True,
            },
        },
    }

    assert engine.recommend_from_knowledge(
        similar_process,
        similar_classification,
        "throttle",
    ) == "terminate"
