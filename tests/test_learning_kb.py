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
