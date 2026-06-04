import os
import subprocess
import sys
import time

import psutil

from analysis.extractor_engine import ExtractorEngine
from analysis.persistence_engine import PersistenceEngine
from analysis.worm_classifier import WormClassifier


def test_entity_family_does_not_become_process_tree():
    extractor = ExtractorEngine()

    parent = {
        "pid": 100,
        "ppid": 1,
        "name": "xfce4-session",
        "cpu": 0,
        "memory": 0,
        "threads": 2,
        "create_time": time.time() - 500,
        "cmdline": "xfce4-session",
    }
    child = {
        "pid": 101,
        "ppid": 100,
        "name": "nm-dispatcher",
        "cpu": 0,
        "memory": 0,
        "threads": 1,
        "create_time": time.time() - 5,
        "cmdline": "nm-dispatcher",
    }
    sibling = {
        "pid": 102,
        "ppid": 100,
        "name": "xorg",
        "cpu": 0,
        "memory": 0,
        "threads": 1,
        "create_time": time.time() - 500,
        "cmdline": "Xorg",
    }

    features = extractor.extract(
        child,
        {
            101: [
                parent,
                child,
                sibling,
            ]
        },
        {},
        {},
    )

    assert features["f_proc_tree"] == 1


def test_benign_session_service_is_not_forkbomb():
    classifier = WormClassifier()

    classification = classifier.classify(
        {
            "cmdline": "nm-dispatcher",
            "f_proc_spawn": 0,
            "f_proc_tree": 1,
            "f_process_trend": 0,
            "f_young_process": 1,
            "f_thread_velocity": 0,
            "f_connection_velocity": 0,
            "f_remote_ips": 0,
            "file_events": 0,
            "worm_score": 0,
            "safe_process": True,
        },
        {"anomalies": {}, "temporal": {}},
        {"dynamic_trust": 0.95, "final_trust": 0.9},
    )

    assert classification["label"] == "normal"
    assert classification["signals"]["forkbomb_detected"] is False


def test_glycin_svg_helper_is_safe():
    extractor = ExtractorEngine()
    classifier = WormClassifier()

    process = {
        "pid": 201,
        "ppid": 100,
        "name": "glycin-svg",
        "cpu": 0,
        "memory": 0.1,
        "threads": 2,
        "create_time": time.time() - 5,
        "cmdline": "glycin-svg",
    }

    features = extractor.extract(
        process,
        {
            201: [
                {
                    "pid": 100,
                    "ppid": 1,
                    "name": "xfce4-session",
                },
                process,
            ]
        },
        {},
        {},
    )

    classification = classifier.classify(
        features,
        {"anomalies": {}, "temporal": {}},
        {"dynamic_trust": 1.0, "final_trust": 1.0},
    )

    assert features["safe_process"] is False
    assert features["f_proc_tree"] == 1
    assert classification["label"] == "normal"
    assert classification["signals"]["forkbomb_detected"] is False


def spawn_forkbomb():
    env = os.environ.copy()
    env["FORKBOMB_MAX_CHILDREN"] = "18"
    env["FORKBOMB_SPAWN_DELAY"] = "0.05"
    env["FORKBOMB_RUN_TIME"] = "180"
    env["SELF_HEALING_FORK_TREE_THRESHOLD"] = "8"
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "forkbomb_sim.py")]
    return subprocess.Popen(cmd, env=env)


def process_tree_records(proc):
    records = [
        {
            "pid": proc.pid,
            "ppid": proc.ppid(),
            "name": proc.name(),
            "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
        }
    ]

    for child in proc.children(recursive=True):
        try:
            records.append(
                {
                    "pid": child.pid,
                    "ppid": child.ppid(),
                    "name": child.name(),
                    "cmdline": " ".join(child.cmdline()) if child.cmdline() else "",
                }
            )
        except psutil.Error:
            continue

    return records


def test_forkbomb_detection():
    extractor = ExtractorEngine()
    classifier = WormClassifier()

    p = spawn_forkbomb()
    time.sleep(3.0)

    try:
        proc = psutil.Process(p.pid)
        snap = {
            "pid": p.pid,
            "name": proc.name(),
            "cpu": proc.cpu_percent(interval=0.05),
            "memory": proc.memory_info().rss,
            "threads": proc.num_threads(),
            "create_time": proc.create_time(),
            "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
        }

        entity_map = {p.pid: process_tree_records(proc)}
        features = extractor.extract(snap, entity_map, {})

        classification = classifier.classify(
            features,
            {"anomalies": {}, "temporal": {}},
            {"dynamic_trust": 0.5, "final_trust": 0.5},
        )

        assert classification["label"] in {"forkbomb", "worm", "suspicious"}
        assert classification["signals"]["correlated_signal_count"] >= 4
        assert classification["signals"]["forkbomb_detected"] is True

        import main as main_mod
        for _ in range(3):
            main_mod.persistence_engine.update(
                pid=p.pid,
                classification=classification,
                trust_state={"dynamic_trust": 0.35, "final_trust": 0.35},
            )

        time.sleep(1.5)

        proc = psutil.Process(p.pid)
        snap2 = {
            "pid": p.pid,
            "name": proc.name(),
            "cpu": proc.cpu_percent(interval=0.05),
            "memory": proc.memory_info().rss,
            "threads": proc.num_threads(),
            "create_time": proc.create_time(),
            "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
        }
        features2 = extractor.extract(
            snap2,
            {
                p.pid:
                    process_tree_records(proc)
            },
            {}
        )

        persistence_state = main_mod.persistence_engine.check_persistence(p.pid)
        trust_state = {"dynamic_trust": 0.35, "final_trust": 0.35}

        result = main_mod.execute_healing(
            pid=p.pid,
            process=snap2,
            features=features2,
            classification=classification,
            persistence_state=persistence_state,
            trust_state=trust_state,
        )

        assert result["response"]["stage"] == "terminate"
        assert result["response"]["action_taken"] is True

        proc.wait(timeout=10)
        assert not psutil.pid_exists(p.pid)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=5)


def test_shell_forkbomb_signature_alone_is_not_critical():
    classifier = WormClassifier()

    classification = classifier.classify(
        {
            "cmdline": "bash -c ':(){ :|:& };:'",
            "f_proc_spawn": 0,
            "f_proc_tree": 4,
            "f_process_trend": 0,
            "f_young_process": 1,
            "f_thread_velocity": 0,
            "f_connection_velocity": 0,
            "f_remote_ips": 0,
            "file_events": 0,
            "worm_score": 0,
            "safe_process": False,
        },
        {"anomalies": {}, "temporal": {}},
        {"dynamic_trust": 1.0, "final_trust": 1.0},
    )

    assert classification["label"] == "normal"
    assert classification["severity"] == "low"
    assert classification["signals"]["forkbomb_detected"] is False


def test_persistent_process_storm_terminates_without_trust_collapse():
    classifier = WormClassifier()
    persistence = PersistenceEngine()

    features = {
        "cmdline": "python process storm",
        "cpu": 4,
        "memory": 1,
        "f_proc_spawn": 0,
        "f_proc_tree": 12,
        "f_process_trend": 0,
        "f_young_process": 1,
        "f_thread_velocity": 0,
        "f_connection_velocity": 0,
        "f_remote_ips": 0,
        "file_events": 0,
        "f_child_similarity": 1.0,
        "f_repeated_child_count": 10,
        "f_short_lived_child_ratio": 1.0,
        "worm_score": 80,
        "false_positive_suppression": 0,
    }

    classification = classifier.classify(
        features,
        {"anomalies": {"aggregate": 0.5}, "temporal": {}},
        {"dynamic_trust": 0.78, "final_trust": 0.82},
    )

    assert classification["signals"]["forkbomb_detected"] is True

    for _ in range(persistence.delta):
        persistence.update(
            12345,
            classification,
            {"dynamic_trust": 0.78, "final_trust": 0.82},
        )

    state = persistence.check_persistence(12345)

    assert state["stage"] == "terminate"
    assert state["termination_ready"] is True


def test_catastrophic_process_storm_can_terminate_in_one_loop():
    classifier = WormClassifier()
    persistence = PersistenceEngine()

    classification = classifier.classify(
        {
            "cmdline": "python process storm",
            "cpu": 8,
            "memory": 1,
            "f_proc_spawn": 0,
            "f_proc_tree": 25,
            "f_process_trend": 0,
            "f_young_process": 1,
            "f_thread_velocity": 0,
            "f_connection_velocity": 0,
            "f_remote_ips": 0,
            "file_events": 0,
            "f_child_similarity": 1.0,
            "f_repeated_child_count": 24,
            "f_short_lived_child_ratio": 1.0,
            "worm_score": 95,
            "false_positive_suppression": 0,
        },
        {"anomalies": {"aggregate": 0.5}, "temporal": {}},
        {"dynamic_trust": 0.8, "final_trust": 0.84},
    )

    persistence.update(
        22222,
        classification,
        {"dynamic_trust": 0.8, "final_trust": 0.84},
    )

    state = persistence.check_persistence(22222)

    assert classification["signals"]["catastrophic_behavior"] is True
    assert state["stage"] == "terminate"
    assert state["catastrophic_ready"] is True


def test_file_replication_burst_terminates_after_persistence():
    classifier = WormClassifier()
    persistence = PersistenceEngine()

    classification = classifier.classify(
        {
            "cmdline": "python file burst",
            "cpu": 3,
            "memory": 1,
            "f_proc_spawn": 0,
            "f_proc_tree": 1,
            "f_process_trend": 0,
            "f_young_process": 1,
            "f_thread_velocity": 0,
            "f_connection_velocity": 0,
            "f_remote_ips": 0,
            "file_events": 80,
            "f_child_similarity": 0,
            "f_repeated_child_count": 0,
            "f_short_lived_child_ratio": 0,
            "worm_score": 80,
            "false_positive_suppression": 0,
        },
        {"anomalies": {"aggregate": 0.30}, "temporal": {}},
        {"dynamic_trust": 0.82, "final_trust": 0.86},
    )

    assert classification["label"] == "worm"
    assert classification["signals"]["replication_detected"] is True

    for _ in range(persistence.delta):
        persistence.update(
            33333,
            classification,
            {"dynamic_trust": 0.82, "final_trust": 0.86},
        )

    state = persistence.check_persistence(33333)

    assert state["stage"] == "terminate"
    assert state["termination_ready"] is True
