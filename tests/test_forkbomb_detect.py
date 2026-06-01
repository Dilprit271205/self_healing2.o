import os
import subprocess
import sys
import time

import psutil

from analysis.extractor_engine import ExtractorEngine
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

    assert features["safe_process"] is True
    assert features["f_proc_tree"] == 1
    assert classification["label"] == "normal"
    assert classification["signals"]["forkbomb_detected"] is False


def spawn_forkbomb():
    env = os.environ.copy()
    env["FORKBOMB_MAX_CHILDREN"] = "18"
    env["FORKBOMB_SPAWN_DELAY"] = "0.05"
    env["FORKBOMB_RUN_TIME"] = "15"
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

        assert classification["label"] == "forkbomb"
        assert classification["signals"]["forkbomb_detected"] is True

        import main as main_mod
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

        persistence_state = {"stage": "observe"}
        trust_state = {"dynamic_trust": 0.5, "final_trust": 0.5}

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


def test_shell_forkbomb_signature_is_critical():
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

    assert classification["label"] == "forkbomb"
    assert classification["severity"] == "critical"
    assert classification["signals"]["forkbomb_detected"] is True
