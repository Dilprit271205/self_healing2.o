import os
import subprocess
import sys
import time

import psutil

from analysis.extractor_engine import ExtractorEngine
from analysis.worm_classifier import WormClassifier


def spawn_forkbomb():
    env = os.environ.copy()
    env["FORKBOMB_MAX_CHILDREN"] = "8"
    env["FORKBOMB_SPAWN_DELAY"] = "0.05"
    env["FORKBOMB_RUN_TIME"] = "15"
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "forkbomb_sim.py")]
    return subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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

        entity_map = {p.pid: [c.pid for c in proc.children(recursive=True)]}
        features = extractor.extract(snap, entity_map, {})

        classification = classifier.classify(
            features,
            {"anomalies": {}, "temporal": {}},
            {"dynamic_trust": 0.5, "final_trust": 0.5},
        )

        assert classification["label"] in {"worm", "forkbomb", "suspicious"}

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
        features2 = extractor.extract(snap2, {p.pid: [c.pid for c in proc.children(recursive=True)]}, {})

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
        assert proc.poll() is not None
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=5)
