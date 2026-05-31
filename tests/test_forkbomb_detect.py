import subprocess
import time
import os

from analysis.extractor_engine import ExtractorEngine
from analysis.worm_classifier import WormClassifier


def spawn_forkbomb():
    cmd = ["/usr/bin/env", "python3", "forkbomb_sim.py"]
    p = subprocess.Popen(cmd)
    print(f"Spawned forkbomb_sim PID {p.pid}")
    return p


def test_forkbomb_detection():
    extractor = ExtractorEngine()
    classifier = WormClassifier()

    p = spawn_forkbomb()

    time.sleep(3.0)

    try:
        # sample the process
        import psutil

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

        classification = classifier.classify(features, {"anomalies": {}, "temporal": {}}, {"dynamic_trust": 0.5, "final_trust": 0.5})

        print("Classification:", classification)

    finally:
        try:
            p.terminate()
        except:
            pass


if __name__ == '__main__':
    test_forkbomb_detection()
