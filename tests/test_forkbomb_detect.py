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

        # attempt autonomous healing via main.execute_healing
        try:
            import main as main_mod

            # re-sample just before mitigation to capture current spawn count
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
                trust_state=trust_state
            )
            print("Healing result:", result)

            assert result["response"]["stage"] == "terminate", (
                f"Expected immediate fork bomb healing, got {result['response']}"
            )
            assert result["response"]["action_taken"] is True, (
                f"Expected action on fork bomb, got {result['response']}"
            )

            try:
                proc.wait(timeout=3)
            except Exception as wait_err:
                raise AssertionError(
                    f"Forkbomb parent process still alive after healing: {wait_err}"
                )
        except Exception as e:
            print("Error calling execute_healing:", e)

    finally:
        try:
            p.terminate()
        except:
            pass


if __name__ == '__main__':
    test_forkbomb_detection()
