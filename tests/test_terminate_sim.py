import subprocess
import time
import os
import signal

from analysis.response_engine import ResponseEngine


def spawn_worm_sim():
    # spawn worm_sim.py as a background process
    cmd = ["/usr/bin/env", "python3", "worm_sim.py"]
    p = subprocess.Popen(cmd)
    print(f"Spawned worm_sim PID {p.pid}")
    return p


def test_terminate():
    resp = ResponseEngine(safe_mode=False)

    p = spawn_worm_sim()

    # allow it to spawn some children
    time.sleep(2)

    try:
        result = resp.terminate_process(p.pid)
        print("Termination result:", result)
    except Exception as e:
        print("Error during termination:", e)

    # wait a bit and ensure process is gone
    time.sleep(1)
    poll = p.poll()
    print("Process poll after termination:", poll)


if __name__ == '__main__':
    test_terminate()
