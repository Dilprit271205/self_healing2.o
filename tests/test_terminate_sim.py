import os
import subprocess
import sys
import time

import pytest

from analysis.response_engine import ResponseEngine


def spawn_worm_sim():
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "worm_sim.py")]
    return subprocess.Popen(cmd)


def test_terminate_sim_process_tree():
    resp = ResponseEngine(safe_mode=False)
    proc = spawn_worm_sim()

    try:
        time.sleep(3)
        result = resp.terminate_process(proc.pid)
        assert result["stage"] == "terminate"
        assert result["action_taken"] is True

        proc.wait(timeout=10)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
