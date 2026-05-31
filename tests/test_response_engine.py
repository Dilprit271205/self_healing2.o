import os
import sys
import subprocess
import time

import psutil
import pytest

from analysis.response_engine import ResponseEngine


def spawn_sleep_process():
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_safe_process_is_not_terminated():
    resp = ResponseEngine(safe_mode=False)
    process = spawn_sleep_process()

    try:
        result = resp.execute(
            pid=process.pid,
            process_info={
                "pid": process.pid,
                "name": "python",
                "cmdline": "streamlit run dashboard.py",
                "exe": sys.executable,
            },
            persistence_state={"stage": "terminate"},
        )

        assert result["stage"] == "protected"
        assert result["action_taken"] is False
        assert "trusted process" in result["status"] or "protected" in result["status"]
        assert process.poll() is None
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_terminate_worm_sim_process_tree():
    resp = ResponseEngine(safe_mode=False)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "..", "worm_sim.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

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
