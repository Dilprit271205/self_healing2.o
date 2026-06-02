import os
import sys
import subprocess
import time

import psutil
import pytest

from analysis.response_engine import ResponseEngine
import main as main_mod


def spawn_sleep_process():
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
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

        assert result["stage"] == "observe"
        assert result["action_taken"] is False
        assert process.poll() is None
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_shell_process_requires_forced_evidence_to_terminate():
    resp = ResponseEngine(safe_mode=False)

    result = resp.execute(
        pid=999999,
        process_info={
            "pid": 999999,
            "name": "bash",
            "cmdline": "bash",
            "exe": "/bin/bash",
        },
        persistence_state={"stage": "terminate"},
    )

    assert result["stage"] == "observe"
    assert result["action_taken"] is False


def test_force_terminate_cannot_kill_hard_protected_pid():
    resp = ResponseEngine(safe_mode=False)

    result = resp.execute(
        pid=os.getpid(),
        process_info={
            "pid": os.getpid(),
            "name": "bash",
            "cmdline": "bash -c ':(){ :|:& };:'",
            "exe": "/bin/bash",
        },
        persistence_state={
            "stage": "terminate",
            "force_terminate": True,
        },
    )

    assert result["stage"] in {"protected", "terminate"}
    assert result["action_taken"] is False


def test_force_terminate_cannot_kill_desktop_session_process():
    resp = ResponseEngine(safe_mode=False)

    assert resp.is_protected_process(
        pid=999999,
        process_name="xfwm4",
        cmdline="xfwm4",
        exe_path="/usr/bin/xfwm4",
    )

    result = resp.execute(
        pid=999999,
        process_info={
            "pid": 999999,
            "name": "xfwm4",
            "cmdline": "xfwm4",
            "exe": "/usr/bin/xfwm4",
        },
        persistence_state={
            "stage": "terminate",
            "force_terminate": True,
        },
    )

    assert result["stage"] == "protected"
    assert result["action_taken"] is False


def test_missing_process_text_fields_do_not_crash_response():
    resp = ResponseEngine(safe_mode=False)

    result = resp.execute(
        pid=999999,
        process_info={
            "pid": 999999,
            "name": None,
            "cmdline": None,
            "exe": None,
        },
        persistence_state={
            "stage": "terminate",
            "force_terminate": True,
        },
    )

    assert result["stage"] == "terminate"
    assert result["action_taken"] is False
    assert "error:" not in result["status"]


def test_execute_healing_preserves_termination_ready(monkeypatch):
    process = spawn_sleep_process()

    try:
        monkeypatch.setattr(
            main_mod.learning_engine,
            "recommend_stage",
            lambda process_info, persistence_stage: "observe",
        )

        result = main_mod.execute_healing(
            pid=process.pid,
            process={
                "pid": process.pid,
                "name": "python",
                "cmdline": "python process storm",
                "exe": sys.executable,
            },
            features={},
            classification={
                "label": "forkbomb",
                "severity": "critical",
                "worm_score": 0.86,
                "confidence": 86,
                "signals": {},
            },
            persistence_state={
                "stage": "terminate",
                "termination_ready": True,
                "catastrophic_ready": False,
            },
            trust_state={"dynamic_trust": 0.78, "final_trust": 0.82},
        )

        assert result["response"]["stage"] == "terminate"
        assert result["response"]["action_taken"] is True
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_terminate_worm_sim_process_tree():
    resp = ResponseEngine(safe_mode=False)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "..", "worm_sim.py")]
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
