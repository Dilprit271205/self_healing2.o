import time

import main as main_mod
from utils.file_event_mapper import get_file_map, record_file_event


def test_file_preflight_does_not_attribute_home_burst_to_new_process(monkeypatch):
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50001,
            "ppid": 100,
            "name": "python",
            "cmdline": "python harmless_new_process.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/random_file.txt": 200,
                "/tmp/random_tmp.txt": 200,
            }
        },
    )

    assert handled == set()


def test_file_preflight_ignores_self_generated_log_bursts():
    main_mod.file_burst_window.clear()

    handled = main_mod.emergency_file_activity_preflight(
        [],
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/logs/system_log.json": 500,
                "/home/kali/Downloads/self_healing2.o-main/__pycache__/main.pyc": 300,
            }
        },
    )

    assert handled == set()
    assert main_mod.file_burst_window == {}


def test_duplicate_file_hash_count_is_recorded(tmp_path):
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text(
        "same payload",
        encoding="utf-8"
    )
    second.write_text(
        "same payload",
        encoding="utf-8"
    )

    record_file_event(
        None,
        str(
            first
        ),
        "create"
    )
    record_file_event(
        None,
        str(
            second
        ),
        "create"
    )

    file_map = get_file_map()

    assert file_map["__duplicate_hash_count__"] == 1
    assert file_map["__event_types__"]["create"] == 2


def test_file_preflight_observes_specific_subdirectory_by_default(monkeypatch):
    calls = []

    def fake_healing(**kwargs):
        calls.append(kwargs)
        return {
            "response": {
                "stage": kwargs["persistence_state"]["stage"],
                "status": "priority throttled",
                "action_taken": True,
            },
            "learning": {},
        }

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        fake_healing,
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "false",
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50002,
            "ppid": 100,
            "name": "python",
            "cmdline": "python worm.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/worm_lab",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/worm_lab/gen_0/file.txt": 160,
            }
        },
    )

    assert handled == {50002}
    assert calls == []


def test_file_preflight_does_not_let_learning_upgrade_default_observe(monkeypatch):
    def fail_healing(**kwargs):
        raise AssertionError("file-only observe mode must not call healing")

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        fail_healing,
    )
    monkeypatch.delenv(
        "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
        raising=False,
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "false",
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50003,
            "ppid": 100,
            "name": "python",
            "cmdline": "python file replication",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/self_healing2.o-main",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/self_healing2.o-main/worm_lab/file.txt": 400,
            }
        },
    )

    assert handled == {50003}


def test_file_preflight_terminates_behavioral_file_burst(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": kwargs["persistence_state"]["stage"],
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )
    monkeypatch.delenv(
        "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
        raising=False,
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50006,
            "ppid": 100,
            "name": "python",
            "cmdline": "python worker.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/workload",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/workload/output/a.bin": 130,
                "/home/kali/workload/output/sub/b.bin": 130,
            }
        },
    )

    assert handled == {50006}
    assert calls
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["persistence_state"]["force_terminate"] is True


def test_file_preflight_uses_recent_exited_process_for_attribution(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "observe",
                "status": "monitoring",
                "action_taken": False,
            },
            "learning": {},
        },
    )
    monkeypatch.delenv(
        "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
        raising=False,
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "false",
    )

    main_mod.file_burst_window.clear()
    main_mod.recent_process_cache.clear()
    main_mod.dead_process_first_seen.clear()

    main_mod.update_recent_process_cache([
        {
            "pid": 50005,
            "ppid": 100,
            "name": "python",
            "cmdline": "python worker.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/workload",
            "age_seconds": 2,
        }
    ])

    handled = main_mod.emergency_file_activity_preflight(
        [],
        {
            "__paths__": {
                "/home/kali/workload/output/copy_1.txt": 150,
            }
        },
    )

    assert handled == {50005}
    assert calls == []


def test_file_preflight_can_contain_in_explicit_lab_mode(monkeypatch):
    calls = []

    def fake_healing(**kwargs):
        calls.append(kwargs)
        return {
            "response": {
                "stage": kwargs["persistence_state"]["stage"],
                "status": "temporarily isolated",
                "action_taken": True,
            },
            "learning": {},
        }

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        fake_healing,
    )
    monkeypatch.setenv(
        "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
        "true",
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "false",
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50004,
            "ppid": 100,
            "name": "python",
            "cmdline": "python file replication",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/self_healing2.o-main",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/self_healing2.o-main/worm_lab/file.txt": 400,
            }
        },
    )

    assert handled == {50004}
    assert calls[0]["persistence_state"]["stage"] == "quarantine"


def test_process_storm_preflight_skips_terminal_parent(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    now = time.time()
    parent = {
        "pid": 60000,
        "ppid": 100,
        "name": "qterminal",
        "cmdline": "qterminal",
        "exe": "/usr/bin/qterminal",
        "cwd": "/home/kali",
        "create_time": now - 5,
        "age_seconds": 5,
    }
    children = [
        {
            "pid": 60001 + index,
            "ppid": 60000,
            "name": "python",
            "cmdline": "python test.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali",
            "create_time": now - 1,
            "age_seconds": 1,
        }
        for index in range(25)
    ]

    handled = main_mod.emergency_process_storm_preflight(
        [parent] + children,
        {},
        {},
    )

    assert handled == set()
    assert calls == []


def test_deep_recursive_process_tree_triggers_emergency(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    now = time.time()
    processes = [
        {
            "pid": 61000,
            "ppid": 100,
            "name": "python",
            "cmdline": "python Test_Worm.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "create_time": now - 4,
            "age_seconds": 4,
        }
    ]

    next_pid = 61001
    current_level = [61000]

    for _depth in range(5):
        next_level = []
        for parent_pid in current_level:
            for _ in range(2):
                processes.append({
                    "pid": next_pid,
                    "ppid": parent_pid,
                    "name": "python",
                    "cmdline": "python Test_Worm.py worker",
                    "exe": "/usr/bin/python",
                    "cwd": "/home/kali/Downloads/self_healing2.o-main",
                    "create_time": now - 1,
                    "age_seconds": 1,
                })
                next_level.append(
                    next_pid
                )
                next_pid += 1
        current_level = next_level

    handled = main_mod.emergency_process_storm_preflight(
        processes,
        {},
        {},
    )

    assert 61000 in handled
    assert calls
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["features"]["f_proc_tree"] >= 30
    assert calls[0]["features"]["f_recursive_depth"] >= 4


def test_behavior_localhost_beaconing_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    processes = [
        {
            "pid": 62000,
            "ppid": 100,
            "name": "python",
            "cmdline": "python worker.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/workload",
            "age_seconds": 2,
        }
    ]

    handled = main_mod.emergency_behavior_preflight(
        processes,
        {
            62000: {
                "connections": 12,
                "connection_velocity": 12,
                "loopback_connections": 8,
            }
        },
    )

    assert handled == {62000}
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["features"]["f_localhost_beaconing"] == 1
    assert calls[0]["features"]["f_loopback_event_count"] == 0


def test_behavior_rolling_localhost_beaconing_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62010,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "age_seconds": 2,
            }
        ],
        {
            62010: {
                "connections": 1,
                "connection_velocity": 0,
                "loopback_connections": 1,
                "loopback_event_count": 12,
                "loopback_connection_rate": 1.0,
                "network_event_count": 12,
                "connection_rate": 1.0,
            }
        },
    )

    assert handled == {62010}
    assert calls[0]["features"]["f_localhost_beaconing"] == 1
    assert calls[0]["features"]["f_loopback_event_count"] == 12


def test_behavior_single_loopback_connection_observes(monkeypatch):
    calls = []

    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62011,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "age_seconds": 2,
            }
        ],
        {
            62011: {
                "connections": 1,
                "connection_velocity": 0,
                "loopback_connections": 1,
                "loopback_event_count": 1,
                "loopback_connection_rate": 0.08,
            }
        },
    )

    assert handled == set()
    assert calls == []


def test_behavior_persistence_artifact_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    processes = [
        {
            "pid": 62001,
            "ppid": 100,
            "name": "python",
            "cmdline": "python worker.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/workload",
            "f_persistence_artifact": 1,
            "age_seconds": 2,
        }
    ]

    handled = main_mod.emergency_behavior_preflight(
        processes,
        {},
    )

    assert handled == {62001}
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["features"]["f_persistence_artifact"] == 1


def test_behavior_persistence_artifact_detects_file_map_path(monkeypatch):
    calls = []

    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62012,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "age_seconds": 2,
            }
        ],
        {},
        {
            "__paths__": {
                "/home/kali/workload/.config/autostart/worker.desktop": 2,
            }
        },
    )

    assert handled == {62012}
    assert calls[0]["features"]["f_persistence_artifact"] == 1
    assert calls[0]["features"]["persistence_events"] == 2


def test_behavior_preflight_respects_production_safe_mode(monkeypatch):
    calls = []

    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "false",
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62002,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "age_seconds": 2,
            }
        ],
        {
            62002: {
                "connections": 4,
                "connection_velocity": 3,
                "loopback_connections": 4,
            }
        },
    )

    assert handled == set()
    assert calls == []


def test_behavior_thread_storm_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62003,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "threads": 95,
                "age_seconds": 2,
            }
        ],
        {},
    )

    assert handled == {62003}
    assert calls[0]["features"]["f_thread_storm"] == 1
    assert calls[0]["persistence_state"]["stage"] == "terminate"


def test_behavior_cpu_exhaustion_with_correlation_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62004,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "cpu": 91,
                "threads": 30,
                "age_seconds": 2,
            }
        ],
        {},
    )

    assert handled == {62004}
    assert calls[0]["features"]["f_cpu_exhaustion"] == 1
    assert calls[0]["persistence_state"]["stage"] == "terminate"


def test_behavior_memory_spike_with_correlation_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62005,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "memory": 42,
                "threads": 30,
                "age_seconds": 2,
            }
        ],
        {},
    )

    assert handled == {62005}
    assert calls[0]["features"]["f_memory_spike"] == 1
    assert calls[0]["persistence_state"]["stage"] == "terminate"


def test_behavior_sensitive_file_access_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62006,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "f_sensitive_file_access": 1,
                "age_seconds": 2,
            }
        ],
        {},
    )

    assert handled == {62006}
    assert calls[0]["features"]["f_sensitive_file_access"] == 1
    assert calls[0]["persistence_state"]["stage"] == "terminate"


def test_behavior_sensitive_file_access_detects_file_map_path(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": "terminate",
                "status": "terminated",
                "action_taken": True,
            },
            "learning": {},
        },
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62013,
                "ppid": 100,
                "name": "python",
                "cmdline": "python worker.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/workload",
                "age_seconds": 2,
            }
        ],
        {},
        {
            "__paths__": {
                "/home/kali/workload/secrets/.env": 1,
            }
        },
    )

    assert handled == {62013}
    assert calls[0]["features"]["f_sensitive_file_access"] == 1
    assert calls[0]["features"]["sensitive_file_events"] == 1


def test_non_lab_cpu_heavy_process_is_not_terminated(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )

    handled = main_mod.emergency_behavior_preflight(
        [
            {
                "pid": 62007,
                "ppid": 100,
                "name": "python",
                "cmdline": "python render_job.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/projects/normal_render",
                "cpu": 98,
                "threads": 12,
                "age_seconds": 2,
            }
        ],
        {},
    )

    assert handled == set()
    assert calls == []
