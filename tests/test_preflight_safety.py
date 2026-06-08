import time

import pytest

import main as main_mod
from utils.file_event_mapper import get_file_map, record_file_event


@pytest.fixture(autouse=True)
def clear_preflight_state():
    main_mod.file_burst_window.clear()
    main_mod.file_behavior_memory.clear()
    main_mod.recent_process_cache.clear()
    main_mod.dead_process_first_seen.clear()
    yield
    main_mod.file_burst_window.clear()
    main_mod.file_behavior_memory.clear()
    main_mod.recent_process_cache.clear()
    main_mod.dead_process_first_seen.clear()


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


def test_file_preflight_ignores_model_retrain_bursts():
    main_mod.file_burst_window.clear()

    handled = main_mod.emergency_file_activity_preflight(
        [],
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/analysis/models/threat_model.joblib": 300,
                "/home/kali/Downloads/self_healing2.o-main/analysis/models/threat_model.metadata.json": 120,
            }
        },
    )

    assert handled == set()
    assert main_mod.file_burst_window == {}


def test_file_preflight_logs_unattributed_burst_for_dashboard(monkeypatch):
    logged = []
    monkeypatch.setattr(
        main_mod,
        "log_process",
        lambda row: logged.append(row),
    )

    handled = main_mod.emergency_file_activity_preflight(
        [],
        {
            "__paths__": {
                "/tmp/p7_file_rename_lab/document_1.tmp": 70,
                "/tmp/p7_file_rename_lab/document_2.locked": 70,
            }
        },
    )

    assert handled == set()
    assert logged
    assert logged[0]["name"] == "file-monitor"
    assert logged[0]["severity"] == "high"
    assert logged[0]["signals"]["replication_detected"] is True
    assert logged[0]["features"]["no_eligible_process_candidate"] is True


def test_file_preflight_skips_operator_terminal(monkeypatch):
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
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50007,
            "ppid": 100,
            "name": "qterminal",
            "cmdline": "qterminal",
            "exe": "/usr/bin/qterminal",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "age_seconds": 5,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/output/a.bin": 140,
                "/home/kali/Downloads/self_healing2.o-main/output/b.bin": 140,
            }
        },
    )

    assert handled == set()
    assert calls == []


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
    assert len(calls) == 1
    assert calls[0]["classification"]["label"] == "worm"
    assert calls[0]["persistence_state"]["stage"] == "observe"


def test_file_preflight_ignores_normal_low_volume_file_activity(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
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
    main_mod.file_behavior_memory.clear()

    processes = [
        {
            "pid": 50009,
            "ppid": 100,
            "name": "python",
            "cmdline": "python normal_behaviour.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/workload",
            "age_seconds": 12,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/workload/normal_behaviour_lab/normal_file_0.txt": 5,
                "/home/kali/workload/normal_behaviour_lab/normal_file_1.txt": 5,
                "/home/kali/workload/normal_behaviour_lab/normal_file_2.txt": 5,
                "/home/kali/workload/normal_behaviour_lab/normal_file_3.txt": 5,
                "/home/kali/workload/normal_behaviour_lab/normal_file_4.txt": 5,
            },
            "__event_types__": {
                "create": 5,
                "modify": 20,
            },
            "__duplicate_hash_count__": 4,
        },
    )

    assert handled == set()
    assert calls == []


def test_file_preflight_detects_default_observe_without_terminating(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": kwargs["persistence_state"]["stage"],
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
    assert len(calls) == 1
    assert calls[0]["classification"]["label"] == "worm"
    assert calls[0]["persistence_state"]["stage"] == "observe"


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
    assert len(calls) == 1
    assert calls[0]["classification"]["label"] == "worm"
    assert calls[0]["persistence_state"]["stage"] == "observe"


def test_file_preflight_detects_low_and_slow_replication_memory(monkeypatch):
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
            "learning": {
                "recommended_action": "terminate"
            },
        },
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )

    processes = [
        {
            "pid": 50007,
            "ppid": 100,
            "name": "python",
            "cmdline": "python edr_12_tests_runner.py --test 12",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/workload",
            "age_seconds": 55,
        }
    ]

    handled = set()

    for generation in range(15):
        handled = main_mod.emergency_file_activity_preflight(
            processes,
            {
                "__paths__": {
                    (
                        "/home/kali/workload/p12_low_slow_lab/"
                        f"gen_{generation}/copy_a_{generation}.txt"
                    ): 1,
                    (
                        "/home/kali/workload/p12_low_slow_lab/"
                        f"gen_{generation}/copy_b_{generation}.txt"
                    ): 1,
                },
                "__event_types__": {
                    "create": 2,
                    "modify": 2,
                },
                "__duplicate_hash_count__": 1,
            },
        )

    assert handled == {50007}
    assert calls
    assert calls[-1]["features"]["low_slow_file_replication"] is True
    assert calls[-1]["persistence_state"]["stage"] == "terminate"
    assert calls[-1]["persistence_state"]["force_terminate"] is True


def test_file_preflight_terminates_suspicious_rename_burst_early(monkeypatch):
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
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )

    processes = [
        {
            "pid": 50008,
            "ppid": 100,
            "name": "python",
            "cmdline": "python n.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                (
                    "/home/kali/Downloads/self_healing2.o-main/"
                    f"p7_file_rename_lab/document_{index}.locked"
                ): 1
                for index in range(7)
            },
            "__event_types__": {
                "rename": 7,
            },
        },
    )

    assert handled == {50008}
    assert calls
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["features"]["f_suspicious_rename"] == 1
    assert calls[0]["features"]["rename_events"] == 7
    assert (
        calls[0]["classification"]["signals"]["correlated_signals"][
            "suspicious_rename"
        ]
        is True
    )


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


def test_file_preflight_does_not_terminate_terminal_launched_simple_program(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 50009,
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs) or {
            "response": {
                "stage": kwargs["persistence_state"]["stage"],
                "status": "monitoring",
                "action_taken": False,
            },
            "learning": {},
        },
    )
    monkeypatch.setenv(
        "SELF_HEALING_BEHAVIOR_CONTAINMENT",
        "true",
    )
    monkeypatch.setenv(
        "SELF_HEALING_ENABLE_FILE_CONTAINMENT",
        "false",
    )

    main_mod.file_burst_window.clear()

    processes = [
        {
            "pid": 50009,
            "ppid": 100,
            "name": "python",
            "cmdline": "python program.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "age_seconds": 3,
        }
    ]

    handled = main_mod.emergency_file_activity_preflight(
        processes,
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/program.log": 66,
            }
        },
    )

    assert handled == {50009}
    assert calls
    assert calls[0]["persistence_state"]["stage"] == "observe"
    assert calls[0]["persistence_state"]["force_terminate"] is False


def test_file_preflight_terminates_terminal_replication_fanout(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 50010,
    )
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
    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setenv("SELF_HEALING_ENABLE_FILE_CONTAINMENT", "false")

    main_mod.file_burst_window.clear()

    handled = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50010,
                "ppid": 100,
                "name": "python",
                "cmdline": "python 5.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 3,
            }
        ],
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/p5_file_replication_lab/gen_0/copy_1.txt": 30,
                "/home/kali/Downloads/self_healing2.o-main/p5_file_replication_lab/gen_1/copy_31.txt": 30,
            }
        },
    )

    assert handled == {50010}
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["persistence_state"]["catastrophic_ready"] is True
    assert calls[0]["features"]["subtree_fanout"] >= 2


def test_file_preflight_terminates_terminal_mass_modification(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 50011,
    )
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
    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setenv("SELF_HEALING_ENABLE_FILE_CONTAINMENT", "false")

    main_mod.file_burst_window.clear()

    handled = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50011,
                "ppid": 100,
                "name": "python",
                "cmdline": "python 6.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 3,
            }
        ],
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/p6_file_modification_lab/file_1.txt": 80,
            },
            "__event_types__": {
                "modify": 80,
            },
        },
    )

    assert handled == {50011}
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["features"]["f_mass_file_modification"] == 1


def test_file_preflight_terminates_terminal_rename_burst(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 50012,
    )
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
    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setenv("SELF_HEALING_ENABLE_FILE_CONTAINMENT", "false")

    main_mod.file_burst_window.clear()

    handled = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50012,
                "ppid": 100,
                "name": "python",
                "cmdline": "python 7.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 3,
            }
        ],
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/p7_file_rename_lab/document_1.locked": 10,
            },
            "__event_types__": {
                "rename": 10,
            },
        },
    )

    assert handled == {50012}
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["features"]["f_suspicious_rename"] == 1


def test_file_preflight_does_not_blame_new_program_for_previous_attack(monkeypatch):
    calls = []
    current_time = {
        "value": 1000.0
    }

    monkeypatch.setattr(
        main_mod.time,
        "time",
        lambda: current_time["value"],
    )
    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid in {50020, 50021},
    )
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
    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setenv("SELF_HEALING_ENABLE_FILE_CONTAINMENT", "false")

    handled_attack = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50020,
                "ppid": 100,
                "name": "python",
                "cmdline": "python 5.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 3,
            }
        ],
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/p5_file_replication_lab/gen_0/copy_1.txt": 30,
                "/home/kali/Downloads/self_healing2.o-main/p5_file_replication_lab/gen_1/copy_31.txt": 30,
            }
        },
    )

    current_time["value"] = 1003.0

    handled_program = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50021,
                "ppid": 100,
                "name": "python",
                "cmdline": "python program.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 1,
            }
        ],
        {},
    )

    assert handled_attack == {50020}
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert handled_program == set()
    assert len(calls) == 1


def test_file_preflight_does_not_attach_global_duplicate_burst_to_program(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 50022,
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )
    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")

    handled = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50022,
                "ppid": 100,
                "name": "python",
                "cmdline": "python program.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 1,
            }
        ],
        {
            "__paths__": {
                "/tmp/unrelated_attack/copy_1.txt": 2,
            },
            "__duplicate_hash_count__": 10,
        },
    )

    assert handled == set()
    assert calls == []


def test_file_preflight_does_not_attach_global_rename_burst_to_program(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 50023,
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )
    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")

    handled = main_mod.emergency_file_activity_preflight(
        [
            {
                "pid": 50023,
                "ppid": 100,
                "name": "python",
                "cmdline": "python program.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "age_seconds": 1,
            }
        ],
        {
            "__paths__": {
                "/tmp/unrelated_attack/document.locked": 2,
            },
            "__event_types__": {
                "rename": 10,
            },
        },
    )

    assert handled == set()
    assert calls == []


def test_process_storm_preflight_targets_terminal_child_storm(monkeypatch):
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

    assert handled == {60025}
    assert calls
    assert calls[0]["pid"] == 60025
    assert calls[0]["process"]["ppid"] == 60000
    assert calls[0]["process"]["observed_family_pids"] == [
        child["pid"]
        for child in reversed(children)
    ]
    assert calls[0]["features"]["protected_parent_pid"] == 60000
    assert calls[0]["persistence_state"]["stage"] == "terminate"


def test_process_storm_preflight_does_not_kill_single_terminal_child_from_learning(monkeypatch):
    calls = []

    class FakeLearningEngine:
        def is_learned_terminate_pattern(self, process_info, classification):
            return True

    monkeypatch.setattr(
        main_mod,
        "learning_engine",
        FakeLearningEngine(),
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )

    now = time.time()
    parent = {
        "pid": 60100,
        "ppid": 100,
        "name": "qterminal",
        "cmdline": "qterminal",
        "exe": "/usr/bin/qterminal",
        "cwd": "/home/kali",
        "create_time": now - 5,
        "age_seconds": 5,
    }
    child = {
        "pid": 60101,
        "ppid": 60100,
        "name": "python",
        "cmdline": "python program.py",
        "exe": "/usr/bin/python",
        "cwd": "/home/kali/Downloads/self_healing2.o-main",
        "create_time": now - 1,
        "age_seconds": 1,
    }

    handled = main_mod.emergency_process_storm_preflight(
        [parent, child],
        {},
        {},
    )

    assert handled == set()
    assert calls == []


def test_process_storm_preflight_skips_dashboard_controller(monkeypatch):
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
        "pid": 60500,
        "ppid": 100,
        "name": "streamlit",
        "cmdline": "streamlit run dashboard.py",
        "exe": "/usr/bin/streamlit",
        "cwd": "/home/kali/Downloads/self_healing2.o-main",
        "create_time": now - 6,
        "age_seconds": 6,
    }
    children = [
        {
            "pid": 60501 + index,
            "ppid": 60500,
            "name": "python",
            "cmdline": "python streamlit worker",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
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


def test_process_storm_preflight_uses_learned_fast_path(monkeypatch):
    calls = []

    class FakeLearningEngine:
        def is_learned_terminate_pattern(self, process_info, classification):
            return True

    monkeypatch.setattr(
        main_mod,
        "learning_engine",
        FakeLearningEngine(),
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

    now = time.time()
    parent = {
        "pid": 60600,
        "ppid": 100,
        "name": "python",
        "cmdline": "python worm_sim.py",
        "exe": "/usr/bin/python",
        "cwd": "/home/kali/Downloads/self_healing2.o-main",
        "create_time": now - 4,
        "age_seconds": 4,
    }
    children = [
        {
            "pid": 60601 + index,
            "ppid": 60600,
            "name": "python",
            "cmdline": "python worm_sim.py worker",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "create_time": now - 1,
            "age_seconds": 1,
        }
        for index in range(3)
    ]

    handled = main_mod.emergency_process_storm_preflight(
        [parent] + children,
        {},
        {},
    )

    assert handled == {60600}
    assert calls
    assert calls[0]["features"]["learned_pattern_fast_path"] is True
    assert calls[0]["persistence_state"]["stage"] == "terminate"


def test_process_storm_preflight_ignores_tiny_learned_family(monkeypatch):
    calls = []

    class FakeLearningEngine:
        def is_learned_terminate_pattern(self, process_info, classification):
            return True

    monkeypatch.setattr(
        main_mod,
        "learning_engine",
        FakeLearningEngine(),
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )

    now = time.time()
    parent = {
        "pid": 60650,
        "ppid": 100,
        "name": "python",
        "cmdline": "python program.py",
        "exe": "/usr/bin/python",
        "cwd": "/home/kali/Downloads/self_healing2.o-main",
        "create_time": now - 4,
        "age_seconds": 4,
    }
    children = [
        {
            "pid": 60651 + index,
            "ppid": 60650,
            "name": "python",
            "cmdline": "python helper.py",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "create_time": now - 1,
            "age_seconds": 1,
        }
        for index in range(2)
    ]

    handled = main_mod.emergency_process_storm_preflight(
        [parent] + children,
        {},
        {},
    )

    assert handled == set()
    assert calls == []


def test_process_storm_preflight_keeps_unknown_small_storm_below_threshold(monkeypatch):
    calls = []

    class FakeLearningEngine:
        def is_learned_terminate_pattern(self, process_info, classification):
            return False

    monkeypatch.setattr(
        main_mod,
        "learning_engine",
        FakeLearningEngine(),
    )
    monkeypatch.setattr(
        main_mod,
        "execute_healing",
        lambda **kwargs: calls.append(kwargs),
    )

    now = time.time()
    parent = {
        "pid": 60700,
        "ppid": 100,
        "name": "python",
        "cmdline": "python unknown_worker.py",
        "exe": "/usr/bin/python",
        "cwd": "/home/kali/Downloads/self_healing2.o-main",
        "create_time": now - 4,
        "age_seconds": 4,
    }
    children = [
        {
            "pid": 60701 + index,
            "ppid": 60700,
            "name": "python",
            "cmdline": "python unknown_worker.py child",
            "exe": "/usr/bin/python",
            "cwd": "/home/kali/Downloads/self_healing2.o-main",
            "create_time": now - 1,
            "age_seconds": 1,
        }
        for index in range(4)
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
                "/home/kali/workload/launch_agents/fake_persistence_1.json": 2,
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


def test_behavior_terminal_thread_storm_terminates(monkeypatch):
    calls = []

    monkeypatch.setenv("SELF_HEALING_BEHAVIOR_CONTAINMENT", "true")
    monkeypatch.setattr(
        main_mod,
        "_has_operator_ancestor",
        lambda pid: pid == 62014,
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
                "pid": 62014,
                "ppid": 100,
                "name": "python",
                "cmdline": "python 2.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "threads": 28,
                "age_seconds": 2,
            }
        ],
        {},
    )

    assert handled == {62014}
    assert calls[0]["features"]["f_thread_storm"] == 1
    assert calls[0]["features"]["f_operator_launched"] == 1
    assert calls[0]["persistence_state"]["stage"] == "terminate"
    assert calls[0]["persistence_state"]["catastrophic_ready"] is True


def test_behavior_cpu_exhaustion_without_file_or_network_correlation_observes(monkeypatch):
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

    assert handled == set()
    assert calls == []


def test_behavior_combined_resource_and_file_replication_terminates(monkeypatch):
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
                "cmdline": "python na.py",
                "exe": "/usr/bin/python",
                "cwd": "/home/kali/Downloads/self_healing2.o-main",
                "cpu": 91,
                "threads": 26,
                "age_seconds": 2,
            }
        ],
        {},
        {
            "__paths__": {
                "/home/kali/Downloads/self_healing2.o-main/p11_combined_worm_lab/gen_0/copy_1.txt": 1,
                "/home/kali/Downloads/self_healing2.o-main/p11_combined_worm_lab/gen_0/copy_2.txt": 1,
                "/home/kali/Downloads/self_healing2.o-main/p11_combined_worm_lab/gen_0/copy_3.txt": 1,
                "/home/kali/Downloads/self_healing2.o-main/p11_combined_worm_lab/gen_0/copy_4.txt": 1,
                "/home/kali/Downloads/self_healing2.o-main/p11_combined_worm_lab/gen_0/copy_5.txt": 1,
            }
        },
    )

    assert handled == {62004}
    assert calls[0]["features"]["f_cpu_exhaustion"] == 1
    assert calls[0]["features"]["f_file_replication"] == 1
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
                "threads": 45,
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
