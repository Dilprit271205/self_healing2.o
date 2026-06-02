import time

import main as main_mod


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
