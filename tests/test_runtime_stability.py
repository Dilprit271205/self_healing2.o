import importlib


def test_monitor_defaults_are_stability_oriented(monkeypatch):
    monkeypatch.delenv("SELF_HEALING_MONITOR_INTERVAL", raising=False)
    monkeypatch.delenv("SELF_HEALING_NETWORK_SCAN_INTERVAL", raising=False)

    import main
    from monitor.network_monitor import NetworkMonitor

    main = importlib.reload(main)

    assert main.MONITOR_INTERVAL >= 3.0
    assert 1.0 <= NetworkMonitor().scan_interval <= 4.0


def test_dashboard_log_window_is_bounded():
    import dashboard

    assert dashboard.DASHBOARD_MAX_ROWS <= 1000


def test_dashboard_healing_status_overlays_process_stage():
    import pandas as pd
    import dashboard

    process_rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-06-03T10:00:00"),
            "pid": 1234,
            "name": "python",
            "stage": "observe",
            "response": "none",
            "severity": "critical",
            "worm_score": 0.9,
            "features": {},
            "signals": {},
        }
    ])
    healing_rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-06-03T10:00:02"),
            "pid": 1234,
            "stage": "terminate",
            "status": "terminated targets=1",
            "action_taken": True,
        }
    ])

    merged = dashboard._overlay_healing_status(
        process_rows,
        healing_rows,
        process_rows,
    )

    assert merged.iloc[0]["stage"] == "terminate"
    assert merged.iloc[0]["response"] == "terminated targets=1"
    assert merged.iloc[0]["action_taken"] is True


def test_dashboard_acceptance_coverage_tracks_behavior_flags():
    import pandas as pd
    import dashboard

    latest_rows = pd.DataFrame([
        {
            "pid": 1,
            "name": "python",
            "stage": "terminate",
            "response": "terminated",
            "beacon_detected": True,
            "persistence_detected": True,
            "sensitive_access_detected": True,
        }
    ])
    signal_rows = [
        {
            "signals": {
                "forkbomb_detected": True,
                "replication_detected": True,
                "correlated_signals": {
                    "thread_explosion": True,
                    "cpu_memory_escalation": True,
                    "resource_pressure": True,
                    "mass_file_modification": True,
                    "suspicious_rename": True,
                },
            }
        }
    ]

    coverage = dashboard._acceptance_coverage_rows(
        latest_rows,
        signal_rows,
    )

    assert len(coverage) == 12
    assert coverage["coverage"].sum() >= 10
