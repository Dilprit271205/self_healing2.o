import importlib


def test_monitor_defaults_are_stability_oriented(monkeypatch):
    monkeypatch.delenv("SELF_HEALING_MONITOR_INTERVAL", raising=False)
    monkeypatch.delenv("SELF_HEALING_NETWORK_SCAN_INTERVAL", raising=False)

    import main
    from monitor.network_monitor import NetworkMonitor

    main = importlib.reload(main)

    assert main.MONITOR_INTERVAL >= 3.0
    assert NetworkMonitor().scan_interval >= 5.0


def test_dashboard_log_window_is_bounded():
    import dashboard

    assert dashboard.DASHBOARD_MAX_ROWS <= 2000
