import importlib


def test_monitor_defaults_are_stability_oriented(monkeypatch):
    monkeypatch.delenv("SELF_HEALING_MONITOR_INTERVAL", raising=False)
    monkeypatch.delenv("SELF_HEALING_NETWORK_SCAN_INTERVAL", raising=False)

    import main
    from monitor.network_monitor import NetworkMonitor
    from monitor import process_monitor

    main = importlib.reload(main)
    process_monitor = importlib.reload(process_monitor)

    assert 0.25 <= main.MONITOR_INTERVAL <= 0.75
    assert 0.10 <= NetworkMonitor().scan_interval <= 0.50


def test_process_sampling_default_is_low_latency(monkeypatch):
    monkeypatch.delenv("SELF_HEALING_PROCESS_SAMPLE_SECONDS", raising=False)

    from monitor import process_monitor

    slept = []
    monkeypatch.setattr(
        process_monitor,
        "init_cpu",
        lambda: None,
    )
    monkeypatch.setattr(
        process_monitor.time,
        "sleep",
        lambda seconds: slept.append(seconds),
    )
    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs=None: [],
    )

    assert process_monitor.get_process_data() == []
    assert slept
    assert slept[0] <= 0.10


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


def test_dashboard_ignores_stale_healing_status_for_reused_pid():
    import pandas as pd
    import dashboard

    process_rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-06-03T10:05:00"),
            "pid": 1234,
            "name": "python",
            "stage": "observe",
            "response": "none",
            "severity": "low",
        }
    ])
    healing_rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-06-03T10:00:00"),
            "pid": 1234,
            "stage": "terminate",
            "status": "terminated old attack",
            "action_taken": True,
        }
    ])

    merged = dashboard._overlay_healing_status(
        process_rows,
        healing_rows,
        process_rows,
    )

    assert merged.iloc[0]["stage"] == "observe"
    assert merged.iloc[0]["response"] == "none"


def test_dashboard_normalizes_missing_dict_columns():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-06-04T01:00:00"),
            "pid": 8501,
            "name": "streamlit",
            "label": "suspicious",
            "severity": "medium",
            "signals": {"category_suppressed": True},
        }
    ])

    normalized = dashboard._normalize_process_rows(rows)

    assert "signals" in normalized.columns
    assert "anomalies" in normalized.columns
    assert "features" in normalized.columns
    assert normalized.iloc[0]["signals"] == {"category_suppressed": True}
    assert bool(normalized.iloc[0]["flagged"]) is False


def test_dashboard_does_not_flag_weak_suspicious_observation():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 222,
            "name": "python",
            "label": "suspicious",
            "severity": "medium",
            "worm_score": 0.42,
            "dynamic_trust": 0.94,
            "final_trust": 0.94,
            "static_trust": 0.85,
            "signals": {"correlated_signal_count": 0},
            "features": {},
            "anomalies": {"aggregate": 0.02},
        }
    ])

    normalized = dashboard._normalize_process_rows(rows)

    assert bool(normalized.iloc[0]["flagged"]) is False


def test_dashboard_flags_confirmed_or_strong_behavior():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 333,
            "name": "python",
            "label": "suspicious",
            "severity": "medium",
            "worm_score": 0.68,
            "dynamic_trust": 0.80,
            "final_trust": 0.80,
            "static_trust": 0.85,
            "signals": {"replication_detected": True},
            "features": {},
            "anomalies": {"aggregate": 0.20},
        }
    ])

    normalized = dashboard._normalize_process_rows(rows)

    assert bool(normalized.iloc[0]["flagged"]) is True


def test_dashboard_trust_score_tracks_raw_trust_without_active_risk():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 444,
            "name": "python",
            "label": "normal",
            "severity": "low",
            "stage": "observe",
            "worm_score": 0.20,
            "dynamic_trust": 0.65,
            "final_trust": 0.80,
            "static_trust": 0.85,
            "signals": {"correlated_signal_count": 0},
            "features": {},
            "anomalies": {"aggregate": 0.35},
        }
    ])

    normalized = dashboard._normalize_process_rows(rows)

    assert bool(normalized.iloc[0]["flagged"]) is False
    assert dashboard._dashboard_trust_score(normalized) == 0.80
    assert dashboard._dashboard_pressure_score(normalized) == 0.35


def test_dashboard_low_trust_drift_is_not_an_active_flag_without_evidence():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 446,
            "name": "python",
            "label": "normal",
            "severity": "low",
            "stage": "observe",
            "response": "none",
            "worm_score": 0.10,
            "dynamic_trust": 0.62,
            "final_trust": 0.68,
            "static_trust": 0.85,
            "signals": {"correlated_signal_count": 0},
            "features": {},
            "anomalies": {"aggregate": 0.10},
        }
    ])

    normalized = dashboard._normalize_process_rows(rows)

    assert bool(normalized.iloc[0]["flagged"]) is False
    assert dashboard._active_flag_rows(normalized).empty


def test_dashboard_high_severity_without_evidence_is_not_security_memory():
    import pandas as pd
    import dashboard

    rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 447,
            "name": "python",
            "label": "suspicious",
            "severity": "high",
            "stage": "observe",
            "response": "monitoring",
            "worm_score": 0.20,
            "dynamic_trust": 0.90,
            "final_trust": 0.90,
            "static_trust": 0.85,
            "signals": {"correlated_signal_count": 0},
            "features": {},
            "anomalies": {},
        }
    ]))

    assert bool(rows.iloc[0]["flagged"]) is False
    assert dashboard._security_event_mask(rows).tolist() == [False]


def test_dashboard_trust_score_uses_raw_risk_when_flagged():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 445,
            "name": "python",
            "label": "worm",
            "severity": "critical",
            "stage": "terminate",
            "worm_score": 0.90,
            "dynamic_trust": 0.45,
            "final_trust": 0.55,
            "static_trust": 0.85,
            "signals": {"replication_detected": True},
            "features": {},
            "anomalies": {"aggregate": 0.55},
        }
    ])

    normalized = dashboard._normalize_process_rows(rows)

    assert bool(normalized.iloc[0]["flagged"]) is True
    assert dashboard._dashboard_trust_score(normalized) == 0.55
    assert dashboard._dashboard_pressure_score(normalized) == 0.55


def test_runtime_attention_filter_ignores_weak_suspicious_label():
    import main

    classification = {
        "label": "suspicious",
        "severity": "medium",
        "worm_score": 0.42,
        "signals": {"correlated_signal_count": 0},
    }
    trust_state = {
        "final_trust": 0.94,
    }

    assert main.is_attention_worthy_classification(
        classification,
        trust_state,
    ) is False


def test_runtime_attention_filter_ignores_normal_low_score_process():
    import main

    classification = {
        "label": "normal",
        "severity": "low",
        "worm_score": 0.408,
        "signals": {"correlated_signal_count": 0},
    }
    trust_state = {
        "final_trust": 0.94,
    }

    assert main.is_attention_worthy_classification(
        classification,
        trust_state,
    ) is False


def test_runtime_attention_filter_ignores_high_severity_without_evidence():
    import main

    classification = {
        "label": "suspicious",
        "severity": "high",
        "worm_score": 0.20,
        "signals": {"correlated_signal_count": 0},
    }
    trust_state = {
        "final_trust": 0.90,
    }

    assert main.is_attention_worthy_classification(
        classification,
        trust_state,
    ) is False


def test_runtime_attention_filter_keeps_confirmed_behavior():
    import main

    classification = {
        "label": "suspicious",
        "severity": "medium",
        "worm_score": 0.42,
        "signals": {"replication_detected": True},
    }
    trust_state = {
        "final_trust": 0.94,
    }

    assert main.is_attention_worthy_classification(
        classification,
        trust_state,
    ) is True


def test_dashboard_prefers_recent_live_rows_for_metrics():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    rows = pd.DataFrame([
        {
            "timestamp": now - pd.Timedelta(minutes=10),
            "pid": 1,
            "final_trust": 0.10,
        },
        {
            "timestamp": now,
            "pid": 2,
            "final_trust": 0.92,
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=45,
    )

    assert set(recent["pid"]) == {2}


def test_dashboard_ignores_future_rows_when_selecting_live_window():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    rows = pd.DataFrame([
        {
            "timestamp": now + pd.Timedelta(hours=8),
            "pid": 1,
            "final_trust": 0.10,
        },
        {
            "timestamp": now,
            "pid": 2,
            "final_trust": 0.92,
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=45,
    )

    assert set(recent["pid"]) == {2}


def test_dashboard_drops_stale_rows_from_live_window():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now() - pd.Timedelta(minutes=5),
            "pid": 1,
            "final_trust": 0.10,
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=12,
    )

    assert recent.empty


def test_dashboard_ignores_fresh_log_append_time_when_row_timestamp_is_stale():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now() - pd.Timedelta(days=3),
            "_source_mtime": pd.Timestamp.now(),
            "pid": 1,
            "final_trust": 0.25,
            "stage": "terminate",
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=12,
    )

    assert recent.empty


def test_dashboard_uses_fresh_log_append_time_when_row_has_no_timestamp():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "_source_mtime": pd.Timestamp.now(),
            "pid": 1,
            "final_trust": 0.25,
            "stage": "terminate",
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=12,
    )

    assert set(recent["pid"]) == {1}


def test_dashboard_recent_rows_union_timestamp_and_log_append_time():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    rows = pd.DataFrame([
        {
            "timestamp": now,
            "_source_mtime": now,
            "pid": 1,
            "stage": "observe",
        },
        {
            "timestamp": now - pd.Timedelta(hours=3),
            "_source_mtime": now,
            "pid": 2,
            "stage": "terminate",
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=12,
    )

    assert set(recent["pid"]) == {1}


def test_dashboard_log_append_time_does_not_revive_stale_timestamped_alerts():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    rows = pd.DataFrame([
        {
            "timestamp": now - pd.Timedelta(hours=3),
            "_source_mtime": now,
            "pid": 1,
            "stage": "terminate",
            "severity": "critical",
        },
    ])

    recent = dashboard._recent_rows(
        rows,
        seconds=12,
    )

    assert recent.empty


def test_runtime_log_paths_are_repo_root_relative(monkeypatch):
    from pathlib import Path
    import dashboard
    from logger import logger as runtime_logger
    from analysis import learning_engine

    monkeypatch.delenv("SELF_HEALING_SYSTEM_LOG", raising=False)
    monkeypatch.delenv("SELF_HEALING_KB_PATH", raising=False)

    root = Path(__file__).resolve().parent.parent

    assert dashboard._project_path(
        "SELF_HEALING_SYSTEM_LOG",
        "logs/system_log.json",
    ) == root / "logs" / "system_log.json"
    assert Path(runtime_logger.project_path(
        "SELF_HEALING_SYSTEM_LOG",
        "logs/system_log.json",
    )) == root / "logs" / "system_log.json"
    assert Path(learning_engine.project_path(
        "SELF_HEALING_KB_PATH",
        "logs/learning_kb.json",
    )) == root / "logs" / "learning_kb.json"


def test_dashboard_learning_rows_normalize_for_visuals():
    import pandas as pd
    import dashboard

    kb = pd.DataFrame([
        {
            "pattern_id": "p1",
            "attack_family": "process_storm",
            "recommended_stage": "terminate",
            "confidence": 91,
            "avg_pattern_strength": 0.8,
            "avg_trust_anomaly_pressure": 0.7,
            "observations": 5,
        },
    ])

    prepared = dashboard._prepare_learning_rows(kb)

    assert prepared.iloc[0]["confidence"] == 0.91
    assert prepared.iloc[0]["confidence_pct"] == 91.0
    assert prepared.iloc[0]["strength_pct"] == 80.0
    assert prepared.iloc[0]["readiness_pct"] > 70


def test_dashboard_learning_action_summary_is_readable():
    import pandas as pd
    import dashboard

    kb = pd.DataFrame([
        {
            "pattern_id": "p1",
            "attack_family": "process_storm",
            "recommended_stage": "terminate",
            "confidence": 0.9,
            "avg_pattern_strength": 0.8,
            "observations": 5,
        },
        {
            "pattern_id": "p2",
            "attack_family": "thread_storm",
            "recommended_stage": "throttle",
            "confidence": 0.6,
            "avg_pattern_strength": 0.5,
            "observations": 2,
        },
    ])

    summary = dashboard._learning_action_summary(kb)

    assert set(summary["recommended_stage"]) == {"terminate", "throttle"}
    assert {"patterns", "avg_confidence", "avg_readiness", "max_observations"}.issubset(
        summary.columns
    )


def test_dashboard_live_latest_rows_never_falls_back_to_stale_history():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now() - pd.Timedelta(minutes=5),
            "pid": 1,
            "final_trust": 0.10,
            "stage": "terminate",
        },
    ])

    latest = dashboard._live_latest_rows(
        rows,
        seconds=12,
    )

    assert latest.empty


def test_dashboard_tail_security_rows_keep_stale_timestamp_alerts_visible():
    import pandas as pd
    import dashboard

    rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": pd.Timestamp.now() - pd.Timedelta(hours=3),
            "pid": 99,
            "name": "python",
            "label": "worm",
            "severity": "critical",
            "stage": "terminate",
            "response": "terminated targets=1",
            "worm_score": 0.95,
            "final_trust": 0.25,
            "dynamic_trust": 0.25,
            "static_trust": 0.85,
            "signals": {
                "catastrophic_behavior": True,
            },
            "features": {},
            "anomalies": {},
        },
    ]))

    recent = dashboard._recent_security_rows(
        rows,
        seconds=12,
    )
    tail = dashboard._tail_security_rows(
        rows,
        limit=50,
    )
    alerts = dashboard._alert_rows(
        tail,
    )

    assert recent.empty
    assert set(tail["pid"]) == {99}
    assert alerts[0]["stage"] == "terminate"


def test_dashboard_security_rows_combine_recent_and_tail_alert_sources():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": now - pd.Timedelta(hours=2),
            "pid": 10,
            "name": "old-clock.py",
            "label": "worm",
            "severity": "critical",
            "stage": "terminate",
            "response": "terminated targets=1",
            "worm_score": 0.95,
            "final_trust": 0.25,
            "dynamic_trust": 0.25,
            "static_trust": 0.85,
            "signals": {"catastrophic_behavior": True},
            "features": {},
            "anomalies": {},
        },
        {
            "_log_index": 2,
            "timestamp": now,
            "pid": 11,
            "name": "fresh.py",
            "label": "suspicious",
            "severity": "high",
            "stage": "throttle",
            "response": "throttled cpu",
            "worm_score": 0.70,
            "final_trust": 0.65,
            "dynamic_trust": 0.65,
            "static_trust": 0.85,
            "signals": {"thread_storm_detected": True},
            "features": {},
            "anomalies": {},
        },
    ]))

    security = dashboard._dashboard_security_rows(
        rows,
        seconds=12,
        tail_limit=50,
    )

    assert set(security["pid"]) == {10, 11}


def test_dashboard_state_keeps_recent_security_event_after_live_window():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": pd.Timestamp.now() - pd.Timedelta(seconds=30),
            "pid": 1,
            "final_trust": 0.30,
            "stage": "terminate",
            "severity": "critical",
            "flagged": True,
        },
    ])

    latest = dashboard._dashboard_state_rows(
        rows,
        live_seconds=12,
        event_seconds=60,
    )

    assert set(latest["pid"]) == {1}
    assert latest.iloc[0]["final_trust"] == 0.30


def test_dashboard_state_expires_old_security_events():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": pd.Timestamp.now() - pd.Timedelta(minutes=5),
            "pid": 1,
            "final_trust": 0.30,
            "stage": "terminate",
            "severity": "critical",
            "flagged": True,
        },
    ])

    latest = dashboard._dashboard_state_rows(
        rows,
        live_seconds=12,
        event_seconds=60,
    )

    assert latest.empty


def test_dashboard_state_keeps_security_event_after_normal_followup():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": pd.Timestamp.now() - pd.Timedelta(seconds=40),
            "pid": 1,
            "final_trust": 0.30,
            "stage": "terminate",
            "severity": "critical",
            "flagged": True,
        },
        {
            "_log_index": 2,
            "timestamp": pd.Timestamp.now() - pd.Timedelta(seconds=30),
            "pid": 1,
            "final_trust": 1.0,
            "stage": "observe",
            "severity": "low",
            "flagged": False,
        },
    ])

    latest = dashboard._dashboard_state_rows(
        rows,
        live_seconds=12,
        event_seconds=60,
    )

    assert set(latest["pid"]) == {1}
    assert latest.iloc[0]["stage"] == "terminate"
    assert bool(latest.iloc[0]["flagged"]) is True


def test_dashboard_recent_security_rows_do_not_revive_stale_timestamped_alerts():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": now - pd.Timedelta(hours=3),
            "_source_mtime": now,
            "pid": 99,
            "name": "python",
            "label": "worm",
            "severity": "critical",
            "stage": "terminate",
            "response": "terminated targets=1",
            "worm_score": 0.95,
            "final_trust": 0.25,
            "dynamic_trust": 0.25,
            "static_trust": 0.85,
            "signals": {
                "catastrophic_behavior": True,
            },
            "features": {},
            "anomalies": {},
        },
    ]))

    security = dashboard._recent_security_rows(
        rows,
        seconds=12,
    )
    alerts = dashboard._alert_rows(
        security,
    )

    assert security.empty
    assert alerts == []


def test_policy_protects_kernel_worker_names():
    from analysis.policy_engine import policy_engine
    from analysis.response_engine import ResponseEngine

    for name in ("jbd2/sda1-8", "khugepaged"):
        process = {
            "name": name,
            "cmdline": name,
            "exe": "",
            "cwd": "",
        }
        category = policy_engine.infer_category(process)

        assert category == "system_kernel"
        assert policy_engine.is_suppressed_category(category)
        assert ResponseEngine().is_protected_process(
            329,
            name,
            name,
            "",
            "",
        )


def test_dashboard_healing_rows_fill_kpis_when_process_rows_missing():
    import pandas as pd
    import dashboard

    healing = pd.DataFrame([
        {
            "_log_index": 0,
            "timestamp": pd.Timestamp.now(),
            "pid": 1234,
            "stage": "terminate",
            "action_taken": True,
            "status": "terminated targets=1",
        },
    ])

    fallback = dashboard._healing_rows_as_process_rows(
        healing,
        seconds=60,
    )

    assert set(fallback["pid"]) == {1234}
    assert bool(fallback.iloc[0]["flagged"]) is True
    assert dashboard._dashboard_trust_score(fallback) == 0.25


def test_dashboard_merges_recent_healing_actions_with_process_rows():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    process_rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "_log_index": 10,
            "timestamp": now,
            "pid": 100,
            "name": "python",
            "label": "normal",
            "severity": "low",
            "stage": "observe",
            "response": "none",
            "final_trust": 1.0,
            "dynamic_trust": 1.0,
            "static_trust": 0.85,
            "signals": {},
            "features": {},
            "anomalies": {},
        },
    ]))
    healing_rows = dashboard._healing_rows_as_process_rows(
        pd.DataFrame([
            {
                "_log_index": 20,
                "timestamp": now,
                "pid": 200,
                "stage": "terminate",
                "action_taken": True,
                "status": "terminated targets=1",
            },
        ]),
        seconds=60,
    )

    latest = dashboard._dashboard_state_rows(
        pd.concat(
            [
                process_rows,
                healing_rows,
            ],
            ignore_index=True,
        ),
        live_seconds=12,
        event_seconds=60,
    )

    assert set(latest["pid"]) == {100, 200}
    assert int(latest["flagged"].sum()) == 1
    assert int(
        latest["stage"]
        .astype(str)
        .str.lower()
        .isin(["terminate"])
        .sum()
    ) == 1


def test_dashboard_flag_rows_explain_evidence_and_action():
    import pandas as pd
    import dashboard

    rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 321,
            "name": "python",
            "label": "worm",
            "severity": "critical",
            "stage": "terminate",
            "response": "terminated targets=1",
            "worm_score": 0.92,
            "final_trust": 0.30,
            "dynamic_trust": 0.30,
            "static_trust": 0.85,
            "signals": {
                "replication_detected": True,
                "correlated_signals": {
                    "file_replication": True,
                },
            },
            "features": {},
            "anomalies": {},
        },
    ]))

    flags = dashboard._active_flag_rows(rows)

    assert not flags.empty
    assert "file replication" in flags.iloc[0]["why"]
    assert "Stopping the process family" in flags.iloc[0]["self_healing_action"]


def test_dashboard_alert_rows_describe_self_healing_action():
    import pandas as pd
    import dashboard

    rows = dashboard._normalize_process_rows(pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "_log_index": 5,
            "pid": 654,
            "name": "worm.py",
            "label": "worm",
            "severity": "critical",
            "stage": "terminate",
            "response": "terminated targets=3",
            "worm_score": 0.95,
            "final_trust": 0.20,
            "dynamic_trust": 0.20,
            "static_trust": 0.85,
            "signals": {
                "catastrophic_behavior": True,
            },
            "features": {},
            "anomalies": {},
        },
    ]))

    alerts = dashboard._alert_rows(rows)

    assert len(alerts) == 1
    assert alerts[0]["stage"] == "terminate"
    assert "catastrophic" in alerts[0]["why"]
    assert "Stopping the process family" in alerts[0]["action"]
    assert alerts[0]["status"] == "terminated targets=3"


def test_dashboard_security_mask_tracks_isolate_and_restrict_actions():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "pid": 1,
            "stage": "isolate",
            "response": "temporarily isolated",
            "flagged": False,
            "severity": "low",
        },
        {
            "pid": 2,
            "stage": "restrict",
            "response": "resource restricted",
            "flagged": False,
            "severity": "low",
        },
    ])

    mask = dashboard._security_event_mask(rows)

    assert mask.tolist() == [True, True]


def test_dashboard_healing_rows_expire_like_live_events():
    import pandas as pd
    import dashboard

    healing = pd.DataFrame([
        {
            "_log_index": 0,
            "timestamp": pd.Timestamp.now() - pd.Timedelta(minutes=5),
            "pid": 1234,
            "stage": "terminate",
            "action_taken": True,
            "status": "terminated targets=1",
        },
    ])

    fallback = dashboard._healing_rows_as_process_rows(
        healing,
        seconds=60,
    )

    assert fallback.empty


def test_dashboard_healing_rows_keep_action_after_observe_followup():
    import pandas as pd
    import dashboard

    now = pd.Timestamp.now()
    healing = pd.DataFrame([
        {
            "_log_index": 1,
            "timestamp": now - pd.Timedelta(seconds=20),
            "pid": 4321,
            "stage": "terminate",
            "action_taken": True,
            "status": "terminated targets=1",
        },
        {
            "_log_index": 2,
            "timestamp": now - pd.Timedelta(seconds=5),
            "pid": 4321,
            "stage": "observe",
            "action_taken": False,
            "status": "monitoring",
        },
    ])

    fallback = dashboard._healing_rows_as_process_rows(
        healing,
        seconds=60,
    )

    assert set(fallback["pid"]) == {4321}
    assert fallback.iloc[0]["stage"] == "terminate"
    assert bool(fallback.iloc[0]["flagged"]) is True


def test_dashboard_latest_by_pid_uses_log_append_order():
    import pandas as pd
    import dashboard

    rows = pd.DataFrame([
        {
            "_log_index": 0,
            "timestamp": pd.Timestamp("2026-06-05T10:34:00"),
            "pid": 1,
            "stage": "terminate",
        },
        {
            "_log_index": 1,
            "timestamp": pd.Timestamp("2026-06-05T01:18:00"),
            "pid": 1,
            "stage": "observe",
        },
    ])

    latest = dashboard._latest_by_pid(rows)

    assert latest.iloc[0]["stage"] == "observe"


def test_logger_emits_normal_state_after_interesting_state(monkeypatch):
    from logger import logger as runtime_logger

    runtime_logger.last_process_log.clear()
    runtime_logger.last_process_state.clear()
    monkeypatch.setattr(runtime_logger, "LOG_NORMAL_PROCESSES", False)
    monkeypatch.setattr(runtime_logger, "PROCESS_LOG_INTERVAL", 10.0)

    assert runtime_logger.should_log_process({
        "pid": 9001,
        "label": "worm",
        "severity": "critical",
        "stage": "terminate",
        "response": "terminated",
    })
    assert runtime_logger.should_log_process({
        "pid": 9001,
        "label": "normal",
        "severity": "low",
        "stage": "observe",
        "response": "none",
    })
    assert not runtime_logger.should_log_process({
        "pid": 9002,
        "label": "normal",
        "severity": "low",
        "stage": "observe",
        "response": "none",
    })


def test_logger_enqueue_latest_preserves_newest_when_queue_is_full():
    import queue
    from logger import logger as runtime_logger

    q = queue.Queue(maxsize=1)
    q.put_nowait({"pid": 1})
    before = runtime_logger.logger_drop_counts.get("process", 0)

    assert runtime_logger.enqueue_latest(
        q,
        {"pid": 2},
        "process",
    ) is True

    assert q.get_nowait() == {"pid": 2}
    assert runtime_logger.logger_drop_counts["process"] == before + 1


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


def test_incompatible_sklearn_model_metadata_retrains(tmp_path, monkeypatch):
    import json
    from analysis import ml_threat_model

    model_path = tmp_path / "threat_model.joblib"
    metadata_path = tmp_path / "threat_model.metadata.json"
    model_path.write_bytes(b"old-model")
    metadata_path.write_text(
        json.dumps(
            {
                "sklearn_version": "0.0",
                "feature_names": ml_threat_model.FEATURE_NAMES,
            }
        ),
        encoding="utf-8",
    )

    calls = []
    fake_model = object()

    monkeypatch.setattr(
        ml_threat_model,
        "MODEL_META_PATH",
        metadata_path,
    )
    monkeypatch.setattr(
        ml_threat_model,
        "train_and_save",
        lambda **kwargs: calls.append(kwargs) or fake_model,
    )

    model = ml_threat_model.load_or_train(
        model_path=model_path,
        log_path=str(tmp_path / "system_log.json"),
    )

    assert model is fake_model
    assert calls


def test_ml_training_uses_bounded_parallelism_and_behavior_labels(monkeypatch):
    from analysis import ml_threat_model

    monkeypatch.delenv("SELF_HEALING_ML_N_JOBS", raising=False)

    model = ml_threat_model.MLThreatModel.train([])

    assert model.report["training_n_jobs"] == 1
    assert model.report["behavior_labels"]["worm_like_behavior"] > 0
    assert model.report["behavior_labels"]["trust_anomaly_pattern"] > 0


def test_ml_detects_correlated_concurrent_worm_behavior():
    from analysis import ml_threat_model

    model = ml_threat_model.MLThreatModel.train([])
    prediction = model.predict(
        features={
            "f_connection_velocity": 9,
            "f_persistence_artifact": 1,
            "persistence_events": 2,
            "f_thread": 50,
            "threads": 50,
            "worm_score": 72,
        },
        anomaly_data={
            "anomalies": {
                "aggregate": 0.48,
                "worm_pattern": 0.5,
            }
        },
        trust_state={
            "dynamic_trust": 0.62,
            "final_trust": 0.65,
            "static_trust": 0.78,
        },
    )

    assert prediction.label == "worm"
    assert prediction.behavior_signals["worm_like_behavior"] is True


def test_research_dataset_profiles_include_benign_and_worm_rows():
    from analysis import ml_threat_model

    rows = ml_threat_model.load_training_rows(log_path="missing-log.json")
    labels = {
        row["label"]
        for row in rows
        if row.get("external_dataset")
    }

    assert {"normal", "worm", "suspicious"}.issubset(labels)


def test_external_research_csv_import_maps_cic_and_unsw_rows(tmp_path):
    from analysis import ml_threat_model

    cic = tmp_path / "cic.csv"
    cic.write_text(
        (
            "Label,Tot Fwd Pkts,Flow Pkts/s,Dst Port\n"
            "BENIGN,4,0.5,443\n"
            "Botnet,220,200,4444\n"
        ),
        encoding="utf-8",
    )
    unsw = tmp_path / "unsw.csv"
    unsw.write_text(
        (
            "attack_cat,spkts,dpkts,rate,ct_dst_src_ltm\n"
            "Normal,10,8,2,1\n"
            "Worms,120,130,80,20\n"
        ),
        encoding="utf-8",
    )

    rows = ml_threat_model.load_external_dataset_rows(
        [cic, unsw],
        max_rows_per_dataset=10,
    )

    labels = [row["label"] for row in rows]
    assert labels.count("normal") == 2
    assert labels.count("worm") == 2
    assert any(row["network_fanout"] == 1 for row in rows if row["label"] == "worm")
