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


def test_dashboard_trust_score_is_healthy_without_active_risk():
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
    assert dashboard._dashboard_trust_score(normalized) == 1.0
    assert dashboard._dashboard_pressure_score(normalized) == 0.0


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
