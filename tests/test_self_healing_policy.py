from analysis.self_healing_policy import (
    apply_self_healing_policy,
    evidence_domains,
)


def test_single_resource_signal_is_capped_below_termination():
    state = apply_self_healing_policy(
        process_info={
            "pid": 1,
            "name": "program",
            "cmdline": "./program",
            "cwd": "/home/kali/project",
        },
        classification={
            "label": "worm",
            "worm_score": 0.94,
            "confidence": 94,
            "signals": {
                "thread_storm_detected": True,
                "correlated_signals": {
                    "thread_explosion": True,
                    "resource_pressure": True,
                },
            },
        },
        persistence_state={
            "stage": "terminate",
            "termination_ready": True,
            "avg_combined_risk": 0.92,
        },
        trust_state={
            "final_trust": 0.30,
            "dynamic_trust": 0.30,
        },
    )

    assert state["stage"] == "throttle"
    assert state["termination_allowed"] is False


def test_multi_domain_worm_can_terminate_when_trust_collapses():
    state = apply_self_healing_policy(
        process_info={
            "pid": 2,
            "name": "python",
            "cmdline": "python combined_worm.py",
            "cwd": "/home/kali/lab",
        },
        classification={
            "label": "worm",
            "worm_score": 0.96,
            "confidence": 96,
            "signals": {
                "replication_detected": True,
                "fanout_detected": True,
                "thread_storm_detected": True,
                "correlated_signals": {
                    "file_replication": True,
                    "network_fanout": True,
                    "thread_explosion": True,
                    "resource_pressure": True,
                },
            },
        },
        persistence_state={
            "stage": "terminate",
            "termination_ready": True,
            "avg_combined_risk": 0.94,
        },
        trust_state={
            "final_trust": 0.40,
            "dynamic_trust": 0.40,
        },
    )

    assert state["stage"] == "terminate"
    assert state["termination_allowed"] is True
    assert {"file", "network", "resource"}.issubset(
        set(state["evidence_domains"])
    )


def test_low_slow_file_and_beacon_pattern_reaches_middle_line_termination():
    state = apply_self_healing_policy(
        process_info={
            "pid": 12,
            "name": "python",
            "cmdline": "python edr_12_tests_runner.py",
            "cwd": "/home/kali/self_healing2.o-main",
        },
        classification={
            "label": "worm",
            "worm_score": 0.91,
            "confidence": 91,
            "signals": {
                "replication_detected": True,
                "fanout_detected": True,
                "worm_like_behavior": True,
                "correlated_signals": {
                    "low_slow_file_replication": True,
                    "network_fanout": True,
                    "localhost_beaconing": True,
                    "resource_pressure": True,
                    "trust_anomaly_pattern": True,
                },
            },
        },
        persistence_state={
            "stage": "terminate",
            "termination_ready": True,
            "avg_combined_risk": 0.91,
        },
        trust_state={
            "dynamic_trust": 0.42,
            "final_trust": 0.48,
        },
    )

    assert state["stage"] == "terminate"
    assert state["termination_allowed"] is True


def test_evidence_domains_tracks_recovery_inputs():
    domains = evidence_domains(
        classification={
            "signals": {
                "trust_anomaly_pattern": True,
                "correlated_signals": {
                    "persistence_artifact": True,
                    "localhost_beaconing": True,
                },
            }
        },
        trust_state={
            "dynamic_trust": 0.50,
        },
    )

    assert {"network", "persistence", "trust"}.issubset(domains)
