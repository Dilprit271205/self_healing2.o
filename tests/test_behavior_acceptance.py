from analysis.persistence_engine import PersistenceEngine
from analysis.worm_classifier import WormClassifier


def classify(features, aggregate=0.5, trust=None):
    classifier = WormClassifier()
    base = {
        "cmdline": "python behavior simulation",
        "cpu": 1,
        "memory": 1,
        "f_thread": 2,
        "f_thread_velocity": 0,
        "f_proc_spawn": 0,
        "f_proc_tree": 1,
        "f_process_trend": 0,
        "f_young_process": 1,
        "f_connection_velocity": 0,
        "f_remote_ips": 0,
        "f_port_spread": 0,
        "file_events": 0,
        "f_child_similarity": 0,
        "f_repeated_child_count": 0,
        "f_short_lived_child_ratio": 0,
        "worm_score": 0,
        "false_positive_suppression": 0,
    }
    base.update(features)

    return classifier.classify(
        base,
        {"anomalies": {"aggregate": aggregate}, "temporal": {}},
        trust or {"dynamic_trust": 0.82, "final_trust": 0.86},
    )


def persistent_state(classification):
    persistence = PersistenceEngine()
    for _ in range(persistence.delta):
        persistence.update(
            99999,
            classification,
            {"dynamic_trust": 0.72, "final_trust": 0.76},
        )
    return persistence.check_persistence(99999)


def test_1_process_storm_simulation_terminates():
    result = classify(
        {
            "f_proc_tree": 25,
            "f_repeated_child_count": 24,
            "f_child_similarity": 1.0,
            "f_short_lived_child_ratio": 1.0,
            "worm_score": 95,
        }
    )

    assert result["signals"]["forkbomb_detected"] is True
    assert result["signals"]["catastrophic_behavior"] is True
    assert persistent_state(result)["stage"] == "terminate"


def test_2_thread_storm_simulation_detects_without_name_dependency():
    result = classify(
        {
            "f_thread": 140,
            "f_thread_velocity": 90,
            "worm_score": 55,
        }
    )

    assert result["signals"]["thread_storm_detected"] is True
    assert result["label"] in {"suspicious", "worm"}


def test_3_cpu_exhaustion_detects_but_does_not_terminate_alone():
    result = classify(
        {
            "cpu": 96,
            "worm_score": 20,
        },
        aggregate=0.35,
    )
    state = persistent_state(result)

    assert result["signals"]["correlated_signals"]["resource_pressure"] is True
    assert result["label"] in {"suspicious", "normal"}
    assert state["stage"] != "terminate"


def test_4_memory_spike_detects_but_does_not_terminate_alone():
    result = classify(
        {
            "memory": 55,
            "worm_score": 20,
        },
        aggregate=0.35,
    )
    state = persistent_state(result)

    assert result["signals"]["correlated_signals"]["resource_pressure"] is True
    assert result["label"] in {"suspicious", "normal"}
    assert state["stage"] != "terminate"


def test_5_file_replication_simulation_terminates_after_persistence():
    result = classify(
        {
            "file_events": 90,
            "worm_score": 80,
        },
        aggregate=0.35,
    )

    assert result["signals"]["replication_detected"] is True
    assert persistent_state(result)["stage"] == "terminate"


def test_6_mass_file_modification_simulation_detects_replication_pressure():
    result = classify(
        {
            "file_events": 85,
            "f_mass_file_modification": 1,
            "worm_score": 70,
        },
        aggregate=0.35,
    )

    assert result["signals"]["replication_detected"] is True
    assert result["label"] == "worm"


def test_7_suspicious_rename_simulation_detects_ransomware_style_behavior():
    result = classify(
        {
            "file_events": 45,
            "rename_events": 20,
            "f_suspicious_rename": 1,
            "worm_score": 75,
        },
        aggregate=0.35,
    )

    assert result["signals"]["replication_detected"] is True
    assert result["signals"]["correlated_signals"]["suspicious_rename"] is True


def test_8_localhost_beaconing_detects_network_fanout_behavior():
    result = classify(
        {
            "cmdline": "python localhost beacon 127.0.0.1",
            "f_connection_velocity": 12,
            "f_loopback_connections": 12,
            "worm_score": 55,
        },
        aggregate=0.35,
    )

    assert result["signals"]["fanout_detected"] is True
    assert result["signals"]["correlated_signals"]["localhost_beaconing"] is True


def test_9_persistence_artifact_simulation_detects_artifact_abuse():
    result = classify(
        {
            "cmdline": "python writes startup autorun artifact",
            "file_events": 6,
            "f_persistence_artifact": 1,
            "worm_score": 65,
        },
        aggregate=0.35,
    )

    assert result["signals"]["artifact_abuse_detected"] is True
    assert result["label"] == "worm"


def test_10_sensitive_file_access_simulation_detects_credential_access():
    result = classify(
        {
            "cmdline": "python reads .env passwords credentials.txt",
            "file_events": 4,
            "f_sensitive_file_access": 1,
            "worm_score": 60,
        },
        aggregate=0.35,
    )

    assert result["signals"]["artifact_abuse_detected"] is True
    assert result["signals"]["correlated_signals"]["sensitive_file_access"] is True


def test_11_combined_worm_behavior_terminates():
    result = classify(
        {
            "cmdline": "python combined worm localhost startup .env",
            "cpu": 88,
            "memory": 48,
            "f_thread": 90,
            "f_thread_velocity": 50,
            "f_proc_tree": 16,
            "f_repeated_child_count": 10,
            "f_child_similarity": 0.9,
            "f_short_lived_child_ratio": 0.9,
            "file_events": 100,
            "f_connection_velocity": 10,
            "f_loopback_connections": 10,
            "f_persistence_artifact": 1,
            "f_sensitive_file_access": 1,
            "worm_score": 98,
        },
        aggregate=0.6,
        trust={"dynamic_trust": 0.45, "final_trust": 0.50},
    )

    state = persistent_state(result)

    assert result["label"] in {"worm", "forkbomb"}
    assert result["signals"]["correlated_signal_count"] >= 6
    assert state["stage"] == "terminate"
