from analysis.baseline_engine import BaselineEngine


def test_dev_like_activity_has_low_baseline_anomaly():
    baseline = BaselineEngine()

    sample = {
        "pid": 70001,
        "cpu": 3,
        "memory": 2,
        "f_thread": 6,
        "connections": 1,
        "file_events": 8,
        "f_proc_spawn": 0,
        "f_proc_tree": 1,
        "f_process_trend": 0,
        "f_young_process": 1,
        "f_syscall_freq": 12,
        "f_remote_ips": 0,
        "f_child_similarity": 0,
    }

    for _ in range(35):
        baseline.update_history(70001, sample)

    for feature, value in {
        "cpu": 3,
        "memory": 2,
        "threads": 6,
        "file_events": 8,
        "tree": 1,
    }.items():
        base = baseline.get_baseline(feature)
        assert baseline.anomaly_score(feature, value, base["mu"], base["sigma"]) <= 0.1


def test_process_tree_storm_stays_anomalous():
    baseline = BaselineEngine()
    base = baseline.get_baseline("tree")

    assert baseline.anomaly_score("tree", 45, base["mu"], base["sigma"]) >= 0.9
