# analysis/ml_threat_model.py

import json
import math
import os
import threading
import time
import warnings
from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.multioutput import MultiOutputClassifier

warnings.filterwarnings(
    "ignore",
    message=".*delayed.*Parallel.*",
    category=UserWarning,
)

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "threat_model.joblib"
MODEL_META_PATH = MODEL_DIR / "threat_model.metadata.json"
BEHAVIOR_ACTIVATION_PROBABILITY = 0.35
AUTO_RETRAIN_MIN_SECONDS = int(
    os.getenv(
        "SELF_HEALING_ML_RETRAIN_SECONDS",
        "45"
    )
)
DEFAULT_LOG_PATH = "logs/system_log.json"

FEATURE_NAMES = [
    "cpu",
    "memory",
    "threads",
    "connections",
    "file_events",
    "f_proc_spawn",
    "f_proc_tree",
    "f_process_trend",
    "f_young_process",
    "f_repeated_child_count",
    "f_child_similarity",
    "f_short_lived_child_ratio",
    "f_recursive_depth",
    "f_branching_parents",
    "f_repeated_descendant_count",
    "f_thread",
    "f_thread_velocity",
    "f_connection_velocity",
    "f_connection_rate",
    "f_remote_ips",
    "f_port_spread",
    "f_loopback_connections",
    "f_localhost_beaconing",
    "f_persistence_artifact",
    "persistence_events",
    "f_sensitive_file_access",
    "sensitive_file_events",
    "f_mass_file_modification",
    "f_suspicious_rename",
    "rename_events",
    "duplicate_file_hash_count",
    "duplicate_file_hash_memory",
    "low_slow_file_replication",
    "file_memory_events",
    "file_memory_fanout",
    "f_scanning_score",
    "f_scanning_detected",
    "source_worm_score",
    "cpu_anomaly",
    "memory_anomaly",
    "threads_anomaly",
    "connections_anomaly",
    "file_events_anomaly",
    "spawn_anomaly",
    "tree_anomaly",
    "remote_ips_anomaly",
    "child_similarity_anomaly",
    "aggregate_anomaly",
    "process_anomaly",
    "network_anomaly",
    "worm_pattern_anomaly",
    "behavior_correlation_score",
    "trust_anomaly_pressure",
    "trust_drop_risk",
    "dynamic_trust",
    "final_trust",
    "static_trust",
]

THREAT_LABELS = ["normal", "suspicious", "worm", "forkbomb"]
SEVERITY_BY_LABEL = {
    "normal": "low",
    "suspicious": "medium",
    "worm": "critical",
    "forkbomb": "critical",
}

BEHAVIOR_LABELS = [
    "rapid_child_spawning",
    "large_or_growing_tree",
    "repeated_similar_children",
    "short_lived_recursive_children",
    "thread_explosion",
    "cpu_memory_escalation",
    "file_replication",
    "network_fanout",
    "process_storm_burst",
    "resource_pressure",
    "high_file_velocity",
    "extreme_file_velocity",
    "low_slow_file_replication",
    "mass_file_modification",
    "suspicious_rename",
    "persistence_artifact",
    "sensitive_file_access",
    "localhost_beaconing",
    "trust_anomaly_pattern",
    "worm_like_behavior",
    "catastrophic_behavior",
]


def _safe_float(value, default=0.0):
    try:
        if value is None:
            return default
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return default
        return number
    except Exception:
        return default


def _normalize_label(label):
    label = str(label or "normal").lower().strip()
    if label in {"forkbomb", "fork_bomb", "process_bomb"}:
        return "forkbomb"
    if label in {"worm", "malware", "ransomware", "replicator"}:
        return "worm"
    if label in {"suspicious", "anomaly", "anomalous", "high"}:
        return "suspicious"
    return "normal"


def _log_signature(log_path=DEFAULT_LOG_PATH):
    try:
        stat = os.stat(log_path)
        return {
            "path": str(log_path),
            "mtime": stat.st_mtime,
            "size": stat.st_size,
        }
    except Exception:
        return {
            "path": str(log_path),
            "mtime": 0,
            "size": 0,
        }


def _load_metadata(path=None):
    path = path or MODEL_META_PATH
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def _write_metadata(metadata, path=None):
    path = path or MODEL_META_PATH
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)
        os.replace(temp_path, path)
    except Exception:
        pass


def _flatten_runtime_row(row):
    features = row.get("features") or {}
    anomalies = row.get("anomalies") or {}
    trust_state = {
        "dynamic_trust": row.get("dynamic_trust", 1.0),
        "final_trust": row.get("final_trust", 1.0),
        "static_trust": row.get("static_trust", 1.0),
    }

    if not isinstance(features, dict):
        features = {}
    if not isinstance(anomalies, dict):
        anomalies = {}

    merged = {}
    merged.update(row)
    merged.update(features)

    for name in [
        "cpu",
        "memory",
        "threads",
        "connections",
        "file_events",
    ]:
        merged.setdefault(name, row.get(name, 0))

    merged["f_thread"] = merged.get("f_thread", merged.get("threads", 0))
    merged["source_worm_score"] = merged.get("worm_score", row.get("worm_score", 0))
    merged["cpu_anomaly"] = anomalies.get("cpu", 0)
    merged["memory_anomaly"] = anomalies.get("memory", 0)
    merged["threads_anomaly"] = anomalies.get("threads", 0)
    merged["connections_anomaly"] = anomalies.get("connections", 0)
    merged["file_events_anomaly"] = anomalies.get("file_events", 0)
    merged["spawn_anomaly"] = anomalies.get("spawn", 0)
    merged["tree_anomaly"] = anomalies.get("tree", 0)
    merged["remote_ips_anomaly"] = anomalies.get("remote_ips", 0)
    merged["child_similarity_anomaly"] = anomalies.get("child_similarity", 0)
    merged["aggregate_anomaly"] = anomalies.get("aggregate", 0)
    merged["process_anomaly"] = anomalies.get("process", 0)
    merged["network_anomaly"] = anomalies.get("network", 0)
    merged["worm_pattern_anomaly"] = anomalies.get("worm_pattern", 0)
    merged.update(trust_state)
    merged["behavior_correlation_score"] = max(
        _safe_float(merged.get("worm_pattern_anomaly", 0)),
        _safe_float(merged.get("aggregate_anomaly", 0)),
    )
    merged["trust_anomaly_pressure"] = max(
        _safe_float(merged.get("trust_anomaly_pressure", 0)),
        1.0 - _safe_float(merged.get("dynamic_trust", 1.0)),
        _safe_float(merged.get("worm_pattern_anomaly", 0)),
    )
    merged["trust_drop_risk"] = max(
        0.0,
        _safe_float(merged.get("static_trust", 1.0))
        - _safe_float(merged.get("dynamic_trust", 1.0))
    )
    return merged


def vectorize(features, anomaly_data=None, trust_state=None):
    anomaly_data = anomaly_data or {}
    anomalies = anomaly_data.get("anomalies", {}) or {}
    features = features or {}
    trust_state = trust_state or {}

    merged = {}
    merged.update(features)
    merged["threads"] = features.get("threads", features.get("f_thread", 0))
    merged["source_worm_score"] = features.get("worm_score", 0)
    merged["cpu_anomaly"] = anomalies.get("cpu", 0)
    merged["memory_anomaly"] = anomalies.get("memory", 0)
    merged["threads_anomaly"] = anomalies.get("threads", 0)
    merged["connections_anomaly"] = anomalies.get("connections", 0)
    merged["file_events_anomaly"] = anomalies.get("file_events", 0)
    merged["spawn_anomaly"] = anomalies.get("spawn", 0)
    merged["tree_anomaly"] = anomalies.get("tree", 0)
    merged["remote_ips_anomaly"] = anomalies.get("remote_ips", 0)
    merged["child_similarity_anomaly"] = anomalies.get("child_similarity", 0)
    merged["aggregate_anomaly"] = anomalies.get("aggregate", 0)
    merged["process_anomaly"] = anomalies.get("process", 0)
    merged["network_anomaly"] = anomalies.get("network", 0)
    merged["worm_pattern_anomaly"] = anomalies.get("worm_pattern", 0)
    merged["dynamic_trust"] = trust_state.get("dynamic_trust", 1.0)
    merged["final_trust"] = trust_state.get("final_trust", 1.0)
    merged["static_trust"] = trust_state.get("static_trust", 1.0)
    merged["behavior_correlation_score"] = max(
        _safe_float(merged.get("worm_pattern_anomaly", 0)),
        _safe_float(merged.get("aggregate_anomaly", 0)),
    )
    merged["trust_anomaly_pressure"] = max(
        _safe_float(trust_state.get("trust_anomaly_pressure", 0)),
        1.0 - _safe_float(merged.get("dynamic_trust", 1.0)),
        _safe_float(merged.get("worm_pattern_anomaly", 0)),
    )
    merged["trust_drop_risk"] = max(
        0.0,
        _safe_float(merged.get("static_trust", 1.0))
        - _safe_float(merged.get("dynamic_trust", 1.0))
    )

    return [_safe_float(merged.get(name, 0)) for name in FEATURE_NAMES]


def _synthetic_profiles():
    rows = []

    def base_row(label, tags=None):
        row = {name: 0 for name in FEATURE_NAMES}
        row.update({tag: 0 for tag in BEHAVIOR_LABELS})
        row["label"] = label
        for tag in tags or []:
            row[tag] = 1
        return row

    benign_templates = [
        {"cpu": 2, "memory": 4, "threads": 4, "connections": 1},
        {"cpu": 8, "memory": 12, "threads": 12, "connections": 2},
        {"cpu": 18, "memory": 20, "threads": 20, "connections": 4},
        {"cpu": 0, "memory": 2, "threads": 1, "connections": 0},
    ]
    for template in benign_templates:
        for scale in range(1, 8):
            row = base_row("normal")
            row.update(template)
            row["cpu"] *= scale / 4
            row["memory"] *= scale / 4
            row["threads"] *= scale / 3
            row["connections"] *= scale / 3
            row["dynamic_trust"] = 0.95
            row["final_trust"] = 0.94
            row["static_trust"] = 0.9
            row["trust_anomaly_pressure"] = 0.05
            row["trust_drop_risk"] = 0.0
            row["behavior_correlation_score"] = 0.0
            row["source_worm_score"] = 0
            rows.append(row)

    suspicious_templates = [
        {"cpu": 35, "memory": 28, "threads": 35, "file_events": 20},
        {"connections": 10, "f_connection_velocity": 6, "f_remote_ips": 4},
        {"f_proc_spawn": 2, "f_proc_tree": 8, "f_process_trend": 3},
    ]
    for template in suspicious_templates:
        for scale in range(1, 6):
            tags = ["resource_pressure"] if "cpu" in template else []
            if "connections" in template:
                tags = ["network_fanout"]
            if "f_proc_spawn" in template:
                tags = ["rapid_child_spawning", "large_or_growing_tree"]
            row = base_row("suspicious", tags)
            row.update(template)
            row["aggregate_anomaly"] = min(0.2 + scale * 0.08, 0.65)
            row["dynamic_trust"] = 0.75 - scale * 0.03
            row["final_trust"] = 0.78 - scale * 0.03
            row["static_trust"] = 0.82
            row["trust_anomaly_pressure"] = min(0.30 + scale * 0.06, 0.75)
            row["trust_drop_risk"] = max(0.0, row["static_trust"] - row["dynamic_trust"])
            row["behavior_correlation_score"] = row["aggregate_anomaly"]
            row["source_worm_score"] = 35 + scale * 5
            rows.append(row)

    for value in [90, 96, 120]:
        row = base_row(
            "suspicious",
            ["resource_pressure", "cpu_memory_escalation"]
        )
        row.update(
            {
                "cpu": value,
                "aggregate_anomaly": 0.35,
                "dynamic_trust": 0.72,
                "final_trust": 0.76,
                "static_trust": 0.82,
                "trust_anomaly_pressure": 0.35,
                "trust_drop_risk": 0.10,
                "behavior_correlation_score": 0.35,
                "source_worm_score": 20,
            }
        )
        rows.append(row)

    for value in [48, 55, 70]:
        row = base_row(
            "suspicious",
            ["resource_pressure", "cpu_memory_escalation"]
        )
        row.update(
            {
                "memory": value,
                "aggregate_anomaly": 0.35,
                "dynamic_trust": 0.72,
                "final_trust": 0.76,
                "static_trust": 0.82,
                "trust_anomaly_pressure": 0.35,
                "trust_drop_risk": 0.10,
                "behavior_correlation_score": 0.35,
                "source_worm_score": 20,
            }
        )
        rows.append(row)

    for value in [85, 140, 220]:
        row = base_row(
            "suspicious",
            ["thread_explosion", "resource_pressure"]
        )
        row.update(
            {
                "f_thread": value,
                "threads": value,
                "f_thread_velocity": value / 2,
                "aggregate_anomaly": 0.45,
                "dynamic_trust": 0.70,
                "final_trust": 0.72,
                "static_trust": 0.82,
                "trust_anomaly_pressure": 0.45,
                "trust_drop_risk": 0.12,
                "behavior_correlation_score": 0.45,
                "source_worm_score": 55,
            }
        )
        rows.append(row)

    worm_templates = [
        {
            "file_events": 260,
            "f_proc_tree": 2,
            "f_persistence_artifact": 1,
            "f_mass_file_modification": 1,
        },
        {
            "f_connection_velocity": 12,
            "f_loopback_connections": 8,
            "f_localhost_beaconing": 1,
        },
        {
            "f_remote_ips": 20,
            "f_port_spread": 30,
            "f_scanning_score": 1,
            "f_scanning_detected": 1,
        },
    ]
    for template in worm_templates:
        for scale in range(1, 7):
            tags = ["file_replication", "high_file_velocity"]
            if template.get("f_mass_file_modification"):
                tags.extend(["mass_file_modification", "extreme_file_velocity"])
            if template.get("f_persistence_artifact"):
                tags.append("persistence_artifact")
            if template.get("f_localhost_beaconing"):
                tags = ["network_fanout", "localhost_beaconing"]
            if template.get("f_scanning_detected"):
                tags = ["network_fanout"]
            row = base_row("worm", tags)
            row.update(template)
            row["aggregate_anomaly"] = min(0.45 + scale * 0.06, 1.0)
            row["dynamic_trust"] = max(0.25, 0.62 - scale * 0.06)
            row["final_trust"] = max(0.25, 0.64 - scale * 0.06)
            row["static_trust"] = 0.78
            row["trust_anomaly_pressure"] = min(0.55 + scale * 0.06, 1.0)
            row["trust_drop_risk"] = max(0.0, row["static_trust"] - row["dynamic_trust"])
            row["behavior_correlation_score"] = row["trust_anomaly_pressure"]
            row["worm_pattern_anomaly"] = row["behavior_correlation_score"]
            row["source_worm_score"] = 80 + scale * 3
            rows.append(row)

    file_templates = [
        (
            {"file_events": 80},
            ["file_replication", "high_file_velocity", "extreme_file_velocity"],
        ),
        (
            {"file_events": 90, "f_mass_file_modification": 1},
            [
                "file_replication",
                "high_file_velocity",
                "extreme_file_velocity",
                "mass_file_modification",
            ],
        ),
        (
            {"file_events": 45, "rename_events": 20, "f_suspicious_rename": 1},
            ["file_replication", "suspicious_rename", "high_file_velocity"],
        ),
        (
            {"file_events": 6, "f_persistence_artifact": 1, "persistence_events": 1},
            ["persistence_artifact"],
        ),
        (
            {
                "file_events": 4,
                "f_sensitive_file_access": 1,
                "sensitive_file_events": 1,
            },
            ["sensitive_file_access"],
        ),
    ]
    for template, tags in file_templates:
        for scale in range(1, 18):
            row = base_row("worm", tags)
            row.update(template)
            row["aggregate_anomaly"] = min(0.30 + scale * 0.08, 0.85)
            row["dynamic_trust"] = max(0.30, 0.72 - scale * 0.05)
            row["final_trust"] = max(0.30, 0.76 - scale * 0.05)
            row["static_trust"] = 0.78
            row["trust_anomaly_pressure"] = min(0.45 + scale * 0.05, 0.95)
            row["trust_drop_risk"] = max(0.0, row["static_trust"] - row["dynamic_trust"])
            row["behavior_correlation_score"] = row["trust_anomaly_pressure"]
            row["worm_pattern_anomaly"] = row["behavior_correlation_score"]
            row["source_worm_score"] = 70 + scale * 5
            rows.append(row)

    network_templates = [
        (
            {"f_connection_velocity": 12, "f_loopback_connections": 12, "f_localhost_beaconing": 1},
            ["network_fanout", "localhost_beaconing"],
        ),
        (
            {"f_connection_velocity": 14, "f_remote_ips": 12, "f_port_spread": 20},
            ["network_fanout"],
        ),
    ]
    for template, tags in network_templates:
        for scale in range(1, 12):
            row = base_row("worm", tags)
            row.update(template)
            row["aggregate_anomaly"] = min(0.35 + scale * 0.08, 0.9)
            row["dynamic_trust"] = max(0.30, 0.70 - scale * 0.05)
            row["final_trust"] = max(0.30, 0.74 - scale * 0.05)
            row["static_trust"] = 0.78
            row["trust_anomaly_pressure"] = min(0.45 + scale * 0.05, 0.95)
            row["trust_drop_risk"] = max(0.0, row["static_trust"] - row["dynamic_trust"])
            row["behavior_correlation_score"] = row["trust_anomaly_pressure"]
            row["worm_pattern_anomaly"] = row["behavior_correlation_score"]
            row["source_worm_score"] = 55 + scale * 5
            rows.append(row)

    for scale in range(1, 14):
        row = base_row(
            "forkbomb",
            [
                "rapid_child_spawning",
                "large_or_growing_tree",
                "repeated_similar_children",
                "short_lived_recursive_children",
                "process_storm_burst",
                "catastrophic_behavior",
            ]
        )
        row.update(
            {
                "f_proc_spawn": scale * 2,
                "f_proc_tree": scale * 5,
                "f_process_trend": scale * 2,
                "f_young_process": 1,
                "f_repeated_child_count": scale * 2,
                "f_child_similarity": 1.0,
                "f_short_lived_child_ratio": 1.0,
                "f_recursive_depth": min(scale, 7),
                "f_branching_parents": scale,
                "f_repeated_descendant_count": scale * 4,
                "aggregate_anomaly": min(0.5 + scale * 0.04, 1.0),
                "dynamic_trust": max(0.2, 0.58 - scale * 0.035),
                "final_trust": max(0.2, 0.60 - scale * 0.035),
                "static_trust": 0.78,
                "trust_anomaly_pressure": min(0.55 + scale * 0.04, 1.0),
                "trust_drop_risk": 0.25,
                "behavior_correlation_score": min(0.55 + scale * 0.04, 1.0),
                "worm_pattern_anomaly": min(0.55 + scale * 0.04, 1.0),
                "source_worm_score": 90 + scale,
                "label": "forkbomb",
            }
        )
        rows.append(row)

    for tree_size in [12, 16, 25, 40]:
        repeat_count = 8 if tree_size >= 25 else 4
        for _ in range(repeat_count):
            row = base_row(
                "forkbomb",
                [
                    "large_or_growing_tree",
                    "repeated_similar_children",
                    "short_lived_recursive_children",
                    "process_storm_burst",
                    "catastrophic_behavior",
                ]
            )
            row.update(
                {
                    "f_proc_tree": tree_size,
                    "f_repeated_child_count": max(10, tree_size - 1),
                    "f_child_similarity": 1.0,
                    "f_short_lived_child_ratio": 1.0,
                    "aggregate_anomaly": 0.55,
                    "dynamic_trust": 0.76,
                    "final_trust": 0.80,
                    "static_trust": 0.78,
                    "trust_anomaly_pressure": 0.82,
                    "trust_drop_risk": 0.02,
                    "behavior_correlation_score": 0.82,
                    "worm_pattern_anomaly": 0.82,
                    "source_worm_score": 95,
                }
            )
            rows.append(row)

        row = base_row(
            "forkbomb",
            [
                "large_or_growing_tree",
                "repeated_similar_children",
                "short_lived_recursive_children",
                "process_storm_burst",
                "catastrophic_behavior",
            ]
        )
        row.update(
            {
                "f_proc_tree": tree_size,
                "f_young_process": 1,
                "f_repeated_child_count": max(10, tree_size - 1),
                "f_child_similarity": 1.0,
                "f_short_lived_child_ratio": 1.0,
                "aggregate_anomaly": 0.55,
                "dynamic_trust": 0.76,
                "final_trust": 0.80,
                "static_trust": 0.78,
                "trust_anomaly_pressure": 0.82,
                "trust_drop_risk": 0.02,
                "behavior_correlation_score": 0.82,
                "worm_pattern_anomaly": 0.82,
                "source_worm_score": 95,
            }
        )
        rows.append(row)

    return rows


def load_training_rows(log_path="logs/system_log.json"):
    rows = []
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    raw = json.loads(line)
                except Exception:
                    continue
                raw["label"] = _normalize_label(raw.get("label"))
                rows.append(_flatten_runtime_row(raw))

    rows.extend(_synthetic_profiles())
    return rows


@dataclass
class Prediction:
    label: str
    severity: str
    worm_score: float
    confidence: float
    probabilities: dict
    anomaly_probability: float
    behavior_signals: dict
    behavior_probabilities: dict
    top_drivers: list


class MLThreatModel:
    def __init__(
        self,
        classifier=None,
        isolation_model=None,
        behavior_model=None,
        report=None
    ):
        self.classifier = classifier
        self.isolation_model = isolation_model
        self.behavior_model = behavior_model
        self.report = report or {}

    @classmethod
    def train(cls, rows):
        frame = pd.DataFrame(rows)
        if frame.empty:
            frame = pd.DataFrame(_synthetic_profiles())

        for name in FEATURE_NAMES:
            if name not in frame.columns:
                frame[name] = 0.0
            frame[name] = pd.to_numeric(
                frame[name],
                errors="coerce"
            ).fillna(0.0)

        frame["label"] = frame.get("label", "normal").apply(_normalize_label)
        behavior_known = pd.Series(False, index=frame.index)
        for tag in BEHAVIOR_LABELS:
            if tag not in frame.columns:
                frame[tag] = 0
            behavior_known = behavior_known | frame[tag].notna()
            frame[tag] = pd.to_numeric(
                frame[tag],
                errors="coerce"
            ).fillna(0).clip(lower=0, upper=1).astype(int)

        x = frame[FEATURE_NAMES]
        y = frame["label"]

        classifier = RandomForestClassifier(
            n_estimators=240,
            max_depth=14,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        classifier.fit(x, y)

        behavior_model = MultiOutputClassifier(
            RandomForestClassifier(
                n_estimators=180,
                max_depth=12,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=11,
                n_jobs=-1,
            )
        )
        behavior_x = x[behavior_known]
        behavior_y = frame.loc[behavior_known, BEHAVIOR_LABELS]
        if behavior_x.empty:
            behavior_x = x
            behavior_y = frame[BEHAVIOR_LABELS]

        behavior_model.fit(
            behavior_x,
            behavior_y
        )

        normal_x = x[y == "normal"]
        if len(normal_x) < 8:
            normal_x = x

        isolation_model = IsolationForest(
            n_estimators=160,
            contamination="auto",
            random_state=42,
        )
        isolation_model.fit(normal_x)

        report = {
            "rows": int(len(frame)),
            "labels": frame["label"].value_counts().to_dict(),
            "behavior_labels": {
                tag: int(frame[tag].sum())
                for tag in BEHAVIOR_LABELS
            },
            "feature_names": FEATURE_NAMES,
            "sklearn_version": sklearn.__version__,
        }

        if hasattr(classifier, "feature_importances_"):
            importances = sorted(
                zip(
                    FEATURE_NAMES,
                    classifier.feature_importances_
                ),
                key=lambda item: item[1],
                reverse=True
            )
            report["top_features"] = [
                {
                    "feature": name,
                    "importance": round(float(value), 5)
                }
                for name, value in importances[:12]
            ]

        if len(frame) >= 12 and y.nunique() > 1:
            try:
                x_train, x_test, y_train, y_test = train_test_split(
                    x,
                    y,
                    test_size=0.25,
                    random_state=42,
                    stratify=y,
                )
                eval_model = RandomForestClassifier(
                    n_estimators=180,
                    max_depth=14,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    random_state=7,
                    n_jobs=-1,
                )
                eval_model.fit(x_train, y_train)
                predicted = eval_model.predict(x_test)
                report["classification_report"] = classification_report(
                    y_test,
                    predicted,
                    zero_division=0,
                    output_dict=True,
                )
            except Exception as exc:
                report["classification_report_error"] = str(exc)

        return cls(
            classifier=classifier,
            isolation_model=isolation_model,
            behavior_model=behavior_model,
            report=report,
        )._normalize_parallelism()

    def save(self, path=MODEL_PATH):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path=MODEL_PATH):
        model = joblib.load(path)
        model._normalize_parallelism()
        return model

    def _normalize_parallelism(self):
        for estimator in (
            self.classifier,
            self.isolation_model,
        ):
            if hasattr(
                estimator,
                "n_jobs"
            ):
                estimator.n_jobs = 1

        if self.behavior_model is not None:
            base_estimator = getattr(
                self.behavior_model,
                "estimator",
                None
            )
            if hasattr(
                base_estimator,
                "n_jobs"
            ):
                base_estimator.n_jobs = 1

            for estimator in getattr(
                self.behavior_model,
                "estimators_",
                []
            ):
                if hasattr(
                    estimator,
                    "n_jobs"
                ):
                    estimator.n_jobs = 1

        return self

    def predict(self, features, anomaly_data=None, trust_state=None):
        x = pd.DataFrame(
            [vectorize(features, anomaly_data, trust_state)],
            columns=FEATURE_NAMES,
        )

        probabilities = {
            label: 0.0
            for label in THREAT_LABELS
        }

        if self.classifier is not None:
            raw_probabilities = self.classifier.predict_proba(x)[0]
            for label, probability in zip(
                self.classifier.classes_,
                raw_probabilities
            ):
                probabilities[_normalize_label(label)] = float(probability)

        anomaly_probability = 0.0
        if self.isolation_model is not None:
            score = float(self.isolation_model.decision_function(x)[0])
            anomaly_probability = 1.0 / (1.0 + math.exp(5.0 * score))

        if not any(probabilities.values()):
            probabilities["suspicious"] = anomaly_probability
            probabilities["normal"] = 1.0 - anomaly_probability

        behavior_signals = {
            tag: False
            for tag in BEHAVIOR_LABELS
        }
        behavior_probabilities = {
            tag: 0.0
            for tag in BEHAVIOR_LABELS
        }
        if self.behavior_model is not None:
            for tag, estimator in zip(
                BEHAVIOR_LABELS,
                self.behavior_model.estimators_
            ):
                classes = list(estimator.classes_)
                if 1 in classes:
                    positive_probability = float(
                        estimator.predict_proba(x)[0][classes.index(1)]
                    )
                else:
                    positive_probability = 0.0

                behavior_probabilities[tag] = round(
                    positive_probability,
                    4
                )
                behavior_signals[tag] = (
                    positive_probability
                    >=
                    BEHAVIOR_ACTIVATION_PROBABILITY
                )

        row = x.iloc[0]

        direct_rules = {
            "file_replication": (
                _safe_float(row.get("file_events", 0)) >= 60
                or _safe_float(row.get("low_slow_file_replication", 0)) > 0
                or _safe_float(row.get("duplicate_file_hash_memory", 0)) >= 8
            ),
            "high_file_velocity": _safe_float(row.get("file_events", 0)) >= 45,
            "extreme_file_velocity": _safe_float(row.get("file_events", 0)) >= 75,
            "low_slow_file_replication": (
                _safe_float(row.get("low_slow_file_replication", 0)) > 0
                or (
                    _safe_float(row.get("file_memory_events", 0)) >= 30
                    and _safe_float(row.get("file_memory_fanout", 0)) >= 8
                )
            ),
            "network_fanout": (
                _safe_float(row.get("f_connection_velocity", 0)) >= 10
                or _safe_float(row.get("f_remote_ips", 0)) >= 10
                or _safe_float(row.get("f_loopback_connections", 0)) >= 8
            ),
            "localhost_beaconing": (
                _safe_float(row.get("f_localhost_beaconing", 0)) > 0
                or (
                    _safe_float(row.get("f_loopback_connections", 0)) >= 8
                    and _safe_float(row.get("f_connection_velocity", 0)) >= 8
                )
            ),
            "persistence_artifact": (
                _safe_float(row.get("f_persistence_artifact", 0)) > 0
                or _safe_float(row.get("persistence_events", 0)) > 0
            ),
            "sensitive_file_access": (
                _safe_float(row.get("f_sensitive_file_access", 0)) > 0
                or _safe_float(row.get("sensitive_file_events", 0)) > 0
            ),
            "thread_explosion": (
                _safe_float(row.get("f_thread", 0)) >= 80
                or _safe_float(row.get("f_thread_velocity", 0)) >= 50
            ),
            "cpu_memory_escalation": (
                _safe_float(row.get("cpu", 0)) >= 85
                or _safe_float(row.get("memory", 0)) >= 35
            ),
            "resource_pressure": (
                _safe_float(row.get("cpu", 0)) >= 85
                or _safe_float(row.get("memory", 0)) >= 35
                or _safe_float(row.get("f_thread", 0)) >= 80
            ),
            "rapid_child_spawning": _safe_float(row.get("f_proc_spawn", 0)) >= 4,
            "large_or_growing_tree": _safe_float(row.get("f_proc_tree", 0)) >= 12,
            "repeated_similar_children": (
                _safe_float(row.get("f_repeated_child_count", 0)) >= 8
                and _safe_float(row.get("f_child_similarity", 0)) >= 0.65
            ),
            "short_lived_recursive_children": (
                _safe_float(row.get("f_short_lived_child_ratio", 0)) >= 0.65
            ),
            "process_storm_burst": (
                _safe_float(row.get("f_proc_tree", 0)) >= 12
                and _safe_float(row.get("f_repeated_child_count", 0)) >= 8
            ),
            "trust_anomaly_pattern": (
                _safe_float(row.get("trust_anomaly_pressure", 0)) >= 0.45
                or _safe_float(row.get("trust_drop_risk", 0)) >= 0.18
                or (
                    _safe_float(row.get("worm_pattern_anomaly", 0)) >= 0.45
                    and _safe_float(row.get("dynamic_trust", 1.0)) <= 0.78
                )
            ),
        }
        direct_rules["catastrophic_behavior"] = (
            direct_rules["process_storm_burst"]
            and direct_rules["repeated_similar_children"]
            and direct_rules["short_lived_recursive_children"]
        )
        correlated_worm_domains = sum(
            1
            for tag in (
                "rapid_child_spawning",
                "large_or_growing_tree",
                "repeated_similar_children",
                "file_replication",
                "low_slow_file_replication",
                "network_fanout",
                "persistence_artifact",
                "sensitive_file_access",
                "thread_explosion",
                "resource_pressure",
                "trust_anomaly_pattern",
            )
            if direct_rules.get(tag)
        )
        direct_rules["worm_like_behavior"] = (
            correlated_worm_domains >= 3
            or (
                _safe_float(row.get("behavior_correlation_score", 0)) >= 0.62
                and direct_rules["trust_anomaly_pattern"]
            )
        )

        for tag, active in direct_rules.items():
            if not active:
                continue

            behavior_signals[tag] = True
            behavior_probabilities[tag] = max(
                behavior_probabilities.get(tag, 0.0),
                0.99
            )

        if direct_rules["catastrophic_behavior"]:
            probabilities["forkbomb"] = max(
                probabilities.get("forkbomb", 0.0),
                0.96
            )
            probabilities["normal"] = min(
                probabilities.get("normal", 0.0),
                0.04
            )
        elif any(
            direct_rules[tag]
            for tag in (
                "file_replication",
                "low_slow_file_replication",
                "network_fanout",
                "persistence_artifact",
                "sensitive_file_access",
                "thread_explosion",
                "worm_like_behavior"
            )
        ):
            probabilities["worm"] = max(
                probabilities.get("worm", 0.0),
                0.92
            )
            probabilities["normal"] = min(
                probabilities.get("normal", 0.0),
                0.08
            )

        if direct_rules["trust_anomaly_pattern"]:
            probabilities["suspicious"] = max(
                probabilities.get("suspicious", 0.0),
                0.55
            )
            probabilities["normal"] = min(
                probabilities.get("normal", 0.0),
                0.30
            )

        worm_score = min(
            1.0,
            probabilities.get("worm", 0.0)
            + probabilities.get("forkbomb", 0.0)
            + probabilities.get("suspicious", 0.0) * 0.35
            + anomaly_probability * 0.15,
        )

        label = max(
            probabilities,
            key=probabilities.get
        )

        confidence = max(probabilities.values())
        top_drivers = self._top_prediction_drivers(x)
        return Prediction(
            label=label,
            severity=SEVERITY_BY_LABEL.get(label, "medium"),
            worm_score=round(float(worm_score), 3),
            confidence=round(float(confidence * 100), 2),
            probabilities={
                key: round(value, 4)
                for key, value in probabilities.items()
            },
            anomaly_probability=round(float(anomaly_probability), 4),
            behavior_signals=behavior_signals,
            behavior_probabilities=behavior_probabilities,
            top_drivers=top_drivers,
        )

    def _top_prediction_drivers(self, frame):
        if not hasattr(self.classifier, "feature_importances_"):
            return []

        row = frame.iloc[0]
        drivers = []

        for name, importance in zip(
            FEATURE_NAMES,
            self.classifier.feature_importances_
        ):
            value = _safe_float(row.get(name, 0))
            contribution = abs(value) * float(importance)
            if contribution <= 0:
                continue
            drivers.append(
                {
                    "feature": name,
                    "value": round(value, 4),
                    "impact": round(contribution, 5)
                }
            )

        return sorted(
            drivers,
            key=lambda item: item["impact"],
            reverse=True
        )[:8]


def train_and_save(log_path="logs/system_log.json", model_path=MODEL_PATH):
    rows = load_training_rows(log_path)
    model = MLThreatModel.train(rows)
    model.report["trained_at"] = time.time()
    model.report["log_signature"] = _log_signature(log_path)
    model.report["model_path"] = str(model_path)
    model.save(model_path)
    _write_metadata(model.report)
    return model


def load_or_train(model_path=MODEL_PATH, log_path="logs/system_log.json"):
    try:
        if Path(model_path).exists():
            metadata = _load_metadata()

            if metadata.get("sklearn_version") != sklearn.__version__:
                return train_and_save(
                    log_path=log_path,
                    model_path=model_path
                )

            if metadata.get("feature_names") != FEATURE_NAMES:
                return train_and_save(
                    log_path=log_path,
                    model_path=model_path
                )

            model = MLThreatModel.load(model_path)
            model.report.setdefault(
                "sklearn_version",
                sklearn.__version__
            )
            return model
    except Exception:
        pass

    return train_and_save(
        log_path=log_path,
        model_path=model_path
    )


class AutonomousThreatModel:
    """
    Runtime model manager.

    It bootstraps the model, serves predictions, and refreshes the artifact
    from telemetry when the process log changes. Retraining happens in the
    background so the monitoring loop can continue using the current model.
    """

    def __init__(
        self,
        model_path=MODEL_PATH,
        log_path=DEFAULT_LOG_PATH,
        retrain_interval=AUTO_RETRAIN_MIN_SECONDS
    ):
        self.model_path = Path(model_path)
        self.log_path = log_path
        self.retrain_interval = retrain_interval
        self.metadata = _load_metadata()
        self.model = load_or_train(
            model_path=self.model_path,
            log_path=self.log_path
        )
        if not self.metadata:
            self.metadata = _load_metadata()
        self._lock = threading.Lock()
        self._retrain_thread = None
        self._last_check = 0

    def _autotrain_enabled(self):
        return os.getenv(
            "SELF_HEALING_ML_AUTOTRAIN",
            "1"
        ).strip().lower() not in {
            "0",
            "false",
            "no",
            "off"
        }

    def _training_needed(self):
        current = _log_signature(self.log_path)
        previous = self.metadata.get(
            "log_signature",
            {}
        )
        return (
            current.get("size", 0) != previous.get("size", 0)
            or
            current.get("mtime", 0) != previous.get("mtime", 0)
        )

    def _reload_model(self):
        self.model = load_or_train(
            model_path=self.model_path,
            log_path=self.log_path
        )
        self.metadata = _load_metadata()

    def _train_background(self):
        try:
            model = train_and_save(
                log_path=self.log_path,
                model_path=self.model_path
            )
            with self._lock:
                self.model = model
                self.metadata = _load_metadata()
        finally:
            with self._lock:
                self._retrain_thread = None

    def maybe_retrain(self):
        if not self._autotrain_enabled():
            return

        now = time.time()
        if now - self._last_check < self.retrain_interval:
            return
        self._last_check = now

        if not self._training_needed():
            return

        with self._lock:
            if (
                self._retrain_thread
                and
                self._retrain_thread.is_alive()
            ):
                return

            self._retrain_thread = threading.Thread(
                target=self._train_background,
                name="self-healing-ml-retrain",
                daemon=True
            )
            self._retrain_thread.start()

    def predict(self, features, anomaly_data=None, trust_state=None):
        self.maybe_retrain()
        with self._lock:
            model = self.model
        return model.predict(
            features=features,
            anomaly_data=anomaly_data,
            trust_state=trust_state
        )

    def status(self):
        return {
            "model_path": str(self.model_path),
            "log_path": str(self.log_path),
            "autotrain": self._autotrain_enabled(),
            "retraining": bool(
                self._retrain_thread
                and
                self._retrain_thread.is_alive()
            ),
            "metadata": self.metadata,
        }


def load_autonomous_model(
    model_path=MODEL_PATH,
    log_path=DEFAULT_LOG_PATH
):
    return AutonomousThreatModel(
        model_path=model_path,
        log_path=log_path
    )
