import os
import math
from analysis.static.static_rules import evaluate_static_risk


def get_file_size(file_path):
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0


def is_hidden(file_path):
    return os.path.basename(file_path).startswith(".")


def get_extension(file_path):
    return os.path.splitext(file_path)[1]


def get_location_risk(file_path):
    suspicious_paths = [
        "/tmp",
        "/var/tmp",
        "/dev",
        "/run",
    ]

    for path in suspicious_paths:
        if file_path.startswith(path):
            return 1  # high risk
    return 0  # safe


def extract_static_features(file_path):
    features = {}

    features["file_path"] = file_path
    features["file_size"] = get_file_size(file_path)
    features["extension"] = get_extension(file_path)
    features["is_hidden"] = is_hidden(file_path)
    features["location_risk"] = get_location_risk(file_path)

    return features


def compute_static_trust(file_path):
    features = extract_static_features(file_path)

    risk_score = evaluate_static_risk(features)

    # Convert risk to trust.
    trust_score = 1 - risk_score

    return {
        "features": features,
        "static_risk": risk_score,
        "static_trust": round(trust_score, 3)
    }
