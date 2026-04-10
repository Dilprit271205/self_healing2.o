import os
from analysis.static.static_analyzer import compute_static_trust


def extract_features(process, connection_map, file_map):
    pid = process["pid"]

    # 🔹 Try to get executable path (important for static analysis)
    file_path = process.get("exe", None)

    # Fallback if exe not available
    if not file_path or not os.path.exists(file_path):
        file_path = process.get("name", "")

    # 🔹 STATIC ANALYSIS
    static_data = compute_static_trust(file_path)

    # 🔹 FINAL FEATURE VECTOR
    features = {
        # Basic Info
        "pid": pid,
        "name": process["name"],

        # Dynamic Features
        "cpu": process["cpu"],
        "memory": process["memory"],
        "connections": connection_map.get(pid, 0),
        "file_events": file_map.get(pid, 0),

        # Static Features
        "file_path": file_path,
        "file_size": static_data["features"]["file_size"],
        "is_hidden": static_data["features"]["is_hidden"],
        "extension": static_data["features"]["extension"],
        "location_risk": static_data["features"]["location_risk"],

        # Static Scores
        "static_risk": static_data["static_risk"],
        "static_trust": static_data["static_trust"],
    }

    return features