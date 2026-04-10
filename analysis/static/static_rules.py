def evaluate_static_risk(features):
    risk = 0

    # 🔴 File size risk
    if features["file_size"] == 0:
        risk += 0.3
    elif features["file_size"] > 50_000_000:  # 50MB+
        risk += 0.2

    # 🔴 Hidden file
    if features["is_hidden"]:
        risk += 0.2

    # 🔴 Suspicious location
    if features["location_risk"] == 1:
        risk += 0.4

    # 🔴 Suspicious extensions
    suspicious_ext = [".exe", ".sh", ".bat", ".py"]

    if features["extension"] in suspicious_ext:
        risk += 0.2

    # Normalize (cap at 1)
    return min(risk, 1.0)