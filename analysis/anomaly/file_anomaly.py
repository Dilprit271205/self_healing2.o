def file_anomaly(file_events):
    # 🔥 simple and effective thresholds
    if file_events > 20:
        return True

    if file_events > 10:
        return True

    return False