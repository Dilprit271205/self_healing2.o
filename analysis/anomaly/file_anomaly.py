def file_anomaly(file_events, mu=2, sigma=2, k=3):
    return min(1, abs(file_events - mu) / (k * sigma))