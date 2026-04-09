def file_anomaly(file_events, mu=2, sigma=2, k=3):
    score = abs(file_events - mu) / (k * sigma)
    return score > 0.7   # threshold