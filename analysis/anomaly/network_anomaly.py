def network_anomaly(connections, mu=2, sigma=2, k=3):
    score = abs(connections - mu) / (k * sigma)
    return score > 0.7