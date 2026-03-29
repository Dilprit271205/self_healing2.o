def network_anomaly(connections, mu=2, sigma=2, k=3):
    return min(1, abs(connections - mu) / (k * sigma))