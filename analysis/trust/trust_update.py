def update_trust(trust, anomalies, alpha=0.6):   # reduced from 0.85
    for dim in trust:
        A = anomalies[dim]
        trust[dim] = alpha * trust[dim] + (1 - alpha) * (1 - A)

    return trust