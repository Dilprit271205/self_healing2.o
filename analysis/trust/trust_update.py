def update_trust(trust, anomalies):
    decay = 0.1
    penalty = 0.2

    no_anomaly = not any(anomalies.values())

    for key in trust:
        if anomalies[key]:
            trust[key] -= penalty
        else:
            trust[key] += decay

        # 🔥 HARD RECOVERY BOOST
        if no_anomaly:
            trust[key] += 0.1

        trust[key] = max(0, min(1, trust[key]))

    return trust