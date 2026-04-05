def update_trust(trust, anomalies, alpha=0.6, recovery_rate=0.15):
    for dim in trust:
        A = anomalies[dim]

        # Normal update
        trust[dim] = alpha * trust[dim] + (1 - alpha) * (1 - A)

        # 🔥 Faster recovery when system is normal
        if A < 0.2:
            trust[dim] += recovery_rate

        # Clamp
        trust[dim] = max(0.0, min(1.0, trust[dim]))

    return trust