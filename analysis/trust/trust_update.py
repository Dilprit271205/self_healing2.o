from analysis.trust.trust_vector import (
    initialize_trust,
    update_dynamic_trust,
    update_static_trust,
    compute_final_trust,
    get_trust
)


def update_trust(pid, current_trust, anomalies, static_score):
    """
    Updates trust values based on anomalies + static score
    """

    decay = 0.05
    penalty = 0.4

    initialize_trust(pid)

    # 🔹 Check if system is clean
    no_anomaly = not any(anomalies.values())

    updated = {}

    # 🔹 Update per-metric trust (cpu, file, net)
    for key in ["cpu", "file", "net"]:
        value = current_trust.get(key, 1.0)

        if anomalies.get(key, False):
            value -= penalty
        else:
            value += decay

        # 🔥 Recovery boost
        if no_anomaly:
            value += 0.1

        # Clamp between 0 and 1
        value = max(0, min(1, value))

        updated[key] = round(value, 3)

    # 🔹 Update dynamic trust vector
    update_dynamic_trust(
        pid,
        cpu=updated["cpu"],
        file=updated["file"],
        net=updated["net"]
    )

    # 🔹 Update static trust
    update_static_trust(pid, static_score)

    # 🔹 Compute final hybrid trust
    final_score = compute_final_trust(pid)

    # 🔹 Return full trust state
    return get_trust(pid)