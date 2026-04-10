def network_anomaly(connections):
    if connections > 10:
        return True

    if connections > 5:
        return True

    return False