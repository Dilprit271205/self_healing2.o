def cpu_anomaly(cpu):
    if cpu > 90:
        return 1.0
    elif cpu > 70:
        return 0.7
    elif cpu > 50:
        return 0.4
    else:
        return 0.1