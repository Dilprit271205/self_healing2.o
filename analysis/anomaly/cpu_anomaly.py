from collections import deque

CPU_THRESHOLD = 50   # 🔥 lower threshold
SPIKE_THRESHOLD = 70

cpu_window = deque(maxlen=5)

def cpu_anomaly(cpu):
    cpu_window.append(cpu)

    avg_cpu = sum(cpu_window) / len(cpu_window)

    # 🔥 detect BOTH sustained + spike
    if cpu > SPIKE_THRESHOLD:
        return True

    if avg_cpu > CPU_THRESHOLD:
        return True

    return False