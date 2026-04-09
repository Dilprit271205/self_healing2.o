from collections import deque

CPU_THRESHOLD = 80  # 🔥 increase this
cpu_window = deque(maxlen=5)

def cpu_anomaly(cpu):
    cpu_window.append(cpu)
    avg_cpu = sum(cpu_window) / len(cpu_window)
    return avg_cpu > CPU_THRESHOLD