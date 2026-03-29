import psutil
import time

_initialized = False

def init_cpu():
    global _initialized
    if not _initialized:
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except:
                pass
        _initialized = True


def get_process_data():
    init_cpu()
    time.sleep(0.5)

    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent',
                                     'memory_percent']):
        try:
            info = proc.info

            processes.append({
                "pid": info['pid'],
                "name": info['name'],
                "cpu": info['cpu_percent'],
                "memory": info['memory_percent']
            })

        except:
            continue

    return processes