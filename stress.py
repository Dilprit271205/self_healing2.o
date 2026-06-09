import multiprocessing
import threading
import time
import socket
import subprocess
import sys

RUN = True

# -----------------------------
# CPU STRESS (CONTROLLED)
# -----------------------------
def cpu_stress():
    while RUN:
        for _ in range(10**6):
            pass
        time.sleep(0.01)  # important


# -----------------------------
# MEMORY STRESS (LIMITED)
# -----------------------------
def memory_stress():
    memory = []
    while RUN:
        memory.append("X" * 5_000_000)  # 5MB
        if len(memory) > 20:  # cap at ~100MB
            memory.pop(0)
        time.sleep(0.1)


# -----------------------------
# FILE STRESS (CONTROLLED)
# -----------------------------
def file_stress():
    while RUN:
        with open("temp_stress.txt", "a", encoding="utf-8") as f:
            for _ in range(20):
                f.write("malicious_data\n")
        time.sleep(0.05)


# -----------------------------
# NETWORK STRESS (CONTROLLED)
# -----------------------------
def network_stress():
    while RUN:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                s.connect(("8.8.8.8", 53))
        except OSError:
            time.sleep(0.05)
        time.sleep(0.05)


# -----------------------------
# PROCESS SPAWNING (LIMITED)
# -----------------------------
def spawn_process():
    while RUN:
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import time; time.sleep(0.5)",
            ]
        )
        time.sleep(0.2)  # limit spawn rate


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    processes = []

    print("[STRESS] Starting controlled attack simulation...")

    # CPU (LIMITED)
    for _ in range(max(1, multiprocessing.cpu_count() // 3)):
        p = multiprocessing.Process(target=cpu_stress)
        p.start()
        processes.append(p)

    # Memory
    mem = multiprocessing.Process(target=memory_stress)
    mem.start()
    processes.append(mem)

    # File
    file_p = multiprocessing.Process(target=file_stress)
    file_p.start()
    processes.append(file_p)

    # Network threads
    for _ in range(3):
        t = threading.Thread(target=network_stress, daemon=True)
        t.start()

    # Process spawn
    spawner = multiprocessing.Process(target=spawn_process)
    spawner.start()
    processes.append(spawner)

    print("[STRESS] Running... Press CTRL+C to stop")

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n[STRESS] Stopping...")

        RUN = False
        time.sleep(1)

        for p in processes:
            p.terminate()
