import multiprocessing
import threading
import time
import socket
import os
import random
import subprocess

RUN = True

BASE_DIR = "stress_dir"


# -----------------------------
# SETUP DIRECTORY
# -----------------------------
def setup():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)


# -----------------------------
# CPU STRESS
# -----------------------------
def cpu_stress():
    while RUN:
        for _ in range(5 * 10**5):
            pass
        time.sleep(0.01)


# -----------------------------
# MEMORY STRESS
# -----------------------------
def memory_stress():
    memory = []
    while RUN:
        memory.append("X" * 2_000_000)  # 2MB chunks
        if len(memory) > 30:
            memory.pop(0)
        time.sleep(0.1)


# -----------------------------
# FILE STRESS (🔥 FIXED)
# -----------------------------
def file_stress():
    while RUN:
        try:
            # 🔥 create new files (important)
            filename = os.path.join(
                BASE_DIR, f"temp_{random.randint(1,10000)}.txt"
            )

            with open(filename, "w") as f:
                f.write("malicious_data\n" * 50)

                # 🔥 force write to disk (VERY IMPORTANT)
                f.flush()
                os.fsync(f.fileno())

            # 🔥 randomly delete files (more events)
            if random.random() < 0.3:
                os.remove(filename)

        except:
            pass

        time.sleep(0.02)


# -----------------------------
# NETWORK STRESS (🔥 STRONGER)
# -----------------------------
def network_stress():
    while RUN:
        try:
            for _ in range(3):  # multiple connections burst
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect(("8.8.8.8", 53))
                s.close()
        except:
            pass

        time.sleep(0.02)


# -----------------------------
# PROCESS SPAWNING (WORM-LIKE)
# -----------------------------
def spawn_process():
    while RUN:
        try:
            subprocess.Popen(["sleep", "0.3"])
        except:
            pass

        time.sleep(0.1)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    setup()

    processes = []

    print("🔥 Starting REALISTIC attack simulation...")

    # CPU (controlled)
    for _ in range(max(1, multiprocessing.cpu_count() // 3)):
        p = multiprocessing.Process(target=cpu_stress)
        p.start()
        processes.append(p)

    # Memory
    mem = multiprocessing.Process(target=memory_stress)
    mem.start()
    processes.append(mem)

    # File (CRITICAL)
    file_p = multiprocessing.Process(target=file_stress)
    file_p.start()
    processes.append(file_p)

    # Network threads
    for _ in range(5):
        t = threading.Thread(target=network_stress, daemon=True)
        t.start()

    # Process spawning
    spawner = multiprocessing.Process(target=spawn_process)
    spawner.start()
    processes.append(spawner)

    print("🚀 Running... Press CTRL + C to stop")

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")

        RUN = False
        time.sleep(1)

        for p in processes:
            p.terminate()