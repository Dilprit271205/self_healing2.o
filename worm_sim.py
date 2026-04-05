import os
import time
import multiprocessing
import requests

# -----------------------------
# NETWORK SCANNING SIMULATION
# -----------------------------
def network_scan():
    while True:
        try:
            requests.get("http://example.com")
        except:
            pass
        time.sleep(0.1)


# -----------------------------
# FILE REPLICATION SIMULATION
# -----------------------------
def file_spread():
    count = 0
    os.makedirs("worm_files", exist_ok=True)

    while True:
        filename = f"worm_files/worm_copy_{count}.txt"
        with open(filename, "w") as f:
            f.write("worm simulation\n")

        count += 1
        time.sleep(0.05)


# -----------------------------
# PROCESS SPAWNING SIMULATION
# -----------------------------
def spawn_processes():
    while True:
        multiprocessing.Process(target=lambda: time.sleep(5)).start()
        time.sleep(0.2)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    print("🪱 Simulating worm-like behavior...")

    multiprocessing.Process(target=network_scan).start()
    multiprocessing.Process(target=file_spread).start()
    multiprocessing.Process(target=spawn_processes).start()

    while True:
        time.sleep(1)