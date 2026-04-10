import threading
import time
import socket
import random
import os

RUN = True

# -----------------------------
# BURST CPU (SPIKY)
# -----------------------------
def cpu_spike():
    while RUN:
        for _ in range(5 * 10**6):
            pass
        time.sleep(random.uniform(0.1, 0.5))  # spike pattern


# -----------------------------
# MEMORY BURST
# -----------------------------
def memory_spike():
    data = []
    while RUN:
        for _ in range(20):
            data.append("X" * 10**6)  # ~1MB each
        time.sleep(0.2)
        data.clear()  # sudden drop (important for anomaly)


# -----------------------------
# NETWORK BURST (VERY IMPORTANT)
# -----------------------------
def network_spike():
    while RUN:
        for _ in range(50):  # burst connections
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect(("8.8.8.8", 53))
                s.close()
            except:
                pass
        time.sleep(0.2)


# -----------------------------
# FILE STORM (KEY TRIGGER)
# -----------------------------
def file_storm():
    while RUN:
        for i in range(50):
            try:
                filename = f"temp_attack_{random.randint(1,100000)}.txt"
                with open(filename, "w") as f:
                    f.write("ATTACK\n" * 100)
                os.remove(filename)
            except:
                pass
        time.sleep(0.2)


# -----------------------------
# RANDOM BEHAVIOR (IMPORTANT)
# -----------------------------
def chaos_controller():
    while RUN:
        choice = random.choice([cpu_spike, memory_spike, network_spike, file_storm])
        t = threading.Thread(target=choice)
        t.start()
        time.sleep(0.3)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    print("🔥 Aggressive Attack Simulation Started")

    threads = []

    for _ in range(3):
        threads.append(threading.Thread(target=cpu_spike))

    for _ in range(2):
        threads.append(threading.Thread(target=memory_spike))

    for _ in range(3):
        threads.append(threading.Thread(target=network_spike))

    for _ in range(2):
        threads.append(threading.Thread(target=file_storm))

    threads.append(threading.Thread(target=chaos_controller))

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        RUN = False
        print("🛑 Attack stopped")