import multiprocessing
import os
import time
import tempfile

# -----------------------------------
# CONFIG
# -----------------------------------
MAX_CHILDREN = 25
SPAWN_DELAY = 0.25
RUN_TIME = 120   # max runtime in seconds

children = []

# -----------------------------------
# Worker = CPU Load
# -----------------------------------
def worker():
    x = 0
    while True:
        x += 1
        x *= 2
        x %= 999999


# -----------------------------------
# Fake replication marker
# -----------------------------------
def create_temp_markers():
    temp_dir = tempfile.gettempdir()

    for i in range(5):
        try:
            path = os.path.join(temp_dir, f"worm_copy_{i}.tmp")
            with open(path, "w", encoding="utf-8") as f:
                f.write("simulation")
        except OSError as exc:
            print(f"[!] Failed to write marker {path}: {exc}")


# -----------------------------------
# Cleanup
# -----------------------------------
def cleanup():
    print("[!] Cleaning child processes...")

    for p in children:
        try:
            p.terminate()
        except OSError as exc:
            print(f"[!] Failed to terminate child {getattr(p, 'pid', 'unknown')}: {exc}")


# -----------------------------------
# Main
# -----------------------------------
def main():
    print("[+] worm_sim.py started")
    print("[+] Simulating rabbit-worm behaviour")

    start = time.time()

    while True:

        # stop after timeout
        if time.time() - start > RUN_TIME:
            break

        # spawn children
        if len(children) < MAX_CHILDREN:
            p = multiprocessing.Process(target=worker)
            p.start()
            children.append(p)

            print(f"[+] Spawned PID {p.pid} | Total: {len(children)}")

        # fake file replication signals
        create_temp_markers()

        time.sleep(SPAWN_DELAY)

    cleanup()


# -----------------------------------
# Kill Handling
# -----------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cleanup()
