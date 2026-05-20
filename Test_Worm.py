import multiprocessing
import time
import os

# ==========================
# SAFE FORK-BOMB EMULATOR
# Defensive Testing Only
# ==========================

MAX_CHILDREN = 10
DEPTH_LIMIT = 6
SLEEP_TIME = 1

children = []


def worker(depth):
    print(f"[PID {os.getpid()}] Running at depth {depth}")

    time.sleep(SLEEP_TIME)

    # Simulated CPU activity
    x = 0
    for _ in range(3000000):
        x += 1

    # Controlled spawning
    if depth < DEPTH_LIMIT:
        for _ in range(2):

            if len(children) >= MAX_CHILDREN:
                return

            p = multiprocessing.Process(
                target=worker,
                args=(depth + 1,)
            )

            children.append(p)
            p.start()


if __name__ == "__main__":

    print("[*] Starting SAFE fork-bomb emulator")

    root = multiprocessing.Process(
        target=worker,
        args=(0,)
    )

    children.append(root)
    root.start()

    # Monitor
    while any(p.is_alive() for p in children):
        alive = sum(p.is_alive() for p in children)

        print(f"[MONITOR] Active processes: {alive}")

        time.sleep(1)

    print("[*] Emulator finished safely")
