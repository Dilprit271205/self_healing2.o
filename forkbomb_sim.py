import multiprocessing
import os
import time

# Safe forkbomb simulator for testing. Spawns processes quickly but bounded.
MAX_CHILDREN = int(os.getenv("FORKBOMB_MAX_CHILDREN", "80"))
SPAWN_DELAY = float(os.getenv("FORKBOMB_SPAWN_DELAY", "0.05"))
RUN_TIME = int(os.getenv("FORKBOMB_RUN_TIME", "60"))

children = []


def worker():
    # minimal work loop
    while True:
        x = 1
        x += 1


def cleanup():
    for p in children:
        try:
            p.terminate()
        except OSError as exc:
            print(f"[!] Failed to terminate child {getattr(p, 'pid', 'unknown')}: {exc}")


if __name__ == '__main__':
    start = time.time()
    try:
        while True:
            if time.time() - start > RUN_TIME:
                break
            if len(children) < MAX_CHILDREN:
                p = multiprocessing.Process(target=worker)
                p.start()
                children.append(p)
                print(f"[+] Spawned PID {p.pid} | Total: {len(children)}")
            time.sleep(SPAWN_DELAY)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
