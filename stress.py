import multiprocessing
import time

# -----------------------------
# CPU STRESS
# -----------------------------
def cpu_stress():
    while True:
        _ = 9999999 * 9999999


# -----------------------------
# MEMORY STRESS
# -----------------------------
def memory_stress():
    memory = []
    try:
        while True:
            # Allocate ~20MB each iteration
            memory.append("X" * 20_000_000)
            time.sleep(0.2)
    except MemoryError:
        print("Memory exhausted")


# -----------------------------
# FILE STRESS (optional)
# -----------------------------
def file_stress():
    while True:
        with open("temp_stress.txt", "a") as f:
            f.write("stress_data\n")
        time.sleep(0.01)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    processes = []

    print("🔥 Starting stress test...")

    # CPU stress (all cores)
    for _ in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=cpu_stress)
        p.start()
        processes.append(p)

    # Memory stress
    mem = multiprocessing.Process(target=memory_stress)
    mem.start()
    processes.append(mem)

    # File stress (optional)
    file_p = multiprocessing.Process(target=file_stress)
    file_p.start()
    processes.append(file_p)

    print("🚀 Running... Press CTRL + C to stop")

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")

        for p in processes:
            p.terminate()