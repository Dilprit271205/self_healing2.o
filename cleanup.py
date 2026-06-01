import os
import glob
import psutil

# -----------------------------
# CONFIG
# -----------------------------
LOG_FILE = "logs/system_log.json"


# -----------------------------
# DELETE TEMP FILES
# -----------------------------
def clean_temp_files():
    print("[CLEANUP] Cleaning temp files...")

    files = glob.glob("temp_*.txt") + ["temp_stress.txt"]

    for file in files:
        try:
            if os.path.exists(file):
                os.remove(file)
                print(f"Deleted: {file}")
        except Exception as e:
            print(f"Error deleting {file}: {e}")


# -----------------------------
# KILL STRESS PROCESSES
# -----------------------------
def kill_stress_processes():
    print("[CLEANUP] Killing stress-related processes...")

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = proc.info['name'] or ""
            cmd = " ".join(proc.info['cmdline'] or [])

            # Kill only safe known stress processes
            if (
                "stress.py" in cmd or
                "sleep" in name or
                "temp_stress" in cmd
            ):
                proc.kill()
                print(f"Killed PID {proc.pid} ({name})")

        except Exception:
            pass


# -----------------------------
# OPTIONAL: CLEAR LOG FILE
# -----------------------------
def clear_logs():
    print("[CLEANUP] Clearing logs...")

    try:
        with open(LOG_FILE, "w") as f:
            pass
        print("Logs cleared")
    except Exception as e:
        print("Error clearing logs:", e)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    print("[CLEANUP] Running cleanup...")

    clean_temp_files()
    kill_stress_processes()

    # Uncomment if you want fresh start
    # clear_logs()

    print("[CLEANUP] Cleanup complete")
