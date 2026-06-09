import os
import glob

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
# PROCESS TERMINATION
# -----------------------------
def kill_stress_processes():
    print("[CLEANUP] Skipping process termination.")
    print("[CLEANUP] Runtime worm handling is behavior-based in main.py.")


# -----------------------------
# OPTIONAL: CLEAR LOG FILE
# -----------------------------
def clear_logs():
    print("[CLEANUP] Clearing logs...")

    try:
        with open(LOG_FILE, "w", encoding="utf-8"):
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
