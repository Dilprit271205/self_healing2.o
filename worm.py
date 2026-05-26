import os
import shutil
import time
import random

# Safe Worm Simulation
# ONLY FOR LOCAL VM/LAB TESTING

BASE_DIR = "worm_lab"
PAYLOAD_NAME = "safe_payload.txt"

# Create base lab directory
os.makedirs(BASE_DIR, exist_ok=True)

# Create initial payload
payload_path = os.path.join(BASE_DIR, PAYLOAD_NAME)

with open(payload_path, "w") as f:
    f.write("SAFE WORM SIMULATION FILE\n")

print("[+] Starting safe worm simulation...")

generation = 0
max_generations = 5

while generation < max_generations:
    print(f"[+] Generation {generation}")

    current_folder = os.path.join(BASE_DIR, f"gen_{generation}")
    os.makedirs(current_folder, exist_ok=True)

    # Create multiple copies
    for i in range(5):
        subfolder = os.path.join(current_folder, f"node_{i}")
        os.makedirs(subfolder, exist_ok=True)

        new_file = os.path.join(subfolder, PAYLOAD_NAME)
        shutil.copy(payload_path, new_file)

        print(f"[+] Spread to: {new_file}")

    generation += 1
    time.sleep(2)

print("[+] Simulation complete.")