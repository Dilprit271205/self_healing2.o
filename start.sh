#!/bin/bash
# Quick Start: Host-Level Fork-Bomb Detection & Autonomous Healing

set -e

echo "========================================="
echo "Self-Healing Worm Detection System"
echo "Host-Level Fork-Bomb Detection Ready"
echo "========================================="
echo

# Set working directory
WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$WORK_DIR"

# Configuration
export PYTHONPATH=.

# Fork-bomb detection tuning (can be overridden)
export SELF_HEALING_FORK_RATE_YOUNG="${SELF_HEALING_FORK_RATE_YOUNG:-4}"
export SELF_HEALING_FORK_RATE_ABSOLUTE="${SELF_HEALING_FORK_RATE_ABSOLUTE:-10}"
export SELF_HEALING_FORK_TREE_THRESHOLD="${SELF_HEALING_FORK_TREE_THRESHOLD:-20}"

# Immediate termination (can be overridden)
export SELF_HEALING_FORK_IMMEDIATE_RATE="${SELF_HEALING_FORK_IMMEDIATE_RATE:-12}"
export SELF_HEALING_FORK_IMMEDIATE_TREE="${SELF_HEALING_FORK_IMMEDIATE_TREE:-25}"

# Optional: Enable privileged network/cgroup quarantine
# export SELF_HEALING_ALLOW_PRIVILEGE=true

# Optional: Disable actual healing for safe testing
# export SELF_HEALING_SAFE_MODE=true

echo "[CONFIG] Fork-bomb detection thresholds:"
echo "  - Young process fork rate: $SELF_HEALING_FORK_RATE_YOUNG spawns/sample"
echo "  - Absolute fork rate: $SELF_HEALING_FORK_RATE_ABSOLUTE spawns/sample"
echo "  - Fork tree threshold: $SELF_HEALING_FORK_TREE_THRESHOLD children"
echo
echo "[CONFIG] Immediate termination thresholds:"
echo "  - Immediate fork rate: $SELF_HEALING_FORK_IMMEDIATE_RATE spawns/sample"
echo "  - Immediate tree size: $SELF_HEALING_FORK_IMMEDIATE_TREE children"
echo

# Validate Python environment
echo "[CHECK] Validating Python environment..."
python3 -c "import psutil; print('  ✓ psutil available')" || {
    echo "  ✗ psutil not found. Install with: pip3 install psutil"
    exit 1
}

# Validate compilation
echo "[CHECK] Validating module compilation..."
python3 -m py_compile main.py \
    analysis/worm_classifier.py \
    analysis/response_engine.py \
    analysis/detector_engine.py \
    analysis/persistence_engine.py \
    analysis/learning_engine.py && echo "  ✓ All modules compile"

# Run test suite (optional)
if [[ "$1" == "--test" ]]; then
    echo
    echo "[TEST] Running validation tests..."
    echo "  - Worm termination test..."
    PYTHONPATH=. python3 tests/test_terminate_sim.py > /tmp/test_worm.log 2>&1 && \
        echo "    ✓ Worm termination PASSED" || \
        echo "    ✗ Worm termination FAILED (see /tmp/test_worm.log)"
    
    echo "  - Fork-bomb detection test..."
    PYTHONPATH=. python3 tests/test_forkbomb_detect.py > /tmp/test_forkbomb.log 2>&1 && \
        echo "    ✓ Fork-bomb detection PASSED" || \
        echo "    ✗ Fork-bomb detection FAILED (see /tmp/test_forkbomb.log)"
    
    exit 0
fi

# Start monitoring loop
echo "[START] Starting self-healing monitor loop..."
echo "Press Ctrl+C to stop"
echo

PYTHONPATH=. python3 main.py
