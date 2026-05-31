# Host-Level Fork-Bomb Detection & Autonomous Termination

## Problem Statement
The self-healing system needed to detect and autonomously terminate fork-bomb worms at the host level, not just script-based worm simulations. Previous implementation had:
- False positives on static system process trees (e.g., `docker-init` with 150 children)
- Weak fork-bomb detection thresholds
- Lack of end-to-end autonomous termination validation

## Solution Overview

### 1. **Hardened Fork-Bomb Detection Scoring** 
**File**: `analysis/worm_classifier.py`

- **Tree Pressure Only on Active Growth**: The classifier now only applies tree pressure scoring when `process_growth > 0`. This eliminates false positives from stable system processes that have large static process trees.
  
  ```python
  # Before: tree_pressure was always applied
  tree_pressure = max(process_tree - 10, 0) * 0.20
  
  # After: tree_pressure only when actively forking
  tree_pressure = 0
  if process_growth > 0:
      tree_pressure = max(process_tree - 10, 0) * 0.20
  ```

- **Explicit Fork-Bomb Heuristics**: Added environment-configurable fork-bomb detection:
  - `SELF_HEALING_FORK_RATE_YOUNG`: Minimum spawn rate for young processes (default: 4 spawns/sample)
  - `SELF_HEALING_FORK_RATE_ABSOLUTE`: Aggressive fork rate threshold (default: 10 spawns/sample)
  - `SELF_HEALING_FORK_TREE_THRESHOLD`: Process tree size trigger (default: 20 children)

- **Visible Fork-Bomb Signal**: Added `forkbomb_detected` flag to classifier output for debugging and audit trails.

### 2. **Tuned Immediate Mitigation Thresholds**
**File**: `main.py` (execute_healing function)

- **Lowered from 20/50 to 12/25**: Fork-bombs are caught faster without compromising detection accuracy
  - `SELF_HEALING_FORK_IMMEDIATE_RATE`: Spawn rate for immediate termination (default: 12)
  - `SELF_HEALING_FORK_IMMEDIATE_TREE`: Process tree size for immediate termination (default: 25)

### 3. **Enhanced Test Validation**
**File**: `tests/test_forkbomb_detect.py`

Added strict assertions to verify:
- ✅ Correct healing stage transitions to "terminate"
- ✅ Action taken is confirmed True (actual process killed)
- ✅ Parent process confirmed dead after healing

## Validation Results

### False Positive Reduction
**Before Fix**: `docker-init` with 150 children flagged as 'suspicious'
```
PID 1: docker-init | tree=150 | worm_score=12.35 | label='suspicious'
```

**After Fix**: `docker-init` with 150 children correctly classified as 'normal'
```
PID 1: docker-init | tree=150 | worm_score=0.054 | label='normal'
```

### Fork-Bomb Detection
Early-stage fork-bomb (6 children, 1-2 spawns):
```
Classification: worm_score=0.211 | label='suspicious' | forkbomb_detected=False
```

After autonomous healing triggers (~25-60 children):
```
[ResponseEngine] Attempting termination: pid=50648
Healing result: action_taken=True | status='terminated'
```

### End-to-End Test Results
```
✓ Worm Termination Test
  - Spawned worm_sim successfully
  - Termination executed
  - action_taken: True
  - Process poll: 0 (confirmed dead)

✓ Fork-Bomb Detection Test
  - Spawned forkbomb_sim successfully
  - 56 children reached before healing
  - Autonomous termination executed
  - action_taken: True
```

## Configuration

### Environment Variables
```bash
# Fork-bomb detection thresholds
export SELF_HEALING_FORK_RATE_YOUNG=4           # spawns/sample for young processes
export SELF_HEALING_FORK_RATE_ABSOLUTE=10       # absolute aggressive spawn rate
export SELF_HEALING_FORK_TREE_THRESHOLD=20      # process tree size trigger

# Immediate termination thresholds
export SELF_HEALING_FORK_IMMEDIATE_RATE=12      # spawn rate for immediate kill
export SELF_HEALING_FORK_IMMEDIATE_TREE=25      # tree size for immediate kill

# Enable privileged containment (optional)
export SELF_HEALING_ALLOW_PRIVILEGE=true

# Safe mode (disables actual healing)
export SELF_HEALING_SAFE_MODE=false
```

## Files Modified

1. **analysis/worm_classifier.py**
   - Tree pressure only applied on active growth
   - Added `forkbomb_detected` field to signals output

2. **main.py** (execute_healing function)
   - Lowered fork-bomb thresholds from 20/50 to 12/25
   - Environment variable defaults updated

3. **tests/test_forkbomb_detect.py**
   - Added strict assertions for healing stage and action confirmation

## Key Technical Insights

1. **Static vs. Dynamic Process Trees**: The critical fix was distinguishing between:
   - **Static trees**: System services with many children that don't actively fork (no growth)
   - **Fork-bombs**: Young processes with rapid growth and/or large expanding trees

2. **Temporal Intelligence**: Growth rate (`f_proc_spawn`) is now the primary signal, with tree size as a secondary confirmation rather than independent trigger.

3. **Safe Defaults**: Propagation scoring is conservative, requiring either:
   - Active spawning (high `process_growth`)
   - Combined signals (young age + suspicious name)
   - Explicit fork-bomb heuristics

## Production Deployment

### Recommended Flow
1. Enable monitoring loop: `PYTHONPATH=. python3 main.py`
2. Monitor logs in real-time: `tail -f logs/system_log.json`
3. For aggressive remediation: `export SELF_HEALING_ALLOW_PRIVILEGE=true`
4. Tune thresholds based on workload via environment variables

### CI/CD Safe Mode
For automated testing environments:
```bash
export SELF_HEALING_SAFE_MODE=true  # Disables actual process termination
```

## Future Improvements
- [ ] Machine learning model for threat scoring
- [ ] Distributed fork-bomb detection across network
- [ ] Custom signature matching for known worm patterns
- [ ] Integration with container orchestration (Kubernetes, Docker Swarm)
