Self-Healing System — Notes & Test Instructions

Overview

This repository implements a self-healing process that detects worm-like behavior and attempts automated remediation (isolate, block resources, terminate).

Configuration (environment variables)

- SELF_HEALING_SAFE_MODE (default: false)
  - When true, healing actions are disabled.
- SELF_HEALING_PERSISTENCE_DELTA (default: 3)
  - Number of recent samples required before persistence-driven escalation.
- SELF_HEALING_MAX_SAFE_KILL (default: 300)
  - Maximum number of child processes allowed for an automated termination. If exceeded, the system will escalate to `block_resources` instead of mass killing.
- SELF_HEALING_WEIGHT_CONN_VEL (default: 3.5)
- SELF_HEALING_WEIGHT_REMOTE_IPS (default: 2.5)
- SELF_HEALING_WEIGHT_SCANNING (default: 8.0)
- SELF_HEALING_SCANNING_BOOST (default: 40)
  - Tuning knobs for detection signal weights.
 - SELF_HEALING_ALLOW_PRIVILEGE (default: false)
   - When true, enables privileged containment actions (iptables/nft/systemd-run). Use only in controlled environments and when running as root.

Testing

Quick local test (safe): runs `worm_sim.py` and attempts termination via the ResponseEngine test harness.

```bash
# from repository root
PYTHONPATH=. python3 tests/test_terminate_sim.py
```

Enable actual healing in a controlled environment:

```bash
export SELF_HEALING_SAFE_MODE=false
# optionally tune vars
export SELF_HEALING_PERSISTENCE_DELTA=4
export SELF_HEALING_MAX_SAFE_KILL=200
python3 main.py
```

Notes & Next Steps

- I can compile a research summary of relevant papers (PPT trust model, anomaly persistence, automated remediation) and propose algorithmic refinements. To fetch papers I need web access — tell me if you want me to gather public literature now.
- Recommend running the system in a sandbox/container before enabling full automatic remediation on production hosts.
