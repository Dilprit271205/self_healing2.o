Self-Healing System — Notes & Test Instructions

Overview

This repository implements a self-healing process that detects worm-like behavior and attempts automated remediation (isolate, block resources, terminate).
The Streamlit dashboard is the operator view: it shows live flags, explains why they were raised, and displays the self-healing action currently being taken.

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
- SELF_HEALING_DASHBOARD_REFRESH_MS (default: 500)
  - Dashboard refresh interval in milliseconds.
- SELF_HEALING_DASHBOARD_EVENT_MEMORY_SECONDS (default: 180)
  - How long live self-healing alerts remain visible after a security event.
- SELF_HEALING_DASHBOARD_TAIL_SECURITY_ROWS (default: 300)
  - Number of recent log rows checked for security events even if event timestamps are stale.

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

Run the dashboard in another terminal:

```bash
streamlit run dashboard.py
```

The dashboard reads `logs/system_log.json`, `logs/healing_log.json`, and `logs/learning_kb.json`. Restart Streamlit after changing dashboard code or environment variables.

Notes & Next Steps

- I can compile a research summary of relevant papers (PPT trust model, anomaly persistence, automated remediation) and propose algorithmic refinements. To fetch papers I need web access — tell me if you want me to gather public literature now.
- Recommend running the system in a sandbox/container before enabling full automatic remediation on production hosts.
