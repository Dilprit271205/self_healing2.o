# Self-Healing Cybersecurity Implementation Notes

## Research Baseline

Self-healing cyber defense should follow a resilience loop:

1. Identify assets and context.
2. Protect with safe defaults and least-disruptive controls.
3. Detect anomalies with telemetry fusion.
4. Respond with reversible containment first.
5. Recover services and trust state.
6. Learn from outcomes without turning false positives into future kill rules.

This maps to the NIST Cybersecurity Framework functions of Identify,
Protect, Detect, Respond, and Recover. MITRE D3FEND provides the defensive
countermeasure framing: sensing, containment, isolation, restoration, and
hardening should be selected from observed adversary behavior, not from a
single noisy signal.

Recent autonomous-defense research also emphasizes resilience cost: a defense
that kills legitimate work has high operational damage even if it stops a
suspected attack. The local implementation therefore treats termination as
the final response, not the default response.

Primary references:

- NIST CSF functions: https://www.nist.gov/cyberframework/csf-11-five-functions
- MITRE D3FEND: https://d3fend.mitre.org/
- Self-healing ML systems survey: https://www.mdpi.com/1999-5903/15/7/244/html
- Autonomous cyber-defense resilience modeling: https://arxiv.org/abs/2503.02780

## Implemented Policy

The code now has an evidence-gated self-healing policy in
`analysis/self_healing_policy.py`.

It computes independent evidence domains:

- process storm
- file replication
- network fanout
- resource pressure
- persistence artifact
- sensitive access
- trust anomaly
- learned behavior
- catastrophic behavior

Response stages are then capped:

- single weak signal: observe or throttle
- two concrete domains: quarantine at most
- terminate: only catastrophic evidence, or termination-ready high-risk
  behavior with at least three concrete evidence domains and collapsed trust
- suppressed developer/system categories: capped to throttle unless
  catastrophic
- low risk with high trust: trust recovery

The response engine also protects terminal-launched interactive workloads.
A simple `./program` or `python script.py` started from an operator shell is
not terminated unless the state is catastrophic.

## Why This Fixes The Earlier Failure

The earlier loop could promote emergency preflight results directly to
`force_terminate=True`. That meant benign programs could be killed after a
single noisy behavior signal.

The new policy adds a final actuator-side safety gate. Even if a classifier,
learning recommendation, or emergency preflight asks for termination, the
response layer only acts destructively when the evidence is broad enough.
