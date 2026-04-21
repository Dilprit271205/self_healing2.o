
# analysis/trust/trust_update.py

from analysis.trust.trust_vector import (
    initialize_trust,
    update_dynamic_trust,
    update_static_trust,
    compute_final_trust,
    get_trust
)


def update_trust(pid, current_trust, anomalies, static_score):
    """
    Final tuned hybrid trust engine

    Goals:
    ✅ no global trust collapse
    ✅ idle daemons recover naturally
    ✅ only correlated malicious behavior punished
    ✅ worm processes trust crashes fast
    ✅ self-healing when clean

    anomaly keys:
    cpu, file, net, spawn, tree, trend
    """

    initialize_trust(pid)

    # ---------------------------------------------------
    # SAFE CURRENT VALUES
    # ---------------------------------------------------
    cpu_val = float(current_trust.get("cpu", 1.0))
    file_val = float(current_trust.get("file", 1.0))
    net_val = float(current_trust.get("net", 1.0))

    # ---------------------------------------------------
    # TUNED PARAMETERS
    # ---------------------------------------------------
    tiny_recovery = 0.01
    normal_recovery = 0.03
    clean_bonus = 0.05

    soft_penalty = 0.05
    medium_penalty = 0.12
    hard_penalty = 0.25

    # ---------------------------------------------------
    # READ FLAGS
    # ---------------------------------------------------
    cpu_flag = bool(anomalies.get("cpu", 0))
    file_flag = bool(anomalies.get("file", 0))
    net_flag = bool(anomalies.get("net", 0))

    spawn_flag = bool(anomalies.get("spawn", 0))
    tree_flag = bool(anomalies.get("tree", 0))
    trend_flag = bool(anomalies.get("trend", 0))

    # ---------------------------------------------------
    # IDLE / CLEAN STATE
    # If nothing suspicious happening, trust heals
    # ---------------------------------------------------
    no_activity = not (
        cpu_flag or file_flag or net_flag or
        spawn_flag or tree_flag or trend_flag
    )

    if no_activity:
        cpu_val += clean_bonus
        file_val += clean_bonus
        net_val += clean_bonus

    else:

        # -----------------------------------------------
        # CPU TRUST
        # -----------------------------------------------
        if cpu_flag:
            cpu_val -= medium_penalty
        else:
            cpu_val += tiny_recovery

        # -----------------------------------------------
        # FILE TRUST
        # -----------------------------------------------
        if file_flag:
            file_val -= medium_penalty
        else:
            file_val += tiny_recovery

        # -----------------------------------------------
        # NETWORK TRUST
        # -----------------------------------------------
        if net_flag:
            net_val -= medium_penalty
        else:
            net_val += tiny_recovery

        # -----------------------------------------------
        # WORM CORRELATION ENGINE
        # Only punish strongly when multiple signals align
        # -----------------------------------------------
        worm_hits = sum([
            spawn_flag,
            tree_flag,
            trend_flag
        ])

        # single weak signal = ignore mostly
        if worm_hits == 1:
            cpu_val -= soft_penalty

        # double signal = dangerous
        elif worm_hits == 2:
            cpu_val -= medium_penalty
            file_val -= soft_penalty
            net_val -= medium_penalty

        # triple signal = confirmed worm style
        elif worm_hits >= 3:
            cpu_val -= hard_penalty
            file_val -= medium_penalty
            net_val -= hard_penalty

        # spawn + trend strongest combo
        if spawn_flag and trend_flag:
            cpu_val -= 0.15
            net_val -= 0.10

    # ---------------------------------------------------
    # STATIC TRUST FUSION
    # bad binary path / suspicious file lowers max trust
    # ---------------------------------------------------
    if static_score < 0.40:
        cpu_val -= 0.08
        file_val -= 0.08
        net_val -= 0.08

    elif static_score > 0.80:
        cpu_val += normal_recovery
        file_val += normal_recovery
        net_val += normal_recovery

    # ---------------------------------------------------
    # CLAMP
    # ---------------------------------------------------
    cpu_val = round(max(0.0, min(1.0, cpu_val)), 3)
    file_val = round(max(0.0, min(1.0, file_val)), 3)
    net_val = round(max(0.0, min(1.0, net_val)), 3)

    # ---------------------------------------------------
    # PUSH DYNAMIC VECTOR
    # ---------------------------------------------------
    update_dynamic_trust(
        pid,
        cpu=cpu_val,
        file=file_val,
        net=net_val
    )

    # ---------------------------------------------------
    # STATIC VECTOR
    # ---------------------------------------------------
    update_static_trust(pid, static_score)

    # ---------------------------------------------------
    # FINAL SCORE
    # ---------------------------------------------------
    compute_final_trust(pid)

    # ---------------------------------------------------
    # RETURN FULL STATE
    # ---------------------------------------------------
    return get_trust(pid)