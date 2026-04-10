def decide_action(trust):
    final = trust.get("final_trust", 1.0)

    actions = {}

    # 🔥 PRIMARY DECISION (based on final trust)
    if final < 0.3:
        actions["level"] = "critical"
        actions["action"] = "kill_process"

    elif final < 0.6:
        actions["level"] = "suspicious"
        actions["action"] = "restrict"

    else:
        actions["level"] = "normal"
        actions["action"] = "allow"

    # 🔍 Optional: include breakdown (for dashboard visibility)
    actions["scores"] = {
        "static": trust.get("static_trust", 1),
        "dynamic": trust.get("dynamic_trust", 1),
        "final": final
    }

    return actions