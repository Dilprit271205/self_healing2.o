def decide_action(trust):
    actions = {}

    for dim, value in trust.items():
        if value > 0.85:
            actions[dim] = "normal"
        elif value > 0.65:
            actions[dim] = "watchlist"
        elif value > 0.4:
            actions[dim] = "restricted"
        else:
            actions[dim] = "critical"

    return actions