trust_db = {}


def initialize_trust(pid):
    if pid not in trust_db:
        trust_db[pid] = {
            # 🔹 Dynamic trust components
            "cpu": 1.0,
            "file": 1.0,
            "net": 1.0,

            # 🔹 Aggregated dynamic trust
            "dynamic_trust": 1.0,

            # 🔹 Static trust
            "static_trust": 1.0,

            # 🔹 Final hybrid trust
            "final_trust": 1.0
        }


def update_dynamic_trust(pid, cpu=None, file=None, net=None):
    initialize_trust(pid)

    if cpu is not None:
        trust_db[pid]["cpu"] = cpu
    if file is not None:
        trust_db[pid]["file"] = file
    if net is not None:
        trust_db[pid]["net"] = net

    # 🔹 Recompute dynamic trust (simple average)
    trust_db[pid]["dynamic_trust"] = round(
        (
            trust_db[pid]["cpu"] +
            trust_db[pid]["file"] +
            trust_db[pid]["net"]
        ) / 3,
        3
    )


def update_static_trust(pid, static_score):
    initialize_trust(pid)
    trust_db[pid]["static_trust"] = round(static_score, 3)


def compute_final_trust(pid, alpha=0.1):
    """
    alpha = weight of static trust
    (1 - alpha) = weight of dynamic trust
    """
    initialize_trust(pid)

    static_score = trust_db[pid]["static_trust"]
    dynamic_score = trust_db[pid]["dynamic_trust"]

    final_score = alpha * static_score + (1 - alpha) * dynamic_score

    trust_db[pid]["final_trust"] = round(final_score, 3)

    return trust_db[pid]["final_trust"]


def get_trust(pid):
    return trust_db.get(pid, {
        "cpu": 1.0,
        "file": 1.0,
        "net": 1.0,
        "dynamic_trust": 1.0,
        "static_trust": 1.0,
        "final_trust": 1.0
    })