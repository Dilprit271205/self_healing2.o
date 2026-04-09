trust_db = {}

def initialize_trust(pid):
    if pid not in trust_db:
        trust_db[pid] = {
            "cpu": 1.0,
            "file": 1.0,
            "net": 1.0
        }

def get_trust(pid):
    return trust_db.get(pid, {"cpu": 1, "file": 1, "net": 1})