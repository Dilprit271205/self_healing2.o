import json
import os
from copy import deepcopy


DEFAULT_POLICY = {
    "persistence": {
        "default_loops": 3,
        "termination_loops": 3,
        "catastrophic_loops": 1,
        "cooldown_loops": 2,
    },
    "response_thresholds": {
        "observe": {"risk": 0.25, "confidence": 0.25},
        "throttle": {"risk": 0.45, "confidence": 0.40},
        "quarantine": {"risk": 0.68, "confidence": 0.62},
        "terminate": {
            "risk": 0.86,
            "confidence": 0.82,
            "min_correlated_signals": 4,
        },
        "catastrophic_terminate": {
            "risk": 0.94,
            "confidence": 0.90,
            "min_correlated_signals": 5,
        },
    },
    "catastrophic_behavior": {
        "spawn_rate": 40,
        "process_tree": 120,
        "tree_growth": 60,
        "file_events": 300,
        "memory_percent": 85,
        "cpu_percent": 95,
    },
    "false_positive_suppression": {
        "suppressed_categories": [],
        "max_stage_without_confirmed_behavior": "throttle",
    },
    "category_hints": {},
    "critical_process_hints": [],
}


def _deep_merge(base, override):
    result = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class PolicyEngine:
    def __init__(self, path=None):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.path = path or os.getenv(
            "SELF_HEALING_POLICY_PATH",
            os.path.join(root, "config", "behavior_policy.json"),
        )
        self.policy = self._load_policy()

    def _load_policy(self):
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            return _deep_merge(DEFAULT_POLICY, loaded)
        except Exception:
            return deepcopy(DEFAULT_POLICY)

    def get(self, dotted_key, default=None):
        value = self.policy
        for part in dotted_key.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
        return value

    def infer_category(self, process_info):
        joined = " ".join(
            str(process_info.get(key, "") or "").lower()
            for key in ("name", "cmdline", "exe", "cwd")
        )
        matches = []
        for category, hints in self.get("category_hints", {}).items():
            if any(str(hint).lower() in joined for hint in hints):
                matches.append(category)
        return matches[0] if matches else "unknown"

    def is_suppressed_category(self, category):
        return category in set(
            self.get("false_positive_suppression.suppressed_categories", [])
        )

    def is_critical_process_hint(self, process_info):
        joined = " ".join(
            str(process_info.get(key, "") or "").lower()
            for key in ("name", "cmdline", "exe")
        )
        return any(
            str(hint).lower() in joined
            for hint in self.get("critical_process_hints", [])
        )

    def catastrophic_thresholds(self):
        return self.get("catastrophic_behavior", {})

    def response_thresholds(self):
        return self.get("response_thresholds", {})


policy_engine = PolicyEngine()
