import ast
import html
import json
import os
import time
from pathlib import Path

try:
    import pandas as pd
    import streamlit as st
    import streamlit.components.v1 as components
except ImportError as exc:
    print(f"Dashboard unavailable: missing dependency {exc}.")

    class _Dummy:
        def __getattr__(self, _):
            return self

        def __call__(self, *_, **__):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def __bool__(self):
            return False

    st = _Dummy()
    pd = _Dummy()
    components = _Dummy()

    def st_autorefresh(*_, **__):
        return None
else:
    try:
        from streamlit_autorefresh import st_autorefresh
    except ImportError:
        def st_autorefresh(*_, **__):
            return None


def _env_int(name, default, minimum=None):
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _env_float(name, default, minimum=None):
    try:
        value = float(os.getenv(name, str(default)))
    except Exception:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


PROJECT_ROOT = Path(__file__).resolve().parent


def _project_path(env_name, default):
    configured = os.getenv(
        env_name
    )
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path

    default_path = Path(default)
    if default_path.is_absolute():
        return default_path

    candidates = []
    for root in (
        PROJECT_ROOT,
        PROJECT_ROOT.parent,
        Path.cwd(),
        Path.cwd().parent,
    ):
        candidate = root / default_path
        if candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return PROJECT_ROOT / default_path


DASHBOARD_MAX_ROWS = 1000
DASHBOARD_REFRESH_MS = _env_int("SELF_HEALING_DASHBOARD_REFRESH_MS", 2000, 500)
DASHBOARD_CACHE_TTL_SECONDS = _env_float(
    "SELF_HEALING_DASHBOARD_CACHE_TTL_SECONDS",
    1.0,
    0.0,
)
DASHBOARD_EVENT_MEMORY_SECONDS = _env_int(
    "SELF_HEALING_DASHBOARD_EVENT_MEMORY_SECONDS",
    180,
    1,
)
DASHBOARD_TAIL_SECURITY_ROWS = _env_int(
    "SELF_HEALING_DASHBOARD_TAIL_SECURITY_ROWS",
    300,
    25,
)
SYSTEM_LOG = _project_path("SELF_HEALING_SYSTEM_LOG", "logs/system_log.json")
HEALING_LOG = _project_path("SELF_HEALING_HEALING_LOG", "logs/healing_log.json")
LEARNING_KB_LOG = _project_path("SELF_HEALING_KB_PATH", "logs/learning_kb.json")
ACTIVE_RESPONSE_STAGES = {
    "restrict",
    "throttle",
    "isolate",
    "quarantine",
    "block_resources",
    "terminate",
}
ACTION_STATUS_PATTERN = (
    "terminated|isolated|throttled|quarantined|restricted"
)
HIGH_CONFIDENCE_TRUST_CUTOFF = 0.50


def _coerce_dashboard_dict(value):
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        for loader in (json.loads, ast.literal_eval):
            try:
                loaded = loader(value)
                return loaded if isinstance(loaded, dict) else {}
            except Exception:
                pass
    return {}


def _file_signature(path):
    try:
        stat = Path(path).stat()
        return {
            "path": str(path),
            "mtime": stat.st_mtime,
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "age_seconds": max(0, time.time() - stat.st_mtime),
        }
    except Exception:
        return {
            "path": str(path),
            "mtime": 0,
            "mtime_ns": 0,
            "size": 0,
            "age_seconds": None,
        }


@st.cache_data(ttl=DASHBOARD_CACHE_TTL_SECONDS)
def _read_json_lines(path, signature):
    path = Path(path)
    if not path.exists():
        return pd.DataFrame()

    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue

    if not rows:
        return pd.DataFrame()

    frame = pd.DataFrame(rows).tail(DASHBOARD_MAX_ROWS)
    frame["_log_index"] = range(len(frame))
    source_mtime = signature.get(
        "mtime",
        0,
    ) if isinstance(signature, dict) else 0
    frame["_source_mtime"] = pd.to_datetime(
        source_mtime,
        unit="s",
        errors="coerce",
    )
    if "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    return frame


@st.cache_data(ttl=DASHBOARD_CACHE_TTL_SECONDS)
def load_learning_kb(signature):
    del signature
    if not LEARNING_KB_LOG.exists():
        return pd.DataFrame()
    try:
        raw = json.loads(LEARNING_KB_LOG.read_text(encoding="utf-8"))
    except Exception:
        return pd.DataFrame()

    if not isinstance(raw, dict):
        return pd.DataFrame()

    rows = []
    for pattern_id, entry in raw.items():
        if isinstance(entry, dict):
            rows.append({"pattern_id": pattern_id, **entry})
    frame = pd.DataFrame(rows)
    if "last_seen" in frame.columns:
        frame["last_seen_time"] = pd.to_datetime(
            frame["last_seen"],
            unit="s",
            errors="coerce",
        )
    return frame


def _normalize_trust(value, default=1.0):
    try:
        number = float(value)
        if number > 1.0:
            number = number / 100.0
        return max(0.0, min(1.0, number))
    except Exception:
        return default


def _normalize_risk_score(value, default=0.0):
    try:
        number = float(value)
        if number > 1.0:
            number = number / 100.0
        return max(0.0, min(1.0, number))
    except Exception:
        return default


def _numeric(frame, column, default=0.0):
    if column not in frame.columns:
        frame[column] = default
    frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(default)
    return frame


def _normalize_process_rows(frame):
    if frame.empty:
        return frame

    frame = frame.copy()
    for column, default in {
        "pid": 0,
        "name": "unknown",
        "label": "normal",
        "severity": "low",
        "stage": "observe",
        "response": "none",
        "worm_score": 0.0,
        "confidence": 0.0,
        "dynamic_trust": 1.0,
        "final_trust": 1.0,
        "static_trust": 1.0,
        "cpu": 0.0,
        "memory": 0.0,
        "threads": 0.0,
        "connections": 0.0,
        "file_events": 0.0,
    }.items():
        if column not in frame.columns:
            frame[column] = default

    for column in ("dynamic_trust", "final_trust", "static_trust"):
        frame[column] = frame[column].apply(_normalize_trust)

    for column in (
        "worm_score",
        "confidence",
        "cpu",
        "memory",
        "threads",
        "connections",
        "file_events",
    ):
        frame = _numeric(frame, column)

    for column in ("signals", "anomalies", "features"):
        if column not in frame.columns:
            frame[column] = [{} for _ in range(len(frame))]
        frame[column] = frame[column].apply(_coerce_dashboard_dict)

    frame["worm_pattern_anomaly"] = frame["anomalies"].apply(
        lambda item: float(item.get("worm_pattern", item.get("aggregate", 0)) or 0)
    )
    frame["aggregate_anomaly"] = frame["anomalies"].apply(
        lambda item: float(item.get("aggregate", 0) or 0)
    )
    frame["trust_anomaly_pressure"] = frame.apply(
        lambda row: max(
            1.0 - float(row["dynamic_trust"]),
            float(row["worm_pattern_anomaly"]),
        ),
        axis=1,
    )
    frame["trust_drop_risk"] = (
        frame["static_trust"] - frame["dynamic_trust"]
    ).clip(lower=0)

    frame["correlated_signal_count"] = frame["signals"].apply(
        lambda signals: int(signals.get("correlated_signal_count", 0) or 0)
    )
    frame["ml_anomaly_probability"] = frame["signals"].apply(
        lambda signals: float(signals.get("ml_anomaly_probability", 0) or 0)
    )
    frame["trust_anomaly_pattern"] = frame["signals"].apply(
        lambda signals: bool(signals.get("trust_anomaly_pattern", False))
    )
    frame["worm_like_behavior"] = frame["signals"].apply(
        lambda signals: bool(signals.get("worm_like_behavior", False))
    )
    frame["category_suppressed"] = frame.apply(
        lambda row: bool(
            _coerce_dashboard_dict(row.get("signals")).get(
                "category_suppressed",
                False
            )
            or _coerce_dashboard_dict(row.get("features")).get(
                "false_positive_suppression",
                0
            )
        ),
        axis=1,
    )
    frame["confirmed_behavior"] = (
        frame["worm_like_behavior"].astype(bool)
        | frame["signals"].apply(
            lambda signals: any(
                bool(signals.get(key, False))
                for key in (
                    "forkbomb_detected",
                    "replication_detected",
                    "fanout_detected",
                    "artifact_abuse_detected",
                    "thread_storm_detected",
                    "catastrophic_behavior",
                )
            )
        )
        | (frame["correlated_signal_count"] >= 3)
    )
    frame["strong_worm_score"] = frame["worm_score"].apply(
        lambda value: _normalize_risk_score(value) >= 0.65
    )
    high_severity = frame["severity"].astype(str).str.lower().isin(
        {"high", "critical"}
    )
    active_response = (
        frame["stage"].astype(str).str.lower().isin(ACTIVE_RESPONSE_STAGES)
        | frame["response"].astype(str).str.lower().str.contains(
            ACTION_STATUS_PATTERN,
            na=False,
        )
    )
    high_confidence_label = (
        frame["label"].astype(str).str.lower().isin({"worm", "forkbomb"})
        & (
            frame["strong_worm_score"].astype(bool)
            | frame["confirmed_behavior"].astype(bool)
        )
    )
    high_confidence_severity = (
        high_severity
        & (
            frame["confirmed_behavior"].astype(bool)
            | frame["strong_worm_score"].astype(bool)
            | (frame["correlated_signal_count"] >= 2)
            | (frame["final_trust"] < HIGH_CONFIDENCE_TRUST_CUTOFF)
        )
    )
    frame["flagged"] = (
        (
            high_confidence_label
            | high_confidence_severity
            | frame["confirmed_behavior"].astype(bool)
            | frame["strong_worm_score"].astype(bool)
            | active_response
        )
        & (
            ~frame["category_suppressed"].astype(bool)
            | frame["confirmed_behavior"].astype(bool)
            | frame["severity"].astype(str).str.lower().eq("critical")
            | active_response
        )
    )
    return frame


def _latest_by_pid(frame):
    if frame.empty or "pid" not in frame.columns:
        return pd.DataFrame()

    if "_log_index" in frame.columns:
        ordered = frame.sort_values("_log_index")
    elif "timestamp" in frame.columns:
        ordered = frame.sort_values("timestamp")
    else:
        ordered = frame

    return ordered.groupby("pid", as_index=False).tail(1)


def _recent_rows(frame, seconds=45, trust_source_mtime=False):
    if frame.empty:
        return frame

    now = pd.Timestamp.now()
    future_grace = now + pd.Timedelta(
        seconds=5
    )
    cutoff = now - pd.Timedelta(
        seconds=seconds
    )

    recent_mask = pd.Series(
        False,
        index=frame.index,
    )

    if "timestamp" in frame.columns:
        timestamps = pd.to_datetime(
            frame["timestamp"],
            errors="coerce"
        )
        recent_mask = recent_mask | (
            (timestamps >= cutoff)
            &
            (timestamps <= future_grace)
        )
    else:
        timestamps = pd.Series(
            pd.NaT,
            index=frame.index,
        )

    if "_source_mtime" in frame.columns:
        source_times = pd.to_datetime(
            frame["_source_mtime"],
            errors="coerce"
        )
        # Some test and demo generators replay fixed event timestamps while
        # actively appending to the log. Treat a hot source file as live so the
        # dashboard follows what is being written instead of freezing at zero.
        if trust_source_mtime:
            source_time_eligible = pd.Series(
                True,
                index=frame.index,
            )
        else:
            source_time_eligible = timestamps.isna()
        recent_mask = recent_mask | (
            source_time_eligible
            &
            (source_times >= cutoff)
            &
            (source_times <= future_grace)
        )

    recent = frame[
        recent_mask
    ]
    if not recent.empty:
        return recent

    return frame.iloc[0:0]


def _live_latest_rows(frame, seconds=45, trust_source_mtime=False):
    recent = _recent_rows(
        frame,
        seconds=seconds,
        trust_source_mtime=trust_source_mtime,
    )
    return _latest_by_pid(
        recent
    )


def _security_event_mask(frame):
    if frame is None or frame.empty:
        return pd.Series(dtype=bool)

    index = frame.index
    flagged = (
        frame.get("flagged", pd.Series(False, index=index))
        .astype(bool)
    )
    severe_with_evidence = (
        frame.get("severity", pd.Series("", index=index))
        .astype(str)
        .str.lower()
        .isin({"high", "critical"})
        & (
            frame.get("confirmed_behavior", pd.Series(False, index=index))
            .astype(bool)
            | frame.get("strong_worm_score", pd.Series(False, index=index))
            .astype(bool)
            | (
                pd.to_numeric(
                    frame.get(
                        "correlated_signal_count",
                        pd.Series(0, index=index),
                    ),
                    errors="coerce",
                ).fillna(0)
                >= 2
            )
            | (
                pd.to_numeric(
                    frame.get(
                        "final_trust",
                        pd.Series(1.0, index=index),
                    ),
                    errors="coerce",
                ).fillna(1.0)
                < HIGH_CONFIDENCE_TRUST_CUTOFF
            )
        )
    )
    response_stage = (
        frame.get("stage", pd.Series("", index=index))
        .astype(str)
        .str.lower()
        .isin(ACTIVE_RESPONSE_STAGES)
    )
    response_text = (
        frame.get("response", pd.Series("", index=index))
        .astype(str)
        .str.lower()
        .str.contains(ACTION_STATUS_PATTERN, na=False)
    )

    return flagged | severe_with_evidence | response_stage | response_text


def _security_memory_rows(frame, seconds=60, trust_source_mtime=False):
    recent = _recent_rows(
        frame,
        seconds=seconds,
        trust_source_mtime=trust_source_mtime,
    )
    if recent.empty:
        return recent

    security_rows = recent[
        _security_event_mask(
            recent
        )
    ]
    if security_rows.empty:
        return security_rows

    return _latest_by_pid(
        security_rows
    )


def _dashboard_state_rows(
    frame,
    live_seconds=12,
    event_seconds=60,
    trust_source_mtime=False,
):
    live = _live_latest_rows(
        frame,
        seconds=live_seconds,
        trust_source_mtime=trust_source_mtime,
    )
    memory = _security_memory_rows(
        frame,
        seconds=event_seconds,
        trust_source_mtime=trust_source_mtime,
    )

    if live.empty:
        return memory
    if memory.empty:
        return live

    combined = pd.concat(
        [live, memory],
        ignore_index=True,
    )
    combined["_security_priority"] = _security_event_mask(
        combined
    ).astype(int)
    sort_columns = [
        column
        for column in (
            "pid",
            "_security_priority",
            "_log_index",
            "timestamp",
        )
        if column in combined.columns
    ]

    return combined.sort_values(
        sort_columns,
    ).groupby(
        "pid",
        as_index=False,
    ).tail(
        1
    ).drop(
        columns=[
            "_security_priority",
        ],
        errors="ignore",
    )


def _recent_security_rows(
    frame,
    seconds=180,
    limit=100,
    trust_source_mtime=False,
):
    recent = _recent_rows(
        frame,
        seconds=seconds,
        trust_source_mtime=trust_source_mtime,
    )
    if recent.empty:
        return recent

    security = recent[
        _security_event_mask(
            recent
        )
    ]
    if security.empty:
        return security

    sort_columns = [
        column
        for column in (
            "_log_index",
            "timestamp",
        )
        if column in security.columns
    ]
    if sort_columns:
        security = security.sort_values(
            sort_columns,
        )

    return security.tail(
        limit
    )


def _tail_security_rows(frame, limit=300):
    if frame is None or frame.empty:
        return pd.DataFrame()

    tail = frame.tail(
        max(1, int(limit))
    ).copy()
    security = tail[
        _security_event_mask(
            tail
        )
    ]
    if security.empty:
        return security

    sort_columns = [
        column
        for column in (
            "_log_index",
            "timestamp",
        )
        if column in security.columns
    ]
    if sort_columns:
        security = security.sort_values(
            sort_columns,
        )

    return security


def _combine_dashboard_rows(*frames):
    available = [
        frame
        for frame in frames
        if frame is not None and not frame.empty
    ]
    if not available:
        return pd.DataFrame()

    combined = pd.concat(
        available,
        ignore_index=True,
    )
    if "_log_index" in combined.columns:
        combined = combined.drop_duplicates(
            subset=[
                column
                for column in (
                    "pid",
                    "stage",
                    "response",
                    "_log_index",
                )
                if column in combined.columns
            ],
            keep="last",
        )
    return combined


def _dashboard_security_rows(frame, seconds=180, tail_limit=300):
    return _combine_dashboard_rows(
        _recent_security_rows(
            frame,
            seconds=seconds,
            limit=tail_limit,
        ),
        _tail_security_rows(
            frame,
            limit=tail_limit,
        ),
    )


def _overlay_healing_status(process_rows, healing_rows, fallback_rows=None):
    if process_rows is None or process_rows.empty:
        return fallback_rows if fallback_rows is not None else pd.DataFrame()
    if healing_rows is None or healing_rows.empty or "pid" not in healing_rows.columns:
        return process_rows

    output = process_rows.copy()
    healing = healing_rows.copy()
    if "timestamp" in healing.columns:
        healing["timestamp"] = pd.to_datetime(healing["timestamp"], errors="coerce")
        healing = healing.sort_values("timestamp")

    latest_healing = healing.groupby("pid", as_index=False).tail(1)
    overlay = latest_healing.set_index("pid").to_dict("index")

    for idx, row in output.iterrows():
        state = overlay.get(row.get("pid"))
        if not state:
            continue
        process_time = row.get("timestamp")
        healing_time = state.get("timestamp")
        if (
            pd.notna(process_time)
            and pd.notna(healing_time)
            and healing_time < process_time - pd.Timedelta(seconds=2)
        ):
            continue
        for source, target in {
            "stage": "stage",
            "status": "response",
            "action_taken": "action_taken",
        }.items():
            if source in state and pd.notna(state[source]):
                output.at[idx, target] = state[source]

    return output


def _healing_stage_trust(stage, action_taken=False):
    stage = str(
        stage
        or "observe"
    ).lower()
    if stage == "terminate":
        return 0.25
    if stage == "quarantine":
        return 0.45
    if stage in {"throttle", "block_resources", "restrict"}:
        return 0.65
    if action_taken:
        return 0.70
    return 0.92


def _healing_rows_as_process_rows(
    healing_rows,
    seconds=60,
    trust_source_mtime=False,
):
    if healing_rows is None or healing_rows.empty:
        return pd.DataFrame()

    recent = _recent_rows(
        healing_rows,
        seconds=seconds,
        trust_source_mtime=trust_source_mtime,
    )
    if recent.empty:
        return pd.DataFrame()

    stage = (
        recent.get("stage", pd.Series("", index=recent.index))
        .astype(str)
        .str.lower()
    )
    status = (
        recent.get("status", pd.Series("", index=recent.index))
        .astype(str)
        .str.lower()
    )
    action_taken = (
        recent.get("action_taken", pd.Series(False, index=recent.index))
        .astype(bool)
    )
    actionable = recent[
        action_taken
        | stage.isin(ACTIVE_RESPONSE_STAGES)
        | status.str.contains(
            ACTION_STATUS_PATTERN,
            na=False,
        )
    ]

    latest = _latest_by_pid(
        actionable
    )
    if latest.empty:
        return pd.DataFrame()

    rows = []
    for _, row in latest.iterrows():
        stage = str(
            row.get(
                "stage",
                "observe"
            )
            or "observe"
        ).lower()
        action_taken = bool(
            row.get(
                "action_taken",
                False
            )
        )
        final_trust = _healing_stage_trust(
            stage,
            action_taken=action_taken,
        )
        flagged = stage in ACTIVE_RESPONSE_STAGES or action_taken
        rows.append({
            "timestamp": row.get("timestamp"),
            "_log_index": row.get("_log_index"),
            "_source_mtime": row.get("_source_mtime"),
            "pid": row.get("pid"),
            "name": "healing-action",
            "label": "response" if flagged else "normal",
            "severity": "critical" if stage == "terminate" else ("high" if flagged else "low"),
            "stage": stage,
            "response": row.get("status", "healing event"),
            "action_taken": action_taken,
            "dynamic_trust": final_trust,
            "final_trust": final_trust,
            "static_trust": 0.85,
            "worm_score": 0.90 if flagged else 0.0,
            "confidence": 90 if flagged else 0,
            "cpu": 0.0,
            "memory": 0.0,
            "threads": 0.0,
            "connections": 0.0,
            "file_events": 0.0,
            "signals": {
                "correlated_signal_count": 1 if flagged else 0,
                "healing_event": flagged,
            },
            "anomalies": {},
            "features": {
                "healing_fallback": True,
            },
        })

    return _normalize_process_rows(
        pd.DataFrame(rows)
    )


def _active_flag_rows(rows):
    if rows is None or rows.empty:
        return pd.DataFrame()

    output = []
    for _, item in rows.iterrows():
        active = _flag_terms(item)

        if not active and not bool(item.get("flagged", False)):
            continue

        stage = str(
            item.get(
                "stage",
                "observe",
            )
            or "observe"
        ).lower()
        explanation = "; ".join(
            FLAG_EXPLANATIONS.get(flag, flag.replace("_", " "))
            for flag in active[:4]
        )

        output.append({
            "pid": item.get("pid"),
            "name": item.get("name"),
            "label": item.get("label"),
            "severity": item.get("severity"),
            "stage": item.get("stage"),
            "final_trust": item.get("final_trust"),
            "worm_score": item.get("worm_score"),
            "trust_anomaly_pressure": item.get("trust_anomaly_pressure"),
            "flags": ", ".join(sorted(set(active))) if active else "low_trust",
            "why": explanation,
            "self_healing_action": ACTION_EXPLANATIONS.get(
                stage,
                "Monitoring and keeping telemetry visible.",
            ),
        })

    return pd.DataFrame(output)


FLAG_EXPLANATIONS = {
    "forkbomb_detected": "rapid recursive process spawning was detected",
    "process_storm_burst": "process count rose fast enough to indicate a storm",
    "large_or_growing_tree": "the process family is growing unusually large",
    "repeated_similar_children": "many children share the same executable pattern",
    "short_lived_recursive_children": "children are appearing and exiting in a recursive pattern",
    "deep_recursive_tree": "the process lineage is deeper than normal",
    "replication_detected": "file replication behavior was confirmed",
    "file_replication": "files are being copied or rewritten in a replication pattern",
    "high_file_velocity": "file events are arriving quickly",
    "extreme_file_velocity": "file velocity is high enough to look destructive",
    "mass_file_modification": "many files are being changed in a short window",
    "suspicious_rename": "rename activity resembles staged encryption or evasion",
    "fanout_detected": "network fanout behavior was confirmed",
    "localhost_beaconing": "repeated localhost connections look like beaconing",
    "network_fanout": "connections are spreading across endpoints or ports",
    "artifact_abuse_detected": "persistence or sensitive artifact abuse was detected",
    "persistence_artifact": "startup, script, or persistence artifacts were touched",
    "sensitive_file_access": "sensitive paths or credential-like files were accessed",
    "thread_storm_detected": "thread creation looks like a resource storm",
    "thread_explosion": "thread count jumped sharply",
    "cpu_memory_escalation": "resource usage is escalating",
    "resource_pressure": "system pressure is high enough to affect trust",
    "trust_anomaly_pattern": "trust dropped in a learned suspicious pattern",
    "worm_like_behavior": "multiple signals combine into worm-like behavior",
    "catastrophic_behavior": "catastrophic behavior is severe enough for immediate response",
    "healing_event": "a self-healing action was recorded",
    "low_trust": "final trust fell below the response threshold",
}


ACTION_EXPLANATIONS = {
    "observe": "Monitoring only; evidence is not strong enough to intervene.",
    "protected": "Action blocked because the target matches a protected workload.",
    "trust_recovery": "Recovering trust after risk dropped below the response threshold.",
    "throttle": "Reducing activity to slow the process while collecting more evidence.",
    "block_resources": "Restricting resources to contain active pressure.",
    "restrict": "Applying a reversible restriction before stronger containment.",
    "quarantine": "Isolating the process or related behavior to prevent spread.",
    "terminate": "Stopping the process family because evidence crossed the termination policy.",
}


def _flag_terms(row):
    signals = _coerce_dashboard_dict(row.get("signals"))
    correlated = _coerce_dashboard_dict(signals.get("correlated_signals"))
    active = [
        name
        for name, value in correlated.items()
        if bool(value)
    ]
    for key in (
        "forkbomb_detected",
        "replication_detected",
        "fanout_detected",
        "artifact_abuse_detected",
        "thread_storm_detected",
        "trust_anomaly_pattern",
        "worm_like_behavior",
        "catastrophic_behavior",
        "healing_event",
    ):
        if signals.get(key):
            active.append(key)

    if not active and bool(row.get("flagged", False)):
        active.append("low_trust")

    return sorted(set(active))


def _stage_tone(stage, flagged=False):
    stage = str(stage or "observe").lower()
    if stage == "terminate":
        return "critical"
    if stage in {"quarantine", "block_resources", "restrict"}:
        return "high"
    if stage == "throttle":
        return "medium"
    if flagged:
        return "medium"
    return "low"


def _format_pct(value):
    try:
        return f"{float(value) * 100:.1f}%"
    except Exception:
        return "n/a"


def _alert_rows(rows, limit=8):
    if rows is None or rows.empty:
        return []

    candidates = rows[
        _security_event_mask(
            rows
        )
    ].copy()
    if candidates.empty:
        return []

    if "timestamp" in candidates.columns:
        candidates["timestamp"] = pd.to_datetime(
            candidates["timestamp"],
            errors="coerce",
        )

    sort_columns = [
        column
        for column in (
            "timestamp",
            "_log_index",
        )
        if column in candidates.columns
    ]
    if sort_columns:
        candidates = candidates.sort_values(
            sort_columns,
            ascending=True,
        )

    alerts = []
    for _, row in candidates.tail(limit).iloc[::-1].iterrows():
        stage = str(row.get("stage", "observe") or "observe").lower()
        flags = _flag_terms(row)
        flag_text = "; ".join(
            FLAG_EXPLANATIONS.get(flag, flag.replace("_", " "))
            for flag in flags[:5]
        )
        if not flag_text:
            flag_text = "risk evidence was recorded but no specific flag names were present"

        severity = str(row.get("severity", "low") or "low").lower()
        label = str(row.get("label", "normal") or "normal").lower()
        response = row.get("response", "")
        status = str(response or ACTION_EXPLANATIONS.get(stage, "Monitoring."))
        alerts.append({
            "pid": row.get("pid"),
            "name": row.get("name", "unknown"),
            "severity": severity,
            "label": label,
            "stage": stage,
            "tone": _stage_tone(stage, bool(row.get("flagged", False))),
            "trust": _format_pct(row.get("final_trust")),
            "worm_score": _format_pct(_normalize_risk_score(row.get("worm_score"))),
            "flags": ", ".join(flags) if flags else "none",
            "why": flag_text,
            "action": ACTION_EXPLANATIONS.get(stage, "Monitoring and keeping telemetry visible."),
            "status": status,
        })

    return alerts


def _render_alert_feed(alerts):
    if not alerts:
        st.success("No active self-healing alerts in the current dashboard window.")
        return

    for alert in alerts:
        safe_alert = {
            key: html.escape(str(value))
            for key, value in alert.items()
        }
        st.markdown(
            f"""
            <div class="alert-card {safe_alert["tone"]}">
                <div class="alert-top">
                    <div>
                        <div class="alert-title">{safe_alert["stage"].upper()} - {safe_alert["name"]}</div>
                        <div class="alert-meta">pid {safe_alert["pid"]} - {safe_alert["label"]} - {safe_alert["severity"]} - trust {safe_alert["trust"]} - worm {safe_alert["worm_score"]}</div>
                    </div>
                    <div class="alert-stage">{safe_alert["stage"]}</div>
                </div>
                <div class="alert-body"><b>Why:</b> {safe_alert["why"]}</div>
                <div class="alert-body"><b>Self-healing action:</b> {safe_alert["action"]}</div>
                <div class="alert-body"><b>Status:</b> {safe_alert["status"]}</div>
                <div class="alert-flags">{safe_alert["flags"]}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _acceptance_coverage_rows(latest_rows, signal_rows):
    observed = set()

    for row in signal_rows:
        signals = _coerce_dashboard_dict(row.get("signals"))
        correlated = _coerce_dashboard_dict(signals.get("correlated_signals"))
        for name, active in correlated.items():
            if active:
                observed.add(name)

        for signal in (
            "forkbomb_detected",
            "replication_detected",
            "fanout_detected",
            "artifact_abuse_detected",
            "trust_anomaly_pattern",
            "worm_like_behavior",
        ):
            if signals.get(signal):
                observed.add(signal)

    if latest_rows is not None and not latest_rows.empty:
        for column, names in {
            "beacon_detected": {"localhost_beaconing", "network_fanout"},
            "persistence_detected": {"persistence_artifact", "artifact_abuse_detected"},
            "sensitive_access_detected": {"sensitive_file_access", "artifact_abuse_detected"},
        }.items():
            if column in latest_rows.columns and latest_rows[column].astype(bool).any():
                observed.update(names)

        protected_seen = (
            latest_rows.get("stage", pd.Series(dtype=str))
            .astype(str)
            .str.lower()
            .eq("protected")
            .any()
            or latest_rows.get("response", pd.Series(dtype=str))
            .astype(str)
            .str.lower()
            .str.contains("protected", na=False)
            .any()
        )
        if protected_seen:
            observed.add("protected_workload")

    checks = [
        ("1 Process storm", {"forkbomb_detected", "process_storm_burst"}),
        ("2 Thread storm", {"thread_explosion"}),
        ("3 CPU exhaustion", {"cpu_memory_escalation", "resource_pressure"}),
        ("4 Memory spike", {"cpu_memory_escalation", "resource_pressure"}),
        ("5 File replication", {"replication_detected", "file_replication"}),
        ("6 Mass file modification", {"mass_file_modification", "extreme_file_velocity"}),
        ("7 Suspicious rename", {"suspicious_rename"}),
        ("8 Localhost beaconing", {"localhost_beaconing", "network_fanout"}),
        ("9 Persistence artifact", {"persistence_artifact", "artifact_abuse_detected"}),
        ("10 Sensitive access", {"sensitive_file_access", "artifact_abuse_detected"}),
        ("11 Combined worm", {"localhost_beaconing", "persistence_artifact", "sensitive_file_access", "thread_explosion"}),
        ("12 Legit workload protected", {"protected_workload"}),
    ]

    return pd.DataFrame([
        {
            "scenario": label,
            "status": "detected" if requirements & observed else "missing",
            "coverage": 1 if requirements & observed else 0,
            "evidence": ", ".join(sorted(requirements & observed)) if requirements & observed else "none",
        }
        for label, requirements in checks
    ])


def _risk_band(value):
    try:
        value = float(value)
    except Exception:
        return "unknown"
    if value >= 0.85:
        return "critical"
    if value >= 0.65:
        return "high"
    if value >= 0.35:
        return "medium"
    return "low"


def _dashboard_trust_score(latest):
    if latest is None or latest.empty:
        return 1.0

    return float(latest["final_trust"].mean())


def _dashboard_pressure_score(latest):
    if latest is None or latest.empty:
        return 0.0

    return float(latest["trust_anomaly_pressure"].mean())


def _format_age(signature):
    age = signature.get("age_seconds")
    if age is None:
        return "missing"
    if age < 60:
        return f"{int(age)}s ago"
    return f"{int(age // 60)}m ago"


def _metric_card(title, value, note, tone="cyan"):
    st.markdown(
        f"""
        <div class="metric-card {tone}">
            <div class="metric-title">{title}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _info_box(title, body):
    st.markdown(
        f"""
        <div class="info-box">
            <div class="info-title">{title}</div>
            <div class="info-body">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _prepare_learning_rows(kb):
    if kb is None or kb.empty:
        return pd.DataFrame()

    graph = kb.copy()
    if "pattern_id" not in graph.columns:
        graph["pattern_id"] = graph.index.astype(str)

    if "attack_family" not in graph.columns:
        graph["attack_family"] = "unknown"

    for column in (
        "confidence",
        "observations",
        "avg_pattern_strength",
        "avg_trust_anomaly_pressure",
    ):
        if column not in graph.columns:
            graph[column] = 0
        graph[column] = pd.to_numeric(
            graph[column],
            errors="coerce",
        ).fillna(0)

    for column, default in {
        "recommended_stage": "observe",
        "disposition": "unknown",
        "summary": "",
        "last_process_name": "unknown",
    }.items():
        if column not in graph.columns:
            graph[column] = default
        graph[column] = (
            graph[column]
            .astype(str)
            .replace("", default)
        )

    for column in ("confidence", "avg_pattern_strength", "avg_trust_anomaly_pressure"):
        graph[column] = graph[column].apply(_normalize_risk_score)

    graph["attack_family"] = (
        graph["attack_family"]
        .astype(str)
        .replace("", "unknown")
    )
    graph["recommended_stage"] = (
        graph["recommended_stage"]
        .astype(str)
        .str.lower()
        .replace("", "observe")
    )
    graph["readiness_score"] = (
        graph["confidence"] * 0.45
        + graph["avg_pattern_strength"] * 0.35
        + graph["avg_trust_anomaly_pressure"] * 0.20
    )
    graph["confidence_pct"] = (
        graph["confidence"] * 100
    ).round(1)
    graph["strength_pct"] = (
        graph["avg_pattern_strength"] * 100
    ).round(1)
    graph["readiness_pct"] = (
        graph["readiness_score"] * 100
    ).round(1)
    return graph


def _learning_action_summary(kb):
    graph = _prepare_learning_rows(kb)
    if graph.empty:
        return pd.DataFrame()

    summary = (
        graph.groupby("recommended_stage", as_index=False)
        .agg(
            patterns=("pattern_id", "count"),
            avg_confidence=("confidence_pct", "mean"),
            avg_readiness=("readiness_pct", "mean"),
            max_observations=("observations", "max"),
        )
        .sort_values("avg_readiness", ascending=False)
    )
    summary["avg_confidence"] = summary["avg_confidence"].round(1)
    summary["avg_readiness"] = summary["avg_readiness"].round(1)
    return summary


def _card_header(title, note=""):
    st.markdown(
        f"""
        <div class="card-heading">
            <div class="card-title">{title}</div>
            <div class="card-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _compact_table(frame, columns, limit=8):
    selected = [col for col in columns if col in frame.columns]
    if not selected:
        return pd.DataFrame()
    return frame[selected].head(limit)


def _safe_text(value, default=""):
    if value is None:
        value = default
    return html.escape(str(value))


def _compact_number(value):
    try:
        number = float(value)
    except Exception:
        return "0"
    if abs(number) >= 1_000_000:
        return f"{number / 1_000_000:.1f}M"
    if abs(number) >= 10_000:
        return f"{number:,.0f}"
    if abs(number) >= 1000:
        return f"{number:,.0f}"
    if number.is_integer():
        return f"{int(number):,}"
    return f"{number:.1f}"


def _spark_bars(values, tone="violet"):
    if not values:
        values = [0.18, 0.42, 0.74, 0.54]
    bars = []
    for value in values[-5:]:
        try:
            height = max(14, min(54, int(float(value) * 54)))
        except Exception:
            height = 18
        bars.append(
            f'<span class="spark-bar {tone}" style="height:{height}px"></span>'
        )
    return "".join(bars)


def _metric_tile(title, value, note, tone, values):
    return f"""
    <div class="crm-kpi">
        <div class="kpi-icon {tone}"></div>
        <div class="kpi-spacer"></div>
        <div class="kpi-label">{_safe_text(title)}</div>
        <div class="kpi-row">
            <div>
                <div class="kpi-value">{_safe_text(value)}</div>
                <div class="kpi-note">{_safe_text(note)}</div>
            </div>
            <div class="spark-bars">{_spark_bars(values, tone)}</div>
        </div>
    </div>
    """


def _chunked_metric_values(frame, column, chunks=9, default=1.0):
    if frame is None or frame.empty or column not in frame.columns:
        return [default for _ in range(chunks)]
    series = pd.to_numeric(
        frame[column],
        errors="coerce",
    ).dropna()
    if series.empty:
        return [default for _ in range(chunks)]
    values = []
    size = max(1, int(len(series) / chunks))
    for index in range(chunks):
        start = index * size
        stop = len(series) if index == chunks - 1 else (index + 1) * size
        segment = series.iloc[start:stop]
        values.append(float(segment.mean()) if not segment.empty else default)
    return values


def _analytics_chart(values):
    labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep"]
    bars = []
    for label, value in zip(labels, values):
        trust = max(0.0, min(1.0, float(value)))
        height = int(28 + trust * 150)
        ghost = max(22, height - 38)
        dot = max(18, min(168, int(trust * 168)))
        bars.append(
            f"""
            <div class="chart-col">
                <div class="chart-track">
                    <span class="chart-ghost" style="height:{ghost}px"></span>
                    <span class="chart-main" style="height:{height}px"></span>
                    <span class="chart-dot" style="bottom:{dot}px"></span>
                </div>
                <div class="chart-label">{label}</div>
            </div>
            """
        )
    return "".join(bars)


def _risk_donut(total, critical, active, stable):
    total = max(1, int(total))
    critical_pct = max(0, min(100, critical / total * 100))
    active_pct = max(0, min(100, active / total * 100))
    critical_end = critical_pct
    active_end = min(100, critical_pct + active_pct)
    return f"""
    <div class="donut-card">
        <div class="card-menu">...</div>
        <div class="side-title">Risk by Source</div>
        <div class="donut-wrap">
            <div class="donut" style="background: conic-gradient(#6a56d9 0 {critical_end:.1f}%, #f59adf {critical_end:.1f}% {active_end:.1f}%, #ffd069 {active_end:.1f}% 100%);">
                <div class="donut-center">
                    <span>Total</span>
                    <b>{_compact_number(total)}</b>
                </div>
            </div>
        </div>
        <div class="donut-legend">
            <div><span class="legend pink"></span><b>Critical</b><small>{_compact_number(critical)}</small></div>
            <div><span class="legend purple"></span><b>Active</b><small>{_compact_number(active)}</small></div>
            <div><span class="legend gold"></span><b>Stable</b><small>{_compact_number(stable)}</small></div>
        </div>
    </div>
    """


def _alerts_panel(alerts):
    if not alerts:
        return """
        <div class="empty-state">
            <b>No active self-healing alerts</b>
            <span>The live window is stable.</span>
        </div>
        """
    rows = []
    for alert in alerts[:3]:
        rows.append(
            f"""
            <div class="alert-line {alert.get("tone", "low")}">
                <div>
                    <b>{_safe_text(str(alert.get("stage", "observe")).upper())}</b>
                    <span>{_safe_text(alert.get("name", "unknown"))} / pid {_safe_text(alert.get("pid", ""))}</span>
                </div>
                <small>{_safe_text(alert.get("status", "monitoring"))}</small>
            </div>
            """
        )
    return "".join(rows)


def _process_table(frame):
    if frame is None or frame.empty:
        return """
        <div class="crm-empty-row">
            <span>Waiting for fresh process telemetry</span>
        </div>
        """
    rows = []
    table = frame.sort_values(
        ["flagged", "trust_anomaly_pressure", "worm_score"],
        ascending=[False, False, False],
    ).head(5)
    for _, row in table.iterrows():
        trust = _normalize_trust(row.get("final_trust", 1.0))
        tone = _risk_band(_normalize_risk_score(row.get("worm_score", 0.0)))
        rows.append(
            f"""
            <div class="deal-row">
                <div class="proc-id"><span></span><div><b>{_safe_text(row.get("name", "unknown"))}</b><small>pid {_safe_text(row.get("pid", ""))}</small></div></div>
                <div>{_safe_text(row.get("label", "normal"))}</div>
                <div>{_safe_text(row.get("stage", "observe"))}</div>
                <div>{trust * 100:.1f}%</div>
                <div><span class="risk-pill {tone}">{_safe_text(row.get("severity", "low"))}</span></div>
            </div>
            """
        )
    return "".join(rows)


def _top_signal_rows(flags, historical_rows):
    source = flags if flags is not None and not flags.empty else historical_rows
    if source is None or source.empty:
        return '<div class="top-deal-row"><b>No signals</b><span>Live system is quiet</span></div>'
    rows = []
    for _, row in source.head(4).iterrows():
        score = _normalize_risk_score(row.get("worm_score", 0.0))
        rows.append(
            f"""
            <div class="top-deal-row">
                <div><b>{_safe_text(row.get("name", "unknown"))}</b><span>{_safe_text(row.get("stage", "observe"))}</span></div>
                <strong>{score * 100:.0f}%</strong>
            </div>
            """
        )
    return "".join(rows)


def _learning_rows(kb):
    if kb is None or kb.empty:
        return '<div class="top-deal-row"><b>No learned patterns</b><span>Knowledge base is empty</span></div>'
    graph = _prepare_learning_rows(kb).sort_values(
        ["readiness_score", "observations"],
        ascending=[False, False],
    ).head(4)
    rows = []
    for _, row in graph.iterrows():
        rows.append(
            f"""
            <div class="top-deal-row">
                <div><b>{_safe_text(row.get("attack_family", "unknown"))}</b><span>{_safe_text(row.get("recommended_stage", "observe"))}</span></div>
                <strong>{float(row.get("readiness_pct", 0)):.0f}%</strong>
            </div>
            """
        )
    return "".join(rows)


def run_dashboard():
    st.set_page_config(
        page_title="Self-Healing Defense Dashboard",
        page_icon=".",
        layout="wide",
    )
    st_autorefresh(
        interval=DASHBOARD_REFRESH_MS,
        key="refresh",
    )

    system_signature = _file_signature(SYSTEM_LOG)
    healing_signature = _file_signature(HEALING_LOG)
    kb_signature = _file_signature(LEARNING_KB_LOG)

    process_rows = _normalize_process_rows(
        _read_json_lines(
            str(SYSTEM_LOG),
            system_signature,
        )
    )
    healing_rows = _read_json_lines(
        str(HEALING_LOG),
        healing_signature,
    )
    kb = load_learning_kb(kb_signature)

    latest_process_rows = _latest_by_pid(
        process_rows,
    )
    healing_fallback_rows = _healing_rows_as_process_rows(
        healing_rows,
        seconds=60 * 60 * 24 * 365,
        trust_source_mtime=True,
    )
    latest = _combine_dashboard_rows(
        latest_process_rows,
        healing_fallback_rows,
    )
    latest = _latest_by_pid(
        latest,
    )
    security_rows = _tail_security_rows(
        process_rows,
        limit=DASHBOARD_TAIL_SECURITY_ROWS,
    )
    alert_source_rows = _combine_dashboard_rows(
        security_rows,
        healing_fallback_rows,
    )
    alerts = _alert_rows(
        alert_source_rows,
        limit=12,
    )
    healing_actions = pd.DataFrame()
    if healing_rows is not None and not healing_rows.empty:
        healing_tail = healing_rows.tail(100).copy()
        if "action_taken" not in healing_tail.columns:
            healing_tail["action_taken"] = False
        if "stage" not in healing_tail.columns:
            healing_tail["stage"] = "observe"
        healing_actions = healing_tail[
            healing_tail["action_taken"].astype(bool)
            | healing_tail["stage"].astype(str).str.lower().isin(ACTIVE_RESPONSE_STAGES)
        ].copy()

    if process_rows.empty and healing_rows.empty and kb.empty:
        st.warning(
            "No telemetry found. Start main.py, or set SELF_HEALING_SYSTEM_LOG and SELF_HEALING_HEALING_LOG to the active log files."
        )
        st.caption(f"System log checked: {SYSTEM_LOG}")
        st.caption(f"Healing log checked: {HEALING_LOG}")
        return

    kpi_rows = latest
    avg_trust = _dashboard_trust_score(kpi_rows)
    raw_avg_pressure = _dashboard_pressure_score(kpi_rows)
    flagged_count = int(
        kpi_rows.get(
            "flagged",
            pd.Series(False, index=kpi_rows.index),
        ).astype(bool).sum()
    ) if not kpi_rows.empty else 0
    critical_count = int(
        kpi_rows.get(
            "severity",
            pd.Series("", index=kpi_rows.index),
        )
        .astype(str)
        .str.lower()
        .eq("critical")
        .sum()
    ) if not kpi_rows.empty else 0
    action_count = int(
        kpi_rows.get(
            "stage",
            pd.Series("", index=kpi_rows.index),
        )
        .astype(str)
        .str.lower()
        .isin(ACTIVE_RESPONSE_STAGES)
        .sum()
    ) if not kpi_rows.empty else 0
    learned_patterns = len(kb)
    terminate_ready = 0
    if not kb.empty and "recommended_stage" in kb.columns:
        terminate_ready = int(
            kb["recommended_stage"]
            .astype(str)
            .str.lower()
            .eq("terminate")
            .sum()
        )
    anomaly_peak = (
        float(
            kpi_rows.get(
                "worm_pattern_anomaly",
                pd.Series(0.0, index=kpi_rows.index),
            ).max()
        )
        if not kpi_rows.empty
        else 0.0
    )

    st.markdown(
        """
        <style>
        .stApp {
            background: #f5f7fb;
            color: #172033;
        }
        .block-container {
            max-width: 1360px;
            padding: 22px 22px 34px 22px;
        }
        header[data-testid="stHeader"] {
            background: transparent;
        }
        div[data-testid="stMetric"] {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 14px 16px;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
        }
        div[data-testid="stMetricLabel"] {
            color: #64748b;
            font-weight: 700;
        }
        div[data-testid="stMetricValue"] {
            color: #0f172a;
        }
        .status-strip {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
            margin: 10px 0 20px 0;
        }
        .status-pill {
            background: #fff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 10px 12px;
            font-size: 12px;
            color: #475569;
            overflow-wrap: anywhere;
        }
        .status-pill b {
            display: block;
            color: #0f172a;
            margin-bottom: 3px;
        }
        .danger-note {
            border-left: 4px solid #dc2626;
            background: #fff1f2;
            color: #7f1d1d;
            padding: 12px 14px;
            border-radius: 8px;
            margin: 10px 0 18px 0;
        }
        @media (max-width: 900px) {
            .status-strip {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("Self-Healing Defense")
    st.caption("Live telemetry from the newest log rows. Focused on trust, alerts, and response actions.")
    st.markdown(
        f"""
        <div class="status-strip">
            <div class="status-pill"><b>System log</b>{_safe_text(str(SYSTEM_LOG))}<br>{_format_age(system_signature)}</div>
            <div class="status-pill"><b>Healing log</b>{_safe_text(str(HEALING_LOG))}<br>{_format_age(healing_signature)}</div>
            <div class="status-pill"><b>Learning KB</b>{_safe_text(str(LEARNING_KB_LOG))}<br>{_format_age(kb_signature)}</div>
            <div class="status-pill"><b>Refresh</b>{DASHBOARD_REFRESH_MS} ms</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if system_signature.get("age_seconds") is None:
        st.error("System telemetry log is missing.")
    elif system_signature.get("age_seconds", 0) > 300:
        st.markdown(
            f"""
            <div class="danger-note">
                System telemetry has not changed for {_format_age(system_signature)}.
                If main.py is running, the dashboard is probably reading a different log path.
            </div>
            """,
            unsafe_allow_html=True,
        )

    row_note = f"{len(process_rows)} process rows, {len(healing_rows)} healing rows"
    alert_count = len(alerts)
    healing_action_count = len(healing_actions)
    trust_delta = f"pressure {raw_avg_pressure:.3f}"
    active_delta = f"{critical_count} critical, {action_count} response stages"

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Telemetry Rows", _compact_number(len(process_rows)), row_note)
    k2.metric("Tracked Processes", _compact_number(len(latest)), "latest row per PID")
    k3.metric("Trust Score", f"{avg_trust * 100:.1f}%", trust_delta)
    k4.metric("Alerts", _compact_number(alert_count), active_delta)
    k5.metric("Healing Actions", _compact_number(healing_action_count), "latest 100 healing rows")

    chart_rows = latest_process_rows.copy()
    if not chart_rows.empty:
        chart_rows = chart_rows.sort_values("_log_index" if "_log_index" in chart_rows.columns else "pid").tail(80)
        chart_data = pd.DataFrame({
            "trust": chart_rows["final_trust"].astype(float) * 100.0,
            "risk": chart_rows["worm_score"].apply(_normalize_risk_score) * 100.0,
        })
        st.subheader("Trust And Risk Trend")
        st.line_chart(chart_data, height=220)

    st.subheader("Active Alerts")
    alert_table = pd.DataFrame(alerts)
    if alert_table.empty:
        st.success("No active alerts in the newest telemetry rows.")
    else:
        display_columns = [
            column
            for column in (
                "pid",
                "name",
                "stage",
                "severity",
                "trust",
                "worm_score",
                "why",
                "action",
                "status",
            )
            if column in alert_table.columns
        ]
        st.dataframe(
            alert_table[display_columns],
            use_container_width=True,
            hide_index=True,
            height=330,
        )

    left, right = st.columns([1.35, 1.0])
    with left:
        st.subheader("Processes Being Watched")
        process_table = latest_process_rows.copy()
        if process_table.empty:
            st.info("No process telemetry rows found.")
        else:
            for column in ("final_trust", "worm_score", "cpu", "memory"):
                if column in process_table.columns:
                    process_table[column] = pd.to_numeric(
                        process_table[column],
                        errors="coerce",
                    ).fillna(0)
            if "final_trust" in process_table.columns:
                process_table["trust_pct"] = (process_table["final_trust"] * 100).round(1)
            if "worm_score" in process_table.columns:
                process_table["risk_pct"] = process_table["worm_score"].apply(
                    lambda value: round(_normalize_risk_score(value) * 100, 1)
                )
            process_columns = [
                column
                for column in (
                    "pid",
                    "name",
                    "label",
                    "severity",
                    "stage",
                    "response",
                    "trust_pct",
                    "risk_pct",
                    "cpu",
                    "memory",
                    "threads",
                    "file_events",
                )
                if column in process_table.columns
            ]
            st.dataframe(
                process_table.sort_values(
                    "_log_index" if "_log_index" in process_table.columns else "pid",
                    ascending=False,
                )[process_columns].head(80),
                use_container_width=True,
                hide_index=True,
                height=430,
            )

    with right:
        st.subheader("Healing Actions")
        if healing_actions.empty:
            st.info("No healing actions in the latest healing rows.")
        else:
            healing_columns = [
                column
                for column in (
                    "timestamp",
                    "pid",
                    "stage",
                    "status",
                    "action_taken",
                )
                if column in healing_actions.columns
            ]
            st.dataframe(
                healing_actions.sort_values(
                    "_log_index" if "_log_index" in healing_actions.columns else "timestamp",
                    ascending=False,
                )[healing_columns].head(50),
                use_container_width=True,
                hide_index=True,
                height=250,
            )

        st.subheader("Learned Patterns")
        learning = _prepare_learning_rows(kb)
        if learning.empty:
            st.info("No learned behavior patterns yet.")
        else:
            learning_columns = [
                column
                for column in (
                    "attack_family",
                    "recommended_stage",
                    "confidence_pct",
                    "readiness_pct",
                    "observations",
                    "last_process_name",
                )
                if column in learning.columns
            ]
            st.dataframe(
                learning[learning_columns].head(12),
                use_container_width=True,
                hide_index=True,
                height=250,
            )


if __name__ == "__main__":
    run_dashboard()
