import ast
import html
import json
import os
import time
from pathlib import Path

try:
    import pandas as pd
    import streamlit as st
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
    path = Path(
        configured
        if configured
        else default
    )
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


DASHBOARD_MAX_ROWS = 1000
DASHBOARD_REFRESH_MS = _env_int("SELF_HEALING_DASHBOARD_REFRESH_MS", 500, 100)
DASHBOARD_CACHE_TTL_SECONDS = _env_float(
    "SELF_HEALING_DASHBOARD_CACHE_TTL_SECONDS",
    0.25,
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
            "size": stat.st_size,
            "age_seconds": max(0, time.time() - stat.st_mtime),
        }
    except Exception:
        return {
            "path": str(path),
            "mtime": 0,
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
    frame["flagged"] = (
        (
            frame["label"].astype(str).str.lower().isin({"worm", "forkbomb"})
            | frame["severity"].astype(str).str.lower().isin({"high", "critical"})
            | frame["confirmed_behavior"].astype(bool)
            | frame["strong_worm_score"].astype(bool)
            | (frame["final_trust"] < 0.75)
        )
        & (
            ~frame["category_suppressed"].astype(bool)
            | frame["confirmed_behavior"].astype(bool)
            | frame["severity"].astype(str).str.lower().eq("critical")
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


def _recent_rows(frame, seconds=45):
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

    if "_source_mtime" in frame.columns:
        source_times = pd.to_datetime(
            frame["_source_mtime"],
            errors="coerce"
        )
        recent_mask = recent_mask | (
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


def _live_latest_rows(frame, seconds=45):
    recent = _recent_rows(
        frame,
        seconds=seconds,
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
    severe = (
        frame.get("severity", pd.Series("", index=index))
        .astype(str)
        .str.lower()
        .isin({"high", "critical"})
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

    return flagged | severe | response_stage | response_text


def _security_memory_rows(frame, seconds=60):
    recent = _recent_rows(
        frame,
        seconds=seconds,
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


def _dashboard_state_rows(frame, live_seconds=12, event_seconds=60):
    live = _live_latest_rows(
        frame,
        seconds=live_seconds,
    )
    memory = _security_memory_rows(
        frame,
        seconds=event_seconds,
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


def _recent_security_rows(frame, seconds=180, limit=100):
    recent = _recent_rows(
        frame,
        seconds=seconds,
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


def _healing_rows_as_process_rows(healing_rows, seconds=60):
    if healing_rows is None or healing_rows.empty:
        return pd.DataFrame()

    recent = _recent_rows(
        healing_rows,
        seconds=seconds,
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
                        <div class="alert-title">{safe_alert["stage"].upper()} · {safe_alert["name"]}</div>
                        <div class="alert-meta">pid {safe_alert["pid"]} · {safe_alert["label"]} · {safe_alert["severity"]} · trust {safe_alert["trust"]} · worm {safe_alert["worm_score"]}</div>
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


def run_dashboard():
    st.set_page_config(
        page_title="Cyber Defense Command",
        page_icon="shield",
        layout="wide",
    )
    st_autorefresh(
        interval=DASHBOARD_REFRESH_MS,
        key="refresh",
    )

    st.markdown(
        """
        <style>
        .stApp {
            color: #f8fafc;
            background: #0f141b;
        }
        .block-container {
            max-width: 1360px;
            padding-top: 26px;
            padding-bottom: 32px;
        }
        section[data-testid="stSidebar"] { display: none; }
        header[data-testid="stHeader"] {
            background: transparent;
        }
        h1, h2, h3 {
            color: #f8fafc;
            letter-spacing: 0;
        }
        .rail {
            min-height: 820px;
            background: #111827;
            border: 1px solid rgba(148,163,184,0.14);
            border-radius: 8px;
            padding: 16px 8px;
            text-align: center;
        }
        .logo {
            width: 42px;
            height: 42px;
            border-radius: 8px;
            background: #14b8a6;
            color: #06111a;
            font-weight: 900;
            font-size: 28px;
            line-height: 42px;
            margin: 0 auto 38px auto;
        }
        .rail-item {
            width: 46px;
            height: 38px;
            border-radius: 8px;
            margin: 0 auto 10px auto;
            border: 1px solid rgba(148,163,184,0.14);
            color: #94a3b8;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            font-weight: 800;
        }
        .rail-item.active {
            background: #123238;
            color: #5eead4;
            border-color: rgba(45,212,191,0.40);
        }
        .content-pad {
            padding: 2px 4px 18px 4px;
        }
        .top-title {
            font-size: 26px;
            font-weight: 700;
            color: #f8fafc;
            margin: 0 0 14px 0;
        }
        .tabs {
            display: flex;
            gap: 30px;
            border-bottom: 1px solid rgba(148,163,184,0.18);
            margin-bottom: 24px;
        }
        .tab {
            padding: 0 0 11px 0;
            color: #94a3b8;
            font-size: 14px;
            font-weight: 650;
        }
        .tab.active {
            color: #f8fafc;
            border-bottom: 2px solid #38bdf8;
        }
        div[data-testid="stVerticalBlock"] > div:has(.card-heading) {
            background: #151922;
            border-radius: 8px;
            padding: 20px 22px;
            border: 1px solid rgba(148,163,184,0.14);
        }
        .card-heading {
            margin-bottom: 8px;
        }
        .card-title {
            font-size: 20px;
            font-weight: 720;
            color: #f8fafc;
        }
        .card-note {
            color: #94a3b8;
            font-size: 12px;
            margin-top: 4px;
        }
        [data-testid="stMetricValue"] { color: #5eead4; }
        .metric-card {
            border-radius: 8px;
            padding: 18px 20px;
            background: #151922;
            min-height: 112px;
            border: 1px solid rgba(148,163,184,0.14);
        }
        .metric-card.cyan { box-shadow: inset 0 3px 0 #38bdf8; }
        .metric-card.red { box-shadow: inset 0 3px 0 #f43f5e; }
        .metric-card.amber { box-shadow: inset 0 3px 0 #f59e0b; }
        .metric-card.green { box-shadow: inset 0 3px 0 #34d399; }
        .metric-title {
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 700;
        }
        .metric-value {
            color: #f8fafc;
            font-size: 32px;
            font-weight: 760;
            line-height: 1.2;
            margin-top: 8px;
        }
        .metric-note {
            color: #94a3b8;
            font-size: 12px;
            margin-top: 6px;
        }
        .health-row {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            color: #94a3b8;
            font-size: 12px;
            margin-top: 8px;
        }
        .health-pill {
            border-radius: 999px;
            padding: 6px 10px;
            background: #151922;
            border: 1px solid rgba(148,163,184,0.16);
        }
        .info-box {
            border-radius: 8px;
            padding: 10px 12px;
            margin: 8px 0 14px 0;
            background: #111827;
            border: 1px solid rgba(56,189,248,0.18);
        }
        .info-title {
            color: #bae6fd;
            font-size: 12px;
            font-weight: 720;
            margin-bottom: 3px;
        }
        .info-body {
            color: #94a3b8;
            font-size: 12px;
            line-height: 1.45;
        }
        .alert-card {
            border-radius: 8px;
            padding: 14px 16px;
            margin: 10px 0;
            background: #111827;
            border: 1px solid rgba(148,163,184,0.16);
        }
        .alert-card.critical {
            border-color: rgba(244,63,94,0.54);
            box-shadow: inset 4px 0 0 #f43f5e;
        }
        .alert-card.high {
            border-color: rgba(251,146,60,0.52);
            box-shadow: inset 4px 0 0 #fb923c;
        }
        .alert-card.medium {
            border-color: rgba(245,158,11,0.52);
            box-shadow: inset 4px 0 0 #f59e0b;
        }
        .alert-card.low {
            border-color: rgba(52,211,153,0.36);
            box-shadow: inset 4px 0 0 #34d399;
        }
        .alert-top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 8px;
        }
        .alert-title {
            color: #f8fafc;
            font-weight: 760;
            font-size: 15px;
        }
        .alert-meta {
            color: #94a3b8;
            font-size: 12px;
            margin-top: 3px;
        }
        .alert-stage {
            border-radius: 999px;
            color: #e2e8f0;
            background: #1f2937;
            border: 1px solid rgba(148,163,184,0.18);
            padding: 5px 9px;
            font-size: 11px;
            font-weight: 760;
            text-transform: uppercase;
            white-space: nowrap;
        }
        .alert-body {
            color: #cbd5e1;
            font-size: 12px;
            line-height: 1.48;
            margin-top: 5px;
        }
        .alert-body b {
            color: #e2e8f0;
        }
        .alert-flags {
            color: #bae6fd;
            font-size: 11px;
            margin-top: 9px;
            overflow-wrap: anywhere;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid rgba(148,163,184,0.14);
            border-radius: 8px;
            overflow: hidden;
        }
        .stDataFrame, .stTable {
            background: #151922;
        }
        button[kind="secondary"] {
            background: #151922;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    system_signature = _file_signature(SYSTEM_LOG)
    healing_signature = _file_signature(HEALING_LOG)
    kb_signature = _file_signature(LEARNING_KB_LOG)

    process_rows = _read_json_lines(str(SYSTEM_LOG), system_signature)
    healing_rows = _read_json_lines(str(HEALING_LOG), healing_signature)
    kb = load_learning_kb(kb_signature)

    process_rows = _normalize_process_rows(process_rows)
    live_window_seconds = int(
        os.getenv(
            "SELF_HEALING_DASHBOARD_LIVE_WINDOW_SECONDS",
            "12"
        )
    )
    event_memory_seconds = int(
        os.getenv(
            "SELF_HEALING_DASHBOARD_EVENT_MEMORY_SECONDS",
            str(DASHBOARD_EVENT_MEMORY_SECONDS)
        )
    )
    recent_process_rows = _recent_rows(
        process_rows,
        seconds=max(
            live_window_seconds,
            event_memory_seconds,
        )
    )
    visible_process_rows = (
        recent_process_rows
        if not recent_process_rows.empty
        else process_rows.tail(
            DASHBOARD_TAIL_SECURITY_ROWS
        )
    )
    latest = _dashboard_state_rows(
        process_rows,
        live_seconds=live_window_seconds,
        event_seconds=event_memory_seconds,
    )
    latest = _overlay_healing_status(latest, healing_rows, latest)
    healing_fallback_rows = _healing_rows_as_process_rows(
        healing_rows,
        seconds=event_memory_seconds,
    )
    telemetry_source = "process log"
    if not healing_fallback_rows.empty:
        if latest.empty:
            latest = healing_fallback_rows
            telemetry_source = "healing log"
        else:
            latest = _dashboard_state_rows(
                pd.concat(
                    [
                        latest,
                        healing_fallback_rows,
                    ],
                    ignore_index=True,
                ),
                live_seconds=live_window_seconds,
                event_seconds=event_memory_seconds,
            )
            telemetry_source = "process + healing log"
    if (
        latest.empty
        and not visible_process_rows.empty
    ):
        latest = _latest_by_pid(
            visible_process_rows
        )
        telemetry_source = (
            telemetry_source
            + " tail fallback"
        )
    security_rows = _dashboard_security_rows(
        process_rows,
        seconds=event_memory_seconds,
        tail_limit=DASHBOARD_TAIL_SECURITY_ROWS,
    )
    if not security_rows.empty:
        telemetry_source = (
            telemetry_source
            + " + alert tail"
        )
    alert_source_rows = _combine_dashboard_rows(
        latest,
        security_rows,
        healing_fallback_rows,
    )
    flags = _active_flag_rows(alert_source_rows)
    alerts = _alert_rows(
        alert_source_rows,
        limit=8,
    )

    if process_rows.empty and healing_rows.empty and kb.empty:
        st.warning("No telemetry yet. Start main.py and the dashboard will populate as the agent observes processes.")
        return

    kpi_rows = _combine_dashboard_rows(
        latest,
        security_rows,
        healing_fallback_rows,
    )
    raw_avg_trust = float(kpi_rows["final_trust"].mean()) if not kpi_rows.empty else 1.0
    raw_avg_pressure = float(kpi_rows["trust_anomaly_pressure"].mean()) if not kpi_rows.empty else 0.0
    avg_trust = _dashboard_trust_score(kpi_rows)
    flagged_count = int(latest["flagged"].sum()) if not latest.empty else 0
    if flagged_count == 0 and not security_rows.empty:
        flagged_count = int(
            security_rows.get(
                "flagged",
                pd.Series(False, index=security_rows.index),
            )
            .astype(bool)
            .sum()
        )
    critical_count = int(latest["severity"].astype(str).str.lower().eq("critical").sum()) if not latest.empty else 0
    if critical_count == 0 and not security_rows.empty:
        critical_count = int(
            security_rows.get(
                "severity",
                pd.Series("", index=security_rows.index),
            )
            .astype(str)
            .str.lower()
            .eq("critical")
            .sum()
        )
    learned_patterns = len(kb)
    terminate_ready = 0
    if not kb.empty and "recommended_stage" in kb.columns:
        terminate_ready = int(kb["recommended_stage"].astype(str).str.lower().eq("terminate").sum())

    anomaly_peak = (
        float(visible_process_rows["worm_pattern_anomaly"].max())
        if not visible_process_rows.empty
        else 0.0
    )
    action_count = 0
    if not latest.empty:
        action_count = int(
            latest["stage"]
            .astype(str)
            .str.lower()
            .isin(ACTIVE_RESPONSE_STAGES)
            .sum()
        )
    if action_count == 0 and not security_rows.empty:
        action_count = int(
            security_rows.get(
                "stage",
                pd.Series("", index=security_rows.index),
            )
            .astype(str)
            .str.lower()
            .isin(ACTIVE_RESPONSE_STAGES)
            .sum()
        )

    rail, body = st.columns([0.075, 0.925], gap="small")

    with rail:
        st.markdown(
            """
            <div class="rail">
                <div class="logo">G</div>
                <div class="rail-item active">TS</div>
                <div class="rail-item">AN</div>
                <div class="rail-item">ML</div>
                <div class="rail-item">PR</div>
                <div class="rail-item">HL</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with body:
        st.markdown(
            f"""
            <div class="content-pad">
                <div class="top-title">Threats</div>
                <div class="tabs">
                    <div class="tab">Overview</div>
                    <div class="tab active">Insights</div>
                    <div class="tab">Process Details</div>
                    <div class="tab">Learnt Patterns</div>
                </div>
                <div class="health-row">
                    <span class="health-pill">system log {_format_age(system_signature)}</span>
                    <span class="health-pill">source {telemetry_source}</span>
                    <span class="health-pill">{len(process_rows)} process rows</span>
                    <span class="health-pill">{len(healing_rows)} healing rows</span>
                    <span class="health-pill">knowledge base {_format_age(kb_signature)}</span>
                    <span class="health-pill">{terminate_ready} terminate-ready patterns</span>
                    <span class="health-pill">{action_count} active responses</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        _info_box(
            "Dashboard guide",
            "Trust Score shows the current average final trust from monitored rows. Active Flags are high-confidence alerts and are tracked separately.",
        )

        kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
        with kpi1:
            _metric_card(
                "Trust Score",
                f"{avg_trust * 100:.1f}%",
                f"raw {raw_avg_trust * 100:.1f}% | pressure {raw_avg_pressure:.3f}",
                "cyan",
            )
        with kpi2:
            _metric_card(
                "Active Flags",
                flagged_count,
                f"{critical_count} critical",
                "red" if flagged_count else "green",
            )
        with kpi3:
            _metric_card(
                "Patterns Learnt",
                learned_patterns,
                f"{terminate_ready} terminate-ready",
                "green",
            )
        with kpi4:
            _metric_card(
                "System Anomaly",
                f"{anomaly_peak:.3f}",
                _risk_band(anomaly_peak),
                "amber",
            )
        with kpi5:
            _metric_card(
                "Process Details",
                len(latest),
                "latest process rows",
                "cyan",
            )
        _info_box(
            "Metric guide",
            "Trust Score follows final_trust directly, so suspicious medium-risk drift still moves the score. Active Flags only count confirmed or high-severity evidence.",
        )

        _card_header(
            "Live Self-Healing Alerts",
            "latest flagged behavior, explanation, and action being taken",
        )
        _info_box(
            "Alert guide",
            "Alerts remain visible for the dashboard memory window so you can see what was flagged, why it was flagged, and which self-healing response is active.",
        )
        _render_alert_feed(
            alerts
        )

        details_left, details_right = st.columns([0.52, 0.48])
        with details_left:
            _card_header("Process Details", "highest risk processes first")
            _info_box(
                "How to read",
                "Rows are sorted by active flag, trust pressure, and worm score. A suspicious label alone is not an active alert.",
            )
            if latest.empty:
                st.info("No live process rows.")
            else:
                process_table = latest.sort_values(
                    ["flagged", "trust_anomaly_pressure", "worm_score"],
                    ascending=[False, False, False],
                )
                st.dataframe(
                    _compact_table(
                        process_table,
                        [
                            "pid",
                            "name",
                            "label",
                            "severity",
                            "stage",
                            "final_trust",
                            "trust_anomaly_pressure",
                            "worm_score",
                        ],
                        limit=12,
                    ),
                    width="stretch",
                    hide_index=True,
                )

        with details_right:
            _card_header("Flags", "active behavioral and trust flags")
            _info_box(
                "How to read",
                "This table only lists strong evidence: confirmed worm behavior, high severity, strong worm score, or trust below the response threshold.",
            )
            if flags.empty:
                st.success("No active flags.")
            else:
                st.dataframe(
                    _compact_table(
                        flags.sort_values(
                            ["trust_anomaly_pressure", "worm_score"],
                            ascending=[False, False],
                        ),
                        [
                            "pid",
                            "name",
                            "severity",
                            "stage",
                            "final_trust",
                            "flags",
                            "why",
                            "self_healing_action",
                        ],
                        limit=12,
                    ),
                    width="stretch",
                    hide_index=True,
                )

        _card_header("Learnt Patterns", "stored behavior patterns and recommended response")
        if kb.empty:
            st.info("Knowledge base is empty.")
        else:
            kb_sorted = _prepare_learning_rows(kb).sort_values(
                ["readiness_score", "observations"],
                ascending=[False, False],
            )
            st.dataframe(
                _compact_table(
                    kb_sorted,
                    [
                        "attack_family",
                        "recommended_stage",
                        "readiness_pct",
                        "confidence_pct",
                        "strength_pct",
                        "observations",
                        "last_process_name",
                        "summary",
                    ],
                    limit=16,
                ),
                width="stretch",
                hide_index=True,
            )


if __name__ == "__main__":
    run_dashboard()
