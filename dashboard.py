import ast
import json
import os
import time
from pathlib import Path

try:
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
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
    px = _Dummy()
    go = _Dummy()

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


DASHBOARD_MAX_ROWS = 1000
DASHBOARD_REFRESH_MS = _env_int("SELF_HEALING_DASHBOARD_REFRESH_MS", 500, 100)
DASHBOARD_CACHE_TTL_SECONDS = _env_float(
    "SELF_HEALING_DASHBOARD_CACHE_TTL_SECONDS",
    0.25,
    0.0,
)
DASHBOARD_EVENT_MEMORY_SECONDS = _env_int(
    "SELF_HEALING_DASHBOARD_EVENT_MEMORY_SECONDS",
    60,
    1,
)
SYSTEM_LOG = Path(os.getenv("SELF_HEALING_SYSTEM_LOG", "logs/system_log.json"))
HEALING_LOG = Path(os.getenv("SELF_HEALING_HEALING_LOG", "logs/healing_log.json"))
LEARNING_KB_LOG = Path(os.getenv("SELF_HEALING_KB_PATH", "logs/learning_kb.json"))


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

    if "timestamp" in frame.columns:
        timestamps = pd.to_datetime(
            frame["timestamp"],
            errors="coerce"
        )
        recent = frame[
            (timestamps >= cutoff)
            &
            (timestamps <= future_grace)
        ]
        if not recent.empty:
            return recent

    if "_source_mtime" in frame.columns:
        source_times = pd.to_datetime(
            frame["_source_mtime"],
            errors="coerce"
        )
        recent = frame[
            (source_times >= cutoff)
            &
            (source_times <= future_grace)
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
        .isin(["throttle", "quarantine", "terminate", "block_resources"])
    )
    response_text = (
        frame.get("response", pd.Series("", index=index))
        .astype(str)
        .str.lower()
        .str.contains("terminated|isolated|throttled|quarantined", na=False)
    )

    return flagged | severe | response_stage | response_text


def _security_memory_rows(frame, seconds=60):
    recent = _recent_rows(
        frame,
        seconds=seconds,
    )
    latest = _latest_by_pid(
        recent
    )
    if latest.empty:
        return latest
    return latest[
        _security_event_mask(
            latest
        )
    ]


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
    return _latest_by_pid(
        combined
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


def _active_flag_rows(rows):
    if rows is None or rows.empty:
        return pd.DataFrame()

    output = []
    for _, item in rows.iterrows():
        signals = _coerce_dashboard_dict(item.get("signals"))
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
            "trust_anomaly_pattern",
            "worm_like_behavior",
            "catastrophic_behavior",
        ):
            if signals.get(key):
                active.append(key)

        if not active and not bool(item.get("flagged", False)):
            continue

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
        })

    return pd.DataFrame(output)


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


def _has_active_dashboard_risk(frame):
    if frame is None or frame.empty:
        return False

    flagged = (
        frame.get("flagged", pd.Series(dtype=bool))
        .astype(bool)
        .any()
    )
    critical = (
        frame.get("severity", pd.Series(dtype=str))
        .astype(str)
        .str.lower()
        .eq("critical")
        .any()
    )
    response_active = (
        frame.get("stage", pd.Series(dtype=str))
        .astype(str)
        .str.lower()
        .isin(["throttle", "quarantine", "terminate", "block_resources"])
        .any()
    )

    return bool(
        flagged
        or critical
        or response_active
    )


def _dashboard_trust_score(latest):
    if latest is None or latest.empty:
        return 1.0

    if not _has_active_dashboard_risk(latest):
        return 1.0

    return float(latest["final_trust"].mean())


def _dashboard_pressure_score(latest):
    if latest is None or latest.empty:
        return 0.0

    if not _has_active_dashboard_risk(latest):
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


def _plot_theme(fig, height=300, showlegend=True):
    fig.update_layout(
        height=height,
        paper_bgcolor="#151922",
        plot_bgcolor="#151922",
        font={
            "color": "#d6dde7",
            "family": "Inter, Segoe UI, Arial, sans-serif",
        },
        margin=dict(l=18, r=18, t=24, b=18),
        legend={
            "orientation": "h",
            "y": 1.08,
            "x": 0.58,
            "font": {"color": "#9aa7b7"},
        },
        showlegend=showlegend,
    )
    fig.update_xaxes(
        gridcolor="rgba(148,163,184,0.12)",
        zerolinecolor="rgba(148,163,184,0.14)",
        linecolor="rgba(148,163,184,0.18)",
        tickfont={"color": "#9aa7b7"},
    )
    fig.update_yaxes(
        gridcolor="rgba(148,163,184,0.14)",
        zerolinecolor="rgba(148,163,184,0.14)",
        linecolor="rgba(148,163,184,0.18)",
        tickfont={"color": "#9aa7b7"},
    )
    return fig


def _draw_security_score(avg_trust, trust_pressure):
    score = max(
        0,
        min(
            100,
            round(
                (
                    avg_trust * 0.72
                    + (1 - min(trust_pressure, 1.0)) * 0.28
                )
                * 100,
                1,
            ),
        ),
    )
    fig = go.Figure()
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "%"},
        gauge={
            "axis": {"range": [0, 100]},
            "bgcolor": "#1f2937",
            "bar": {"color": "#34d399"},
            "borderwidth": 0,
            "steps": [
                {"range": [0, 40], "color": "#ef4444"},
                {"range": [40, 70], "color": "#f59e0b"},
                {"range": [70, 100], "color": "#22c55e"},
            ],
            "threshold": {
                "line": {"color": "#06b6d4", "width": 5},
                "thickness": 0.65,
                "value": score,
            },
        },
    ))
    return _plot_theme(fig, height=300, showlegend=False)


def _draw_anomaly_timeline(frame):
    if frame.empty or "timestamp" not in frame.columns:
        return None
    plot = frame.dropna(subset=["timestamp"]).tail(250).copy()
    if plot.empty:
        return None
    plot["time_bucket"] = plot["timestamp"].dt.floor("10s")
    grouped = (
        plot.groupby("time_bucket", as_index=False)[
            [
                "aggregate_anomaly",
                "worm_pattern_anomaly",
                "trust_anomaly_pressure",
            ]
        ]
        .mean()
    )
    for col in (
        "aggregate_anomaly",
        "worm_pattern_anomaly",
        "trust_anomaly_pressure",
    ):
        grouped[col] = grouped[col] * 100
    fig = px.line(
        grouped,
        x="time_bucket",
        y=["aggregate_anomaly", "worm_pattern_anomaly", "trust_anomaly_pressure"],
        labels={"value": "score", "time_bucket": "", "variable": ""},
        color_discrete_sequence=["#38bdf8", "#06b6d4", "#34d399"],
    )
    fig.update_traces(mode="lines+markers", line={"width": 2.2})
    return _plot_theme(fig, height=320)


def _draw_learning_graph(kb):
    if kb.empty:
        return None
    graph = kb.copy()
    for column in ("confidence", "observations", "avg_pattern_strength"):
        if column not in graph.columns:
            graph[column] = 0
        graph[column] = pd.to_numeric(graph[column], errors="coerce").fillna(0)
    if "attack_family" not in graph.columns:
        graph["attack_family"] = "unknown"
    family_counts = (
        graph["attack_family"]
        .astype(str)
        .replace("", "unknown")
        .value_counts()
        .head(5)
        .reset_index()
    )
    family_counts.columns = ["attack_family", "count"]
    fig = px.pie(
        family_counts,
        names="attack_family",
        values="count",
        hole=0.72,
        color_discrete_sequence=["#14b8a6", "#38bdf8", "#a3e635", "#f59e0b", "#f43f5e"],
    )
    fig.add_annotation(
        text=f"{len(graph)}<br><span style='font-size:14px;color:#9aa7b7'>Total</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 34, "color": "#f8fafc"},
    )
    return _plot_theme(fig, height=300)


def _draw_stage_graph(frame):
    if frame.empty:
        return None
    counts = (
        frame["stage"]
        .astype(str)
        .str.lower()
        .value_counts()
        .reset_index()
    )
    counts.columns = ["stage", "count"]
    fig = px.pie(
        counts,
        names="stage",
        values="count",
        hole=0.72,
        color="stage",
        color_discrete_sequence=["#22c55e", "#f59e0b", "#fb923c", "#f43f5e", "#38bdf8"],
    )
    fig.add_annotation(
        text=f"{int(counts['count'].sum())}<br><span style='font-size:14px;color:#9aa7b7'>Total</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 34, "color": "#f8fafc"},
    )
    return _plot_theme(fig, height=300)


def _draw_health_ring(latest, kb):
    if latest.empty:
        health = 100
    elif not _has_active_dashboard_risk(latest):
        health = 100
    else:
        trust = float(latest["final_trust"].mean())
        pressure = float(latest["trust_anomaly_pressure"].mean())
        flagged_ratio = float(latest["flagged"].mean())
        health = round(
            max(
                0,
                min(
                    100,
                    (
                        trust * 0.60
                        + (1 - pressure) * 0.25
                        + (1 - flagged_ratio) * 0.15
                    )
                    * 100,
                ),
            ),
            1,
        )

    if not kb.empty and "recommended_stage" in kb.columns:
        terminate_ready = int(
            kb["recommended_stage"]
            .astype(str)
            .str.lower()
            .eq("terminate")
            .sum()
        )
    else:
        terminate_ready = 0

    fig = go.Figure()
    fig.add_trace(go.Pie(
        values=[health, max(0, 100 - health)],
        hole=0.76,
        marker={"colors": ["#34d399", "#243041"]},
        textinfo="none",
        sort=False,
    ))
    fig.add_annotation(
        text=f"{health:.0f}%<br><span style='font-size:13px;color:#9aa7b7'>Health</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 34, "color": "#f8fafc"},
    )
    fig.add_annotation(
        text=f"{terminate_ready} terminate-ready patterns",
        x=0.5,
        y=-0.08,
        showarrow=False,
        font={"size": 12, "color": "#9aa7b7"},
    )
    return _plot_theme(fig, height=300, showlegend=False)


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
    latest = _dashboard_state_rows(
        process_rows,
        live_seconds=live_window_seconds,
        event_seconds=event_memory_seconds,
    )
    latest = _overlay_healing_status(latest, healing_rows, latest)
    flags = _active_flag_rows(latest)

    if process_rows.empty and kb.empty:
        st.warning("No telemetry yet. Start main.py and the dashboard will populate as the agent observes processes.")
        return

    raw_avg_trust = float(latest["final_trust"].mean()) if not latest.empty else 1.0
    raw_avg_pressure = float(latest["trust_anomaly_pressure"].mean()) if not latest.empty else 0.0
    avg_trust = _dashboard_trust_score(latest)
    avg_pressure = _dashboard_pressure_score(latest)
    flagged_count = int(latest["flagged"].sum()) if not latest.empty else 0
    critical_count = int(latest["severity"].astype(str).str.lower().eq("critical").sum()) if not latest.empty else 0
    learned_patterns = len(kb)
    terminate_ready = 0
    if not kb.empty and "recommended_stage" in kb.columns:
        terminate_ready = int(kb["recommended_stage"].astype(str).str.lower().eq("terminate").sum())

    anomaly_peak = (
        float(recent_process_rows["worm_pattern_anomaly"].max())
        if not recent_process_rows.empty
        else 0.0
    )
    action_count = 0
    if not latest.empty:
        action_count = int(
            latest["stage"]
            .astype(str)
            .str.lower()
            .isin(["throttle", "quarantine", "terminate", "block_resources"])
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
            "Active flags are high-confidence alerts only. Medium suspicious rows stay visible in tables, but they do not count as active flags unless behavior, trust, or severity crosses the response threshold.",
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
            "Trust Score is operational health: it stays healthy when there are no active flags or critical responses. System Anomaly still shows medium behavior pressure separately.",
        )

        main_chart, score_card = st.columns([0.74, 0.26])
        with main_chart:
            _card_header("Anomalies Over Time", "aggregate, worm pattern, and trust pressure")
            _info_box(
                "How to read",
                "Spikes show behavior becoming unusual. Aggregate is general anomaly, worm pattern is worm-like activity, and trust pressure rises when dynamic trust drops.",
            )
            anomaly_fig = _draw_anomaly_timeline(recent_process_rows)
            if anomaly_fig:
                st.plotly_chart(anomaly_fig, width="stretch")
            else:
                st.info("No anomaly timeline yet.")

        with score_card:
            _card_header("Security Score", "trust weighted system health")
            _info_box(
                "How to read",
                "Higher is healthier. This combines average trust and anomaly pressure, so it can dip before a process is terminated.",
            )
            st.plotly_chart(
                _draw_security_score(avg_trust, avg_pressure),
                width="stretch",
            )

        lower_left, lower_right = st.columns([0.49, 0.51])
        with lower_left:
            _card_header("Learnt Pattern Categories", "knowledge base attack families")
            _info_box(
                "How to read",
                "This shows what the learning engine has remembered from previous detections, grouped by attack family.",
            )
            learning_fig = _draw_learning_graph(kb)
            if learning_fig:
                st.plotly_chart(learning_fig, width="stretch")
            else:
                st.info("No learned patterns yet.")

        with lower_right:
            _card_header("System Health", "response stages and terminate readiness")
            _info_box(
                "How to read",
                "Health summarizes trust across live processes. The stage chart shows how many processes are only observed versus throttled, quarantined, or terminated.",
            )
            health_a, health_b = st.columns([0.48, 0.52])
            with health_a:
                st.plotly_chart(
                    _draw_health_ring(latest, kb),
                    width="stretch",
                )
            with health_b:
                stage_fig = _draw_stage_graph(latest)
                if stage_fig:
                    st.plotly_chart(stage_fig, width="stretch")
                else:
                    st.info("No response data yet.")

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
                        ],
                        limit=12,
                    ),
                    width="stretch",
                    hide_index=True,
                )

        _card_header("Learnt Patterns", "what the ML agent will escalate faster next time")
        _info_box(
            "How to read",
            "Each row is a behavior pattern the learner can reuse. Higher confidence and observations mean the system has seen similar behavior more often.",
        )
        if kb.empty:
            st.info("Knowledge base is empty.")
        else:
            kb_sorted = kb.sort_values(
                [col for col in ("confidence", "observations") if col in kb.columns],
                ascending=False,
            )
            st.dataframe(
                _compact_table(
                    kb_sorted,
                    [
                        "attack_family",
                        "disposition",
                        "confidence",
                        "recommended_stage",
                        "observations",
                        "avg_pattern_strength",
                        "avg_trust_anomaly_pressure",
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
