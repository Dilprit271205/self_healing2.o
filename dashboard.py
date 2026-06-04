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
    from streamlit_autorefresh import st_autorefresh
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


DASHBOARD_MAX_ROWS = 1000
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


@st.cache_data(ttl=1)
def _read_json_lines(path, signature):
    del signature
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
    if "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    return frame


@st.cache_data(ttl=1)
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
    frame["flagged"] = (
        (
            frame["label"].astype(str).str.lower().isin({"worm", "forkbomb", "suspicious"})
            | frame["severity"].astype(str).str.lower().isin({"high", "critical"})
            | frame["trust_anomaly_pattern"].astype(bool)
            | frame["worm_like_behavior"].astype(bool)
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
    ordered = frame.sort_values("timestamp") if "timestamp" in frame.columns else frame
    return ordered.groupby("pid", as_index=False).tail(1)


def _recent_rows(frame, seconds=45):
    if frame.empty or "timestamp" not in frame.columns:
        return frame

    timestamps = pd.to_datetime(
        frame["timestamp"],
        errors="coerce"
    )

    if timestamps.dropna().empty:
        return frame

    cutoff = timestamps.max() - pd.Timedelta(
        seconds=seconds
    )
    recent = frame[
        timestamps >= cutoff
    ]

    return recent if not recent.empty else frame.tail(100)


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


def _plot_theme(fig, height=300, showlegend=True):
    fig.update_layout(
        height=height,
        paper_bgcolor="#202033",
        plot_bgcolor="#202033",
        font={
            "color": "#d8d8e8",
            "family": "Inter, Segoe UI, Arial, sans-serif",
        },
        margin=dict(l=18, r=18, t=24, b=18),
        legend={
            "orientation": "h",
            "y": 1.08,
            "x": 0.58,
            "font": {"color": "#a9a8b8"},
        },
        showlegend=showlegend,
    )
    fig.update_xaxes(
        gridcolor="rgba(255,255,255,0.06)",
        zerolinecolor="rgba(255,255,255,0.10)",
        linecolor="rgba(255,255,255,0.14)",
        tickfont={"color": "#aaa9b8"},
    )
    fig.update_yaxes(
        gridcolor="rgba(255,255,255,0.11)",
        zerolinecolor="rgba(255,255,255,0.10)",
        linecolor="rgba(255,255,255,0.14)",
        tickfont={"color": "#aaa9b8"},
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
            "bgcolor": "#2a2a40",
            "bar": {"color": "#6ef8a3"},
            "borderwidth": 0,
            "steps": [
                {"range": [0, 40], "color": "#ff5f6d"},
                {"range": [40, 70], "color": "#ffd15c"},
                {"range": [70, 100], "color": "#70f28d"},
            ],
            "threshold": {
                "line": {"color": "#35ffd0", "width": 5},
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
        color_discrete_sequence=["#2e8bff", "#25d7f7", "#39f39b"],
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
        color_discrete_sequence=["#26f3d1", "#25d7f7", "#6747ff", "#ffcf4d", "#ff4f73"],
    )
    fig.add_annotation(
        text=f"{len(graph)}<br><span style='font-size:14px;color:#aaa9b8'>Total</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 34, "color": "#f7f7fb"},
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
        color_discrete_sequence=["#64d84d", "#ffe35c", "#ff9f38", "#ff4f73", "#25d7f7"],
    )
    fig.add_annotation(
        text=f"{int(counts['count'].sum())}<br><span style='font-size:14px;color:#aaa9b8'>Total</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 34, "color": "#f7f7fb"},
    )
    return _plot_theme(fig, height=300)


def _draw_health_ring(latest, kb):
    if latest.empty:
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
        marker={"colors": ["#6ef8a3", "#303044"]},
        textinfo="none",
        sort=False,
    ))
    fig.add_annotation(
        text=f"{health:.0f}%<br><span style='font-size:13px;color:#aaa9b8'>Health</span>",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 34, "color": "#f7f7fb"},
    )
    fig.add_annotation(
        text=f"{terminate_ready} terminate-ready patterns",
        x=0.5,
        y=-0.08,
        showarrow=False,
        font={"size": 12, "color": "#aaa9b8"},
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
        interval=int(os.getenv("SELF_HEALING_DASHBOARD_REFRESH_MS", "2000")),
        key="refresh",
    )

    st.markdown(
        """
        <style>
        .stApp {
            color: #f7f7fb;
            background:
                radial-gradient(circle at 10% 0%, #3140ff 0, rgba(49,64,255,0.24) 24%, transparent 42%),
                radial-gradient(circle at 22% 105%, #21d7ff 0, rgba(33,215,255,0.22) 18%, transparent 38%),
                linear-gradient(135deg, #111028 0%, #090914 54%, #05070d 100%);
        }
        .block-container {
            max-width: 1380px;
            padding-top: 42px;
            padding-bottom: 42px;
        }
        section[data-testid="stSidebar"] { display: none; }
        header[data-testid="stHeader"] {
            background: transparent;
        }
        h1, h2, h3 {
            color: #f7f7fb;
            letter-spacing: 0;
        }
        .shell {
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            background: #171626;
            box-shadow: 0 30px 80px rgba(0,0,0,0.38);
            overflow: hidden;
        }
        .rail {
            min-height: 860px;
            background: #22213a;
            border-radius: 12px 0 0 12px;
            padding: 22px 10px;
            text-align: center;
        }
        .logo {
            width: 42px;
            height: 42px;
            border-radius: 8px;
            background: #1dffbf;
            color: #171626;
            font-weight: 900;
            font-size: 28px;
            line-height: 42px;
            margin: 0 auto 54px auto;
        }
        .rail-item {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            margin: 0 auto 18px auto;
            border: 1px solid rgba(255,255,255,0.10);
            color: #b5b4c6;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            font-weight: 800;
        }
        .rail-item.active {
            background: #353955;
            color: #1dffbf;
            border-color: rgba(29,255,191,0.35);
        }
        .content-pad {
            padding: 22px 22px 24px 10px;
        }
        .top-title {
            font-size: 24px;
            font-weight: 700;
            color: #f7f7fb;
            margin: 0 0 28px 0;
        }
        .tabs {
            display: flex;
            gap: 30px;
            border-bottom: 1px solid rgba(255,255,255,0.12);
            margin-bottom: 24px;
        }
        .tab {
            padding: 0 0 11px 0;
            color: #aaa9b8;
            font-size: 14px;
            font-weight: 650;
        }
        .tab.active {
            color: #f7f7fb;
            border-bottom: 2px solid #bcc6ff;
        }
        div[data-testid="stVerticalBlock"] > div:has(.card-heading) {
            background: #202033;
            border-radius: 16px;
            padding: 24px 26px;
            border: 1px solid rgba(255,255,255,0.04);
        }
        .card-heading {
            margin-bottom: 8px;
        }
        .card-title {
            font-size: 24px;
            font-weight: 720;
            color: #f7f7fb;
        }
        .card-note {
            color: #aaa9b8;
            font-size: 12px;
            margin-top: 4px;
        }
        [data-testid="stMetricValue"] { color: #5eead4; }
        .metric-card {
            border-radius: 16px;
            padding: 18px 20px;
            background: #202033;
            min-height: 112px;
            border: 1px solid rgba(255,255,255,0.04);
        }
        .metric-card.cyan { box-shadow: inset 0 3px 0 #25d7f7; }
        .metric-card.red { box-shadow: inset 0 3px 0 #ff4f73; }
        .metric-card.amber { box-shadow: inset 0 3px 0 #ffcf4d; }
        .metric-card.green { box-shadow: inset 0 3px 0 #1dffbf; }
        .metric-title {
            color: #aaa9b8;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 700;
        }
        .metric-value {
            color: #f7f7fb;
            font-size: 32px;
            font-weight: 760;
            line-height: 1.2;
            margin-top: 8px;
        }
        .metric-note {
            color: #aaa9b8;
            font-size: 12px;
            margin-top: 6px;
        }
        .health-row {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            color: #aaa9b8;
            font-size: 12px;
            margin-top: 8px;
        }
        .health-pill {
            border-radius: 999px;
            padding: 6px 10px;
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.06);
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 14px;
            overflow: hidden;
        }
        .stDataFrame, .stTable {
            background: #202033;
        }
        button[kind="secondary"] {
            background: #202033;
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
    recent_process_rows = _recent_rows(
        process_rows,
        seconds=int(
            os.getenv(
                "SELF_HEALING_DASHBOARD_LIVE_WINDOW_SECONDS",
                "45"
            )
        )
    )
    latest = _latest_by_pid(recent_process_rows)
    if latest.empty:
        latest = _latest_by_pid(process_rows)
    latest = _overlay_healing_status(latest, healing_rows, latest)
    flags = _active_flag_rows(latest)

    if process_rows.empty and kb.empty:
        st.warning("No telemetry yet. Start main.py and the dashboard will populate as the agent observes processes.")
        return

    avg_trust = float(latest["final_trust"].mean()) if not latest.empty else 1.0
    avg_pressure = float(latest["trust_anomaly_pressure"].mean()) if not latest.empty else 0.0
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

        kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
        with kpi1:
            _metric_card(
                "Trust Score",
                f"{avg_trust * 100:.1f}%",
                f"pressure {avg_pressure:.3f}",
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

        main_chart, score_card = st.columns([0.74, 0.26])
        with main_chart:
            _card_header("Anomalies Over Time", "aggregate, worm pattern, and trust pressure")
            anomaly_fig = _draw_anomaly_timeline(recent_process_rows)
            if anomaly_fig:
                st.plotly_chart(anomaly_fig, width="stretch")
            else:
                st.info("No anomaly timeline yet.")

        with score_card:
            _card_header("Security Score", "trust weighted system health")
            st.plotly_chart(
                _draw_security_score(avg_trust, avg_pressure),
                width="stretch",
            )

        lower_left, lower_right = st.columns([0.49, 0.51])
        with lower_left:
            _card_header("Learnt Pattern Categories", "knowledge base attack families")
            learning_fig = _draw_learning_graph(kb)
            if learning_fig:
                st.plotly_chart(learning_fig, width="stretch")
            else:
                st.info("No learned patterns yet.")

        with lower_right:
            _card_header("System Health", "response stages and terminate readiness")
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
