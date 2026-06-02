import sys
import os
import json
from collections import deque

try:
    import streamlit as st
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from streamlit_autorefresh import st_autorefresh
except ImportError as e:
    print(
        f"Dashboard unavailable: missing dependency {e}."
    )
    print(
        "Install streamlit, pandas, plotly, and streamlit-autorefresh to run the dashboard."
    )

    class _DummyObject:
        def __getattr__(self, name):
            return self._noop

        def __call__(self, *args, **kwargs):
            return self

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __bool__(self):
            return False

        def __len__(self):
            return 0

        def __iter__(self):
            return iter(())

        def __contains__(self, item):
            return False

        def _noop(self, *args, **kwargs):
            return self

        def get(self, *args, **kwargs):
            return {}

        def items(self, *args, **kwargs):
            return ()

        def value_counts(self, *args, **kwargs):
            return _DummyValueCounts()

        def sort_values(self, *args, **kwargs):
            return self

        def groupby(self, *args, **kwargs):
            return self

        def tail(self, *args, **kwargs):
            return self

        def reset_index(self, *args, **kwargs):
            return self

        def fillna(self, *args, **kwargs):
            return self

        def mean(self, *args, **kwargs):
            return 0

        def append(self, *args, **kwargs):
            return self

        def __getitem__(self, key):
            return self

        def __setitem__(self, key, value):
            pass

        def columns(self, count):
            return [self for _ in range(count)]

        def __getattribute__(self, name):
            if name == 'empty':
                return True
            if name == 'dtype':
                return None
            if name == 'shape':
                return (0, 0)
            return object.__getattribute__(self, name)

    class _DummyDataFrame(_DummyObject):
        columns = []

        def __iter__(self):
            return iter(())

    class _DummyValueCounts(_DummyObject):
        def __init__(self):
            self.index = []
            self.values = []

        def get(self, *args, **kwargs):
            return 0

    class _DummyPandas(_DummyObject):
        def read_json(self, *args, **kwargs):
            return _DummyDataFrame()

        def to_datetime(self, *args, **kwargs):
            return self

        def to_numeric(self, *args, **kwargs):
            return self

        def DataFrame(self, *args, **kwargs):
            return _DummyDataFrame()

    def _noop_cache_data(*args, **kwargs):
        def decorator(fn):
            return fn
        return decorator

    st = _DummyObject()
    st.cache_data = _noop_cache_data
    pd = _DummyPandas()
    px = _DummyObject()
    go = _DummyObject()

    def st_autorefresh(*args, **kwargs):
        return None

# ===================================================
# CONFIG
# ===================================================
st.set_page_config(
    page_title="Cyber Defense Command Center",
    page_icon="🛡️",
    layout="wide"
)

st_autorefresh(
    interval=int(
        os.getenv(
            "SELF_HEALING_DASHBOARD_REFRESH_MS",
            "8000"
        )
    ),
    key="refresh"
)

# ===================================================
# CYBER SOC STYLE
# ===================================================
st.markdown("""
<style>

.main {
    background-color: #0E1117;
}

.metric-container {
    background: #151A23;
    border-radius: 12px;
    padding: 12px;
}

h1,h2,h3 {
    color: #00E5FF;
}

[data-testid="stMetricValue"] {
    color: #00FFAA;
}

</style>
""", unsafe_allow_html=True)

# ===================================================
# FILES
# ===================================================
PROCESS_LOG = (
    "logs/system_log.json"
)

ENTITY_LOG = (
    "logs/entity_log.json"
)

HEALING_LOG = (
    "logs/healing_log.json"
)

LEARNING_KB_LOG = (
    "logs/learning_kb.json"
)

IGNORE_ROOTS = [1, 2]

# ===================================================
# TITLE
# ===================================================
st.title(
    "🛡️ Self-Healing Cyber Defense System"
)

st.caption(
    "Executive Cyber SOC Dashboard"
)


# ===================================================
# NAVIGATION
# ===================================================
page = st.radio(

    "Navigation",

    [

        "🛡 Operations",

        "🧬 Threat Intelligence",

        "🐇 Worm Lab",

        "📚 Learning Center"
    ],

    horizontal=True
)
# ===================================================
# LOADERS
# ===================================================
DASHBOARD_MAX_ROWS = int(
    os.getenv(
        "SELF_HEALING_DASHBOARD_MAX_ROWS",
        "500"
    )
)

CHART_MAX_ROWS = int(
    os.getenv(
        "SELF_HEALING_DASHBOARD_CHART_ROWS",
        "250"
    )
)


def _tail_lines(file_path, max_lines):

    try:
        with open(file_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            position = f.tell()
            blocks = []
            lines = []
            chunk_size = 65536

            while position > 0 and len(lines) <= max_lines:
                read_size = min(chunk_size, position)
                position -= read_size
                f.seek(position)
                blocks.append(
                    f.read(read_size)
                )
                lines = (
                    b"".join(
                        reversed(blocks)
                    )
                    .splitlines()
                )

        return [
            line.decode(
                "utf-8",
                "ignore"
            )
            for line in lines[-max_lines:]
        ]

    except Exception:
        return []


def _load_json_lines(file_path):

    try:
        rows = deque(maxlen=DASHBOARD_MAX_ROWS)

        for line in _tail_lines(
            file_path,
            DASHBOARD_MAX_ROWS
        ):
            try:
                rows.append(
                    json.loads(line)
                )
            except Exception:
                continue

        return pd.DataFrame(
            list(
                rows
            )
        )

    except Exception:
        return pd.DataFrame()


def _load_json_file(file_path):

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            rows = list(data.values())
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        return pd.DataFrame(rows)

    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=3)
def load_process_logs():

    return _load_json_lines(PROCESS_LOG)


@st.cache_data(ttl=3)
def load_entity_logs():

    return _load_json_lines(ENTITY_LOG)


@st.cache_data(ttl=3)
def load_healing_logs():

    return _load_json_lines(HEALING_LOG)


@st.cache_data(ttl=3)
def load_learning_kb():

    return _load_json_file(LEARNING_KB_LOG)


# ===================================================
# LOAD DATA
# ===================================================
df = load_process_logs()
entity_df = load_entity_logs()
healing_df = load_healing_logs()
learning_kb_df = load_learning_kb()

if df.empty and learning_kb_df.empty:

    st.warning(
        "No logs found."
    )

    st.stop()

if df.empty:
    df = pd.DataFrame([
        {
            "timestamp": pd.Timestamp.now(),
            "pid": 0,
            "name": "no live process logs",
            "dynamic_trust": 1.0,
            "final_trust": 1.0,
            "static_trust": 1.0,
            "worm_score": 0,
            "confidence": 0,
            "label": "normal",
            "severity": "low",
            "stage": "observe",
            "cpu": 0,
            "memory": 0,
            "threads": 0,
            "connections": 0,
            "file_events": 0,
            "learning_state": None,
            "features": {},
            "anomalies": {}
        }
    ])

# ===================================================
# CLEAN DATA
# ===================================================
df["timestamp"] = pd.to_datetime(
    df["timestamp"]
)

LIVE_WINDOW_SECONDS = 45

latest_timestamp = df[
    "timestamp"
].max()

live_cutoff = (
    latest_timestamp
    -
    pd.Timedelta(
        seconds=LIVE_WINDOW_SECONDS
    )
)

live_df = (
    df[
        df["timestamp"]
        >=
        live_cutoff
    ]
)

if live_df.empty:
    live_df = df

latest = (

    live_df.sort_values(
        "timestamp"
    )

    .groupby("pid")

    .tail(1)

    .reset_index(drop=True)
)

# ===================================================
# SAFE DEFAULTS
# ===================================================
defaults = {

    "dynamic_trust": 1.0,
    "final_trust": 1.0,
    "static_trust": 1.0,

    "worm_score": 0,
    "confidence": 0,

    "label": "normal",
    "severity": "low",

    "stage": "observe",

    "response": "none",

    "cpu": 0,
    "memory": 0,

    "connections": 0,
    "files": 0,

    "threads": 0
}

for col, val in defaults.items():

    if col not in latest.columns:

        latest[col] = val

# ===================================================
# FINAL BALANCED HEALTH ENGINE
# PPT + REVIEW ALIGNED
# ===================================================

# ---------------------------------------
# NUMERIC SAFETY
# ---------------------------------------
latest["final_trust"] = pd.to_numeric(

    latest["final_trust"],

    errors="coerce"

).fillna(1.0)

latest["worm_score"] = pd.to_numeric(

    latest["worm_score"],

    errors="coerce"

).fillna(0)

# ---------------------------------------
# SIZE SANITIZER
# ensure plotly receives valid non-negative
# numeric values for marker sizing
# ---------------------------------------
def _safe_size_col(df, col, tmp_name):
    try:
        if col in df.columns:
            df[tmp_name] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(lower=0)
        else:
            df[tmp_name] = 0
    except Exception:
        df[tmp_name] = 0


# prepare common safe size columns on latest
_safe_size_col(latest, "worm_score", "__size_worm_score")
_safe_size_col(latest, "confidence", "__size_confidence")

# ---------------------------------------
# BASE SIGNALS
# ---------------------------------------
avg_trust = (

    latest[
        "final_trust"
    ].mean()
)

worm_risk = (

    latest[
        "worm_score"
    ].mean()
)

# ---------------------------------------
# SEVERITY DISTRIBUTION
# ratio based
# prevents dashboard collapse
# ---------------------------------------
severity_distribution = (

    latest[
        "severity"
    ]

    .value_counts(
        normalize=True
    )
)

critical_ratio = (

    severity_distribution.get(
        "critical",
        0
    )
)

high_ratio = (

    severity_distribution.get(
        "high",
        0
    )
)

medium_ratio = (

    severity_distribution.get(
        "medium",
        0
    )
)

low_ratio = (

    severity_distribution.get(
        "low",
        0
    )
)

# ---------------------------------------
# SMART PENALTY
#
# critical hurts a lot
# high hurts moderately
# medium hurts slightly
# low almost ignored
# ---------------------------------------
severity_penalty = (

    critical_ratio * 40

    +

    high_ratio * 12

    +

    medium_ratio * 5

    +

    low_ratio * 1
)

# ---------------------------------------
# FINAL HEALTH SCORE
# ---------------------------------------
health_score = (

    (
        avg_trust
        * 100
    )

    -

    severity_penalty

    -

    (
        worm_risk
        * 8
    )
)

health_score = max(

    0,

    min(

        100,

        round(
            health_score,
            2
        )
    )
)

if len(latest) < 5 and critical_ratio >= 0.5:
    health_score = max(
        health_score,
        65
    )

# ===================================================
# EXECUTIVE KPIs
# ===================================================
ACTIVE_HEALING_STAGES = [
    "restrict",
    "isolate",
    "block_resources",
    "terminate",
    "trust_recovery"
]

NON_ACTION_RESPONSES = [
    "skipped",
    "monitoring",
    "none",
    "protected pid",
    "trusted process",
    "safe mode (healing disabled)"
]

active_processes = len(
    latest
)

critical_processes = len(

    latest[
        latest["severity"]
        ==
        "critical"
    ]
)

healing_active = len(

    latest[
        latest["stage"].isin(
            ACTIVE_HEALING_STAGES
        )
        &
        ~latest["response"].isin(
            NON_ACTION_RESPONSES
        )
    ]
)

trust_stability = round(
    avg_trust * 100,
    2
)

k1, k2, k3, k4, k5 = (
    st.columns(5)
)

k1.metric(
    "⚙️ Active Processes",
    active_processes
)

k2.metric(
    "🧠 Trust Stability",
    f"{trust_stability}%"
)

k3.metric(
    "🐛 Worm Risk",
    round(worm_risk, 2)
)

k4.metric(
    "🛡 Active Healing",
    healing_active
)

k5.metric(
    "🚨 Critical",
    critical_processes
)

st.markdown("---")

# ===================================================
# EXECUTIVE VISUALS
# ===================================================
v1, v2 = st.columns(2)

with v1:

    fig = go.Figure(

        go.Indicator(

            mode="gauge+number",

            value=health_score,

            title={
                "text":
                "System Health"
            },

            gauge={
                "axis":
                {
                    "range":
                    [0, 100]
                }
            }
        )
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )

with v2:

    sev = latest[
        "severity"
    ].value_counts()

    fig = px.pie(

        values=sev.values,

        names=sev.index,

        title=
        "Threat Severity"
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )


if page == "🛡 Operations":
    # ===================================================
    # TRUST INTELLIGENCE
    # ===================================================
    st.subheader(
        "🧠 Trust Intelligence"
    )

    t1, t2 = st.columns(2)

    with t1:

        fig = px.histogram(

            latest,

            x="final_trust",

            nbins=30,

            title=
            "Final Trust Distribution"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    with t2:

        fig = px.scatter(

            latest,

            x="dynamic_trust",

            y="final_trust",

            color="severity",

            hover_data=[
                "name",
                "pid"
            ],

            title=
            "Trust Correlation"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    # ===================================================
    # WORM INTELLIGENCE
    # ===================================================
    st.subheader(
        "🐛 Worm Intelligence"
    )

    w1, w2 = st.columns(2)

    with w1:

        top_worm = (

            latest

            .sort_values(
                "worm_score",
                ascending=False
            )

            .head(10)
        )

        fig = px.bar(

            top_worm,

            x="name",

            y="worm_score",

            color="severity",

            title=
            "Top Worm Likelihood"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    with w2:

        fig = px.scatter(

            latest,

            x="connections",

            y="threads",

            size="__size_worm_score",

            color="severity",

            hover_data=[
                "name",
                "pid"
            ],

            title=
            "Propagation Analysis"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    # ===================================================
    # SYSTEM RUNTIME ANALYTICS
    # ===================================================
    st.subheader(
        "📈 Runtime Intelligence"
    )

    timeline_df = df.copy()

    timeline_df["minute"] = (

        timeline_df[
            "timestamp"
        ]

        .dt.floor("min")
    )

    runtime = (

        timeline_df

        .groupby("minute")

        .agg({

            "pid": "nunique",

            "worm_score":
                "mean",

            "final_trust":
                "mean"
        })

        .reset_index()
    )

    r1, r2 = st.columns(2)

    with r1:

        fig = px.line(

            runtime,

            x="minute",

            y="pid",

            title=
            "Active Process Trend"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    with r2:

        fig = px.line(

            runtime,

            x="minute",

            y="worm_score",

            title=
            "Worm Risk Trend"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    fig = px.line(

        runtime,

        x="minute",

        y="final_trust",

        title=
        "Trust Evolution Timeline"
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )
    # ===================================================
    # CONFIDENCE ANALYTICS
    # ===================================================
    st.subheader(
        "🎯 Confidence Intelligence"
    )

    c1, c2 = st.columns(2)

    with c1:

        fig = px.histogram(

            latest,

            x="confidence",

            nbins=25,

            color="severity",

            title=
            "Confidence Distribution"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    with c2:

        fig = px.scatter(

            latest,

            x="confidence",

            y="worm_score",

            size="__size_worm_score",

            color="severity",

            hover_data=[
                "name",
                "pid"
            ],

            title=
            "Confidence vs Worm Score"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    # ===================================================
    # ADAPTIVE HEALING CENTER
    # PPT SLIDE 16–17
    # ===================================================
    st.subheader(
        "🛡 Adaptive Healing Center"
    )

    stage_order = [

        "observe",
        "restrict",
        "isolate",
        "block_resources",
        "terminate",
        "trust_recovery"
    ]

    stage_counts = (

        latest["stage"]

        .value_counts()

        .reindex(
            stage_order,
            fill_value=0
        )
    )

    h1, h2 = st.columns(2)

    with h1:

        fig = px.bar(

            x=stage_counts.index,

            y=stage_counts.values,

            title=
            "Healing Stage Distribution"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    with h2:

        active_healing = (

            latest[
                latest[
                    "stage"
                ]
                !=
                "observe"
            ]
        )

        if not active_healing.empty:

            fig = px.scatter(

                active_healing,

                x="worm_score",

                y="final_trust",

                color="stage",

                size="__size_confidence",

                hover_data=[
                    "name",
                    "pid"
                ],

                title=
                "Live Healing Activity"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )

        else:

            st.success(
                "✅ No active containment"
            )


    # ===================================================
    # HEALING TIMELINE
    # ===================================================
    if not healing_df.empty:

        st.subheader(
            "🕒 Healing Timeline"
        )

        healing_df[
            "timestamp"
        ] = pd.to_datetime(

            healing_df[
                "timestamp"
            ]
        )

        fig = px.scatter(

            healing_df,

            x="timestamp",

            y="stage",

            color="stage",

            hover_data=[
                "pid",
                "status"
            ],

            title=
            "Healing Response Timeline"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )


# ===================================================
# OPERATIONS CENTER
# ===================================================

    st.subheader(
        "🛡 Process Operations Center"
    )

    process_cols = [

        "pid",
        "name",

        "dynamic_trust",
        "final_trust",

        "worm_score",
        "confidence",

        "label",
        "severity",

        "stage",

        "cpu",
        "memory",
        "threads",
        "connections"
    ]

    process_cols = [

        c for c in process_cols
        if c in latest.columns
    ]

    display_df = (

        latest[process_cols]

        .sort_values(
            by=[
                "final_trust",
                "worm_score"
            ],
            ascending=[
                True,
                False
            ]
        )
    )

    st.dataframe(
        display_df,
        width="stretch",
        height=500
    )

    st.markdown("---")

    o1, o2 = st.columns(2)

    with o1:

        top_cpu = (

            latest

            .sort_values(
                "cpu",
                ascending=False
            )

            .head(10)
        )

        fig = px.bar(

            top_cpu,

            x="name",
            y="cpu",

            color="severity",

            title=
            "Top CPU Consumers"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

    with o2:

        top_mem = (

            latest

            .sort_values(
                "memory",
                ascending=False
            )

            .head(10)
        )

        fig = px.bar(

            top_mem,

            x="name",
            y="memory",

            color="severity",

            title=
            "Top Memory Consumers"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )


# ===================================================
# THREAT INTELLIGENCE
# ===================================================
elif page == "🧬 Threat Intelligence":

    st.subheader(
        "🧬 Threat Intelligence Center"
    )

    if entity_df.empty:

        st.info(
            "No entity intelligence available."
        )

    else:

        entity_df["timestamp"] = (

            pd.to_datetime(
                entity_df[
                    "timestamp"
                ]
            )
        )

        latest_entity = (

            entity_df

            .sort_values(
                "timestamp"
            )

            .groupby(
                "entity_root"
            )

            .tail(1)
        )

        latest_entity = (

            latest_entity[

                ~latest_entity[
                    "entity_root"
                ].isin(
                    IGNORE_ROOTS
                )
            ]
        )

        e1, e2 = st.columns(2)

        with e1:

            fig = px.bar(

                latest_entity

                .sort_values(
                    "children_count",
                    ascending=False
                )

                .head(10),

                x="entity_root",
                y="children_count",

                title=
                "Largest Process Families"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )

        with e2:

            _safe_size_col(latest_entity, "children_count", "__size_children_count")

            fig = px.scatter(

                latest_entity,

                x="growth_velocity",
                y="children_count",

                size="__size_children_count",

                hover_data=[
                    "entity_root"
                ],

                title=
                "Propagation Velocity"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )

        st.subheader(
            "🧬 Entity Audit Table"
        )

        entity_cols = [

            "entity_root",
            "children_count",
            "growth_velocity",
            "total_cpu",
            "total_memory"
        ]

        entity_cols = [

            c for c in entity_cols
            if c in latest_entity.columns
        ]

        st.dataframe(

            latest_entity[
                entity_cols
            ]

            .sort_values(
                "children_count",
                ascending=False
            ),

            width="stretch",
            height=420
        )


# ===================================================
# WORM LAB
# ===================================================
elif page == "🐇 Worm Lab":

    st.subheader(
        "🐛 Worm Intelligence Lab"
    )

    worm_df = (

        latest[
            latest[
                "worm_score"
            ] > 0
        ]

        .sort_values(
            "worm_score",
            ascending=False
        )
    )

    a, b, c = st.columns(3)

    a.metric(
        "🐛 Worm Signals",
        len(worm_df)
    )

    b.metric(

        "⚠ Highest Risk",

        round(

            worm_df[
                "worm_score"
            ].max(),

            2
        )

        if not worm_df.empty
        else 0
    )

    c.metric(

        "🛡 Healing Active",

        len(

            latest[
                latest[
                    "stage"
                ]
                !=
                "observe"
            ]
        )
    )

    st.markdown("---")

    if worm_df.empty:

        st.success(
            "✅ No active worm activity."
        )

    else:

        w3, w4 = st.columns(2)

        with w3:

            _safe_size_col(worm_df, "worm_score", "__size_worm_score")

            fig = px.bar(

                worm_df.head(10),

                x="name",
                y="worm_score",

                color="severity",

                text="worm_score",

                title=
                "Top Worm Likelihood"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )

        with w4:

            fig = px.scatter(

                worm_df,

                x="connections",
                y="threads",

                size="__size_worm_score",

                color="severity",

                hover_data=[
                    "pid",
                    "name"
                ],

                title=
                "Worm Propagation Map"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )

        st.subheader(
            "🐛 Worm Audit Table"
        )

        worm_cols = [

            "pid",
            "name",

            "worm_score",
            "confidence",

            "severity",
            "label",

            "stage",

            "connections",
            "threads"
        ]

        worm_cols = [

            c for c in worm_cols
            if c in worm_df.columns
        ]

        st.dataframe(

            worm_df[
                worm_cols
            ],

            width="stretch",
            height=400
        )


# ===================================================
# LEARNING CENTER
# ===================================================
elif page == "📚 Learning Center":

    st.subheader(
        "📚 Adaptive Learning Center"
    )

    st.subheader(
        "Behavior Knowledge Base"
    )

    if learning_kb_df.empty:

        st.info(
            "No learned behavior patterns yet."
        )

    else:

        kb = learning_kb_df.copy()

        for col, default in {
            "confidence": 0,
            "observations": 0,
            "action_count": 0,
            "false_positive_count": 0
        }.items():
            if col not in kb.columns:
                kb[col] = default

        if "last_seen" in kb.columns:
            kb["last_seen_time"] = pd.to_datetime(
                kb["last_seen"],
                unit="s",
                errors="coerce"
            )

        k1, k2, k3, k4 = st.columns(4)

        k1.metric("Learned Patterns", len(kb))
        k2.metric(
            "Attack Families",
            kb.get("attack_family", pd.Series(dtype=str)).nunique()
        )

        malicious_count = (
            kb.get("disposition", pd.Series(dtype=str))
            .eq("malicious")
            .sum()
        )

        k3.metric("Malicious Patterns", int(malicious_count))
        k4.metric("Avg Confidence", round(float(kb["confidence"].mean()), 3))

        kb_top = (
            kb.sort_values(
                ["confidence", "observations"],
                ascending=False
            )
            .head(12)
        )

        c1, c2 = st.columns(2)

        with c1:
            family_counts = (
                kb["attack_family"].value_counts()
                if "attack_family" in kb.columns
                else pd.Series(dtype=int)
            )

            if len(family_counts):
                fig = px.bar(
                    x=family_counts.index,
                    y=family_counts.values,
                    labels={"x": "Attack Family", "y": "Patterns"},
                    title="Learned Attack Families"
                )
                st.plotly_chart(fig, width="stretch")

        with c2:
            if "disposition" in kb.columns and len(kb):
                disp = kb["disposition"].value_counts()
                fig = px.pie(
                    values=disp.values,
                    names=disp.index,
                    title="Knowledge Disposition"
                )
                st.plotly_chart(fig, width="stretch")

        st.subheader("What The EDR Learned")

        display_cols = [
            "attack_family",
            "disposition",
            "confidence",
            "recommended_stage",
            "observations",
            "action_count",
            "false_positive_count",
            "last_process_name",
            "last_label",
            "last_severity",
            "summary",
            "evidence",
            "last_seen_time"
        ]

        display_cols = [
            col
            for col in display_cols
            if col in kb_top.columns
        ]

        st.dataframe(
            kb_top[display_cols],
            width="stretch",
            height=360
        )

        with st.expander("Knowledge Base Raw Patterns"):
            st.dataframe(
                kb.sort_values("observations", ascending=False),
                width="stretch",
                height=420
            )

    st.markdown("---")

    if "learning_state" not in latest.columns:

        st.info(
            "Learning data not available yet."
        )

    else:

        learning = latest[
            "learning_state"
        ].dropna()

        if len(learning):

            learning_df = (
                pd.json_normalize(
                    learning
                )
            )

            l1, l2 = st.columns(2)

            with l1:

                rep = px.histogram(

                    learning_df,

                    x="reputation",

                    nbins=20,

                    title=
                    "Reputation Distribution"
                )

                st.plotly_chart(
                    rep,
                    width="stretch"
                )

            with l2:

                trust_level = (

                    learning_df[
                        "trust_level"
                    ]

                    .value_counts()
                )

                fig = px.pie(

                    values=
                    trust_level.values,

                    names=
                    trust_level.index,

                    title=
                    "Trust Categories"
                )

                st.plotly_chart(
                    fig,
                    width="stretch"
                )

            st.subheader(
                "📚 Learning Audit"
            )

            st.dataframe(
                learning_df,
                width="stretch",
                height=400
            )

    st.markdown("---")

    st.subheader(
        "🔎 Full System Audit"
    )

    audit_cols = [

        "pid",
        "name",

        "final_trust",
        "dynamic_trust",

        "worm_score",
        "confidence",

        "label",
        "severity",

        "stage"
    ]

    audit_cols = [

        c for c in audit_cols
        if c in latest.columns
    ]

    st.dataframe(

        latest[
            audit_cols
        ]

        .sort_values(
            "worm_score",
            ascending=False
        ),

        width="stretch",
        height=500
    )
