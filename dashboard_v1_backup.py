import sys

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

    class _DummyValueCounts(_DummyObject):
        def __init__(self):
            self.index = []
            self.values = []

        def get(self, *args, **kwargs):
            return 0

    class _DummyColumns(list):
        def duplicated(self, *args, **kwargs):
            return _DummyColumns()

        def __invert__(self):
            return self

    class _DummyDataFrame(_DummyObject):
        columns = _DummyColumns()

        @property
        def loc(self):
            return self

        def __getitem__(self, key):
            return self

        def __iter__(self):
            return iter(())

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

# ---------------------------------------------------
# FILES
# ---------------------------------------------------
PROCESS_LOG = "logs/system_log.json"
ENTITY_LOG = "logs/entity_log.json"

IGNORE_ROOTS = [1, 2]

# ---------------------------------------------------
# CONFIG
# ---------------------------------------------------
st.set_page_config(
    page_title="Cyber Defense Command Center",
    layout="wide"
)

st_autorefresh(interval=3000, key="refresh")

st.title(" Self-Healing Cyber Defense System")
st.caption("Executive Cyber Resilience Dashboard")

# ---------------------------------------------------
# LOADERS
# ---------------------------------------------------
@st.cache_data(ttl=3)
def load_process_logs():
    try:
        return pd.read_json(PROCESS_LOG, lines=True).tail(4000)
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=3)
def load_entity_logs():
    try:
        return pd.read_json(ENTITY_LOG, lines=True).tail(4000)
    except Exception:
        return pd.DataFrame()


df = load_process_logs()
entity_df = load_entity_logs()

if df.empty:
    st.warning("No logs found.")
    st.stop()

# ---------------------------------------------------
# CLEAN
# ---------------------------------------------------
df["timestamp"] = pd.to_datetime(df["timestamp"])

latest = (
    df.sort_values("timestamp")
    .groupby("pid")
    .tail(1)
    .reset_index(drop=True)
)

# ---------------------------------------------------
# EXPAND TRUST / ANOMALIES
# ---------------------------------------------------
if "trust" in latest.columns:
    try:
        trust_df = pd.json_normalize(latest["trust"])
        latest = pd.concat([latest, trust_df], axis=1)
    except Exception:
        pass

if "anomalies" in latest.columns:
    try:
        anom_df = pd.json_normalize(latest["anomalies"])
        latest = pd.concat([latest, anom_df], axis=1)
    except Exception:
        pass

latest = latest.loc[:, ~latest.columns.duplicated()]

# ---------------------------------------------------
# SAFE DEFAULTS
# ---------------------------------------------------
defaults = {
    "final_trust": 1.0,
    "cmdline": "",
    "worm_score": 0,
    "f_proc_spawn": 0,
    "f_proc_tree": 0,
    "f_process_trend": 0,
    "cpu": 0,
    "memory": 0,
    "connections": 0,
    "file_events": 0
}

for col, val in defaults.items():
    if col not in latest.columns:
        latest[col] = val

# ---------------------------------------------------
# SAFE SYSTEM LIST
# ---------------------------------------------------
SAFE_SYSTEM = [
    "chrome", "chrome_crashpad_handler",
    "kdeconnectd", "code", "firefox",
    "discord", "slack", "teams",
    "streamlit",
    "systemd", "kthreadd", "kworker",
    "dnsmasq", "gdm", "gdm3",
    "gdm-session-worker",
    "sshd", "sd-pam",
    "fusermount", "pipewire",
    "dbus", "networkmanager",
    "gnome-keyring",
    "mariadb", "mariadbd",
    "packagekit", "polkit",
    "prometheus",
    "python3"
]

# ---------------------------------------------------
# FINAL CLASSIFIER
# ---------------------------------------------------
def classify(row):
    try:
        name = str(row["name"]).lower()

        trust = float(row["final_trust"])
        worm = float(row["worm_score"])
        spawn = float(row["f_proc_spawn"])
        trend = float(row["f_process_trend"])
        tree = float(row["f_proc_tree"])
        cpu = float(row["cpu"])
        mem = float(row["memory"])

        safe = any(app in name for app in SAFE_SYSTEM)

        idle = (
            cpu <= 0.1 and
            mem < 0.20 and
            worm < 25 and
            spawn == 0
        )

        if idle:
            return "normal"

        # SAFE APPS
        if safe:
            if (
                worm > 90 or
                (spawn > 10 and trend > 0) or
                tree > 250
            ):
                return "critical"

            elif (
                worm > 70 or
                trust < 0.18
            ):
                return "watchlist"

            else:
                return "normal"

        # UNKNOWN APPS
        if (
            worm > 80 or
            trust < 0.15
        ):
            return "critical"

        elif (
            worm > 45 or
            trust < 0.30
        ):
            return "watchlist"

        return "normal"

    except Exception:
        return "normal"


latest["level"] = latest.apply(classify, axis=1)

critical = latest[latest["level"] == "critical"]
watchlist = latest[latest["level"] == "watchlist"]
normal = latest[latest["level"] == "normal"]

# ---------------------------------------------------
# HEALTH SCORE (FINAL FIXED LOGIC)
# ---------------------------------------------------
total = len(latest)

critical_count = len(critical)
watch_count = len(watchlist)

if total == 0:
    health_score = 100

else:
    # weighted penalties
    critical_penalty = (critical_count / total) * 70
    watch_penalty = (watch_count / total) * 25

    # average trust effect (small influence only)
    avg_trust = latest["final_trust"].mean() * 10

    health_score = (
        100
        - critical_penalty
        - watch_penalty
        - (10 - avg_trust)
    )

    health_score = round(
        max(0, min(100, health_score)),
        2
    )

# ---------------------------------------------------
# KPI
# ---------------------------------------------------
c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Active Processes", len(latest))
c2.metric("Risk Processes", len(critical) + len(watchlist))
c3.metric("Avg CPU", round(latest["cpu"].mean(), 2))
c4.metric("Avg Memory", round(latest["memory"].mean(), 2))
c5.metric(" Health", f"{health_score}%")

st.markdown("---")

# ---------------------------------------------------
# VISUALS
# ---------------------------------------------------
v1, v2 = st.columns(2)

with v1:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=health_score,
        title={"text": "System Health"},
        gauge={"axis": {"range": [0, 100]}}
    ))

    st.plotly_chart(fig, width="stretch")

with v2:
    counts = latest["level"].value_counts()

    fig = px.pie(
        values=counts.values,
        names=counts.index,
        title="Risk Distribution"
    )

    st.plotly_chart(fig, width="stretch")

# ---------------------------------------------------
# TABS
# ---------------------------------------------------
page = st.radio(
    "Navigation",
    [
        " Operations",
        " Threat Intelligence",
        " Worm Lab"
    ],
    horizontal=True
)

# ===================================================
# TAB 1
# ===================================================
if page == " Operations":

    st.subheader(" Process Trust Table")

    cols = [
        "pid", "name", "cpu", "memory",
        "connections", "file_events",
        "final_trust", "level"
    ]

    cols = [c for c in cols if c in latest.columns]

    st.dataframe(
        latest[cols].sort_values("final_trust"),
        width="stretch",
        height=520
    )

    st.subheader(" Top CPU Consumers")

    top_cpu = latest.sort_values(
        "cpu",
        ascending=False
    ).head(10)

    fig = px.bar(
        top_cpu,
        x="name",
        y="cpu",
        color="cpu"
    )

    st.plotly_chart(fig, width="stretch")

# ===================================================
# TAB 2
# ===================================================
elif page == " Threat Intelligence":

    st.subheader(" Process Family Analysis")

    if entity_df.empty:
        st.info("No entity logs found.")

    else:
        entity_df["timestamp"] = pd.to_datetime(
            entity_df["timestamp"]
        )

        fam = (
            entity_df.sort_values("timestamp")
            .groupby("entity_root")
            .tail(1)
        )

        fam = fam[
            ~fam["entity_root"].isin(IGNORE_ROOTS)
        ]

        st.dataframe(
            fam[[
                "entity_root",
                "children_count"
            ]].sort_values(
                "children_count",
                ascending=False
            ),
            width="stretch",
            height=420
        )

        fig = px.bar(
            fam.sort_values(
                "children_count",
                ascending=False
            ).head(10),
            x="entity_root",
            y="children_count",
            title="Largest Families"
        )

        st.plotly_chart(fig, width="stretch")

# ===================================================
# TAB 3
# ===================================================
elif page == " Worm Lab":

    st.subheader(" Worm Simulation & Attack Lab")

    st.info(
        "Only worm_sim.py or correlated "
        "spawn + growth + trust collapse "
        "is flagged."
    )

    latest["name_lower"] = (
        latest["name"]
        .astype(str)
        .str.lower()
    )

    suspects = latest[
        (
            latest["cmdline"]
            .astype(str)
            .str.contains(
                "worm_sim.py|stress.py",
                case=False,
                na=False
            )
        )
        |
        (
            (latest["f_proc_spawn"] > 10)
            &
            (latest["f_process_trend"] > 0)
            &
            (latest["worm_score"] > 80)
        )
    ].sort_values(
        "worm_score",
        ascending=False
    )

    a, b, c = st.columns(3)

    a.metric("Active Worm Signals", len(suspects))

    b.metric(
        "Highest Worm Score",
        round(
            suspects["worm_score"].max(),
            2
        ) if not suspects.empty else 0
    )

    c.metric(
        "Containment",
        "ACTIVE" if not suspects.empty else "STABLE"
    )

    st.markdown("---")

    if suspects.empty:
        st.success("No active worm signatures.")
        st.info("Run worm_sim.py to simulate.")

    else:
        st.error("Worm replication detected")

        cols = [
            "pid", "name",
            "worm_score",
            "f_proc_spawn",
            "f_proc_tree",
            "f_process_trend",
            "final_trust"
        ]

        cols = [
            c for c in cols
            if c in suspects.columns
        ]

        st.dataframe(
            suspects[cols],
            width="stretch",
            height=350
        )

        fig = px.bar(
            suspects.head(10),
            x="name",
            y="worm_score",
            color="worm_score",
            text="worm_score"
        )

        st.plotly_chart(fig, width="stretch")
