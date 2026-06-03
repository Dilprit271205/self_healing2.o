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
    background: #0b0f14;
}

section[data-testid="stSidebar"] {
    background: #0f1720;
}

.metric-container {
    background: #151A23;
    border-radius: 12px;
    padding: 12px;
}

h1,h2,h3 {
    color: #e7f2ff;
    letter-spacing: 0;
}

[data-testid="stMetricValue"] {
    color: #5eead4;
}

.command-band {
    background: linear-gradient(135deg, #101923 0%, #162433 55%, #101923 100%);
    border: 1px solid #26384a;
    border-radius: 8px;
    padding: 18px 20px;
    margin: 6px 0 18px 0;
}

.command-title {
    color: #f8fafc;
    font-size: 28px;
    font-weight: 750;
    line-height: 1.1;
}

.command-subtitle {
    color: #a8bdcf;
    font-size: 14px;
    margin-top: 6px;
}

.status-pill {
    display: inline-block;
    border-radius: 999px;
    padding: 4px 10px;
    margin: 0 6px 6px 0;
    font-size: 12px;
    font-weight: 650;
    border: 1px solid #31465a;
    color: #dcecff;
    background: #111c27;
}

.brief-card {
    border: 1px solid #26384a;
    border-radius: 8px;
    padding: 12px 14px;
    background: #0f1720;
    min-height: 94px;
}

.brief-label {
    color: #93a8bb;
    font-size: 12px;
    font-weight: 650;
    text-transform: uppercase;
}

.brief-value {
    color: #f8fafc;
    font-size: 24px;
    font-weight: 760;
    margin-top: 4px;
}

.brief-note {
    color: #a8bdcf;
    font-size: 13px;
    margin-top: 4px;
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

MODEL_METADATA_LOG = (
    "analysis/models/threat_model.metadata.json"
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
            rows = []

            for key, value in data.items():
                if isinstance(value, dict):
                    row = {
                        "pattern_id": key
                    }
                    row.update(value)
                    rows.append(row)
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        return pd.DataFrame(rows)

    except Exception:
        return pd.DataFrame()


def _file_signature(file_path):

    try:
        stat = os.stat(file_path)
        return (
            stat.st_mtime,
            stat.st_size
        )
    except Exception:
        return (
            0,
            0
        )


@st.cache_data(ttl=1)
def load_process_logs(_signature):

    return _load_json_lines(PROCESS_LOG)


@st.cache_data(ttl=1)
def load_entity_logs(_signature):

    return _load_json_lines(ENTITY_LOG)


@st.cache_data(ttl=1)
def load_healing_logs(_signature):

    return _load_json_lines(HEALING_LOG)


@st.cache_data(ttl=1)
def load_learning_kb(_signature):

    return _load_json_file(LEARNING_KB_LOG)


@st.cache_data(ttl=2)
def load_model_metadata(_signature):

    try:
        with open(MODEL_METADATA_LOG, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


NUMERIC_DEFAULTS = {
    "pid": 0,
    "entity_root": 0,
    "dynamic_trust": 1.0,
    "final_trust": 1.0,
    "static_trust": 1.0,
    "worm_score": 0.0,
    "confidence": 0.0,
    "cpu": 0.0,
    "memory": 0.0,
    "threads": 0.0,
    "connections": 0.0,
    "files": 0.0,
    "file_events": 0.0,
    "children_count": 0.0,
    "growth_velocity": 0.0,
    "total_cpu": 0.0,
    "total_memory": 0.0,
    "observations": 0.0,
    "action_count": 0.0,
    "false_positive_count": 0.0
}

TEXT_DEFAULTS = {
    "name": "unknown",
    "label": "normal",
    "severity": "low",
    "stage": "observe",
    "response": "none",
    "status": "",
    "type": "",
    "source": "",
    "alert": "",
    "disposition": "",
    "attack_family": "",
    "recommended_stage": "",
    "summary": "",
    "evidence": "",
    "last_process_name": "",
    "last_label": "",
    "last_severity": ""
}


def _normalize_score_series(series, default=0.0):

    numeric = pd.to_numeric(
        series,
        errors="coerce"
    ).fillna(default)

    return numeric.clip(lower=0)


def _normalize_trust_series(series, default=1.0):

    numeric = pd.to_numeric(
        series,
        errors="coerce"
    ).fillna(default)

    # Some historical rows store trust as 0-100; current rows use 0-1.
    numeric = numeric.where(
        numeric <= 1,
        numeric / 100
    )

    return numeric.clip(
        lower=0,
        upper=1
    )


def _normalize_dashboard_df(dataframe, required=None):

    if dataframe.empty:
        return dataframe

    normalized = dataframe.copy()

    for col, default in NUMERIC_DEFAULTS.items():
        if col not in normalized.columns:
            if required and col in required:
                normalized[col] = default
            continue

        if col in {
            "dynamic_trust",
            "final_trust",
            "static_trust"
        }:
            normalized[col] = _normalize_trust_series(
                normalized[col],
                default
            )
        else:
            normalized[col] = _normalize_score_series(
                normalized[col],
                default
            )

    for col, default in TEXT_DEFAULTS.items():
        if col not in normalized.columns:
            if required and col in required:
                normalized[col] = default
            continue

        normalized[col] = (
            normalized[col]
            .fillna(default)
            .astype(str)
            .replace(
                {
                    "": default,
                    "None": default,
                    "nan": default,
                    "NaT": default
                }
            )
            .str.lower()
            if col in {"severity", "stage", "response", "label"}
            else normalized[col]
            .fillna(default)
            .astype(str)
            .replace(
                {
                    "": default,
                    "None": default,
                    "nan": default,
                    "NaT": default
                }
            )
        )

    return normalized


# ===================================================
# LOAD DATA
# ===================================================
process_signature = _file_signature(PROCESS_LOG)
entity_signature = _file_signature(ENTITY_LOG)
healing_signature = _file_signature(HEALING_LOG)
learning_signature = _file_signature(LEARNING_KB_LOG)
model_signature = _file_signature(MODEL_METADATA_LOG)

df = load_process_logs(process_signature)
entity_df = load_entity_logs(entity_signature)
healing_df = load_healing_logs(healing_signature)
learning_kb_df = load_learning_kb(learning_signature)
model_metadata = load_model_metadata(model_signature)

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

df = _normalize_dashboard_df(
    df,
    required=set(NUMERIC_DEFAULTS) | set(TEXT_DEFAULTS)
)
entity_df = _normalize_dashboard_df(
    entity_df
)
healing_df = _normalize_dashboard_df(
    healing_df
)
learning_kb_df = _normalize_dashboard_df(
    learning_kb_df
)

# ===================================================
# CLEAN DATA
# ===================================================
df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

df = df.dropna(
    subset=[
        "timestamp"
    ]
)

if df.empty:
    st.warning(
        "Process log rows exist, but none have valid timestamps."
    )

    st.stop()

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


def _safe_table(dataframe):

    if dataframe is None or dataframe.empty:
        return pd.DataFrame()

    table = _normalize_dashboard_df(
        dataframe
    )

    def _safe_table_value(value):

        if isinstance(
            value,
            (dict, list, tuple, set)
        ):
            return json.dumps(
                value,
                sort_keys=True,
                default=str
            )

        try:
            if pd.isna(value):
                return ""
        except Exception:
            pass

        return str(value)

    for col in table.columns:
        if table[col].dtype != "object":
            continue

        table[col] = table[col].apply(
            _safe_table_value
        )

    return table


def _coerce_dict(value):

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}

    return {}


def _signal_value(signals, path, default=None):

    current = _coerce_dict(signals)

    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)

    return current


def _latest_signal_rows(rows):

    if rows.empty or "signals" not in rows.columns:
        return []

    signal_rows = []

    for _, item in rows.iterrows():
        signals = _coerce_dict(
            item.get("signals")
        )
        if signals:
            signal_rows.append(
                {
                    "pid": item.get("pid"),
                    "name": item.get("name"),
                    "label": item.get("label"),
                    "severity": item.get("severity"),
                    "worm_score": item.get("worm_score"),
                    "confidence": item.get("confidence"),
                    "signals": signals
                }
            )

    return signal_rows


def _behavior_summary(signal_rows):

    counts = {}

    for row in signal_rows:
        correlated = _coerce_dict(
            row["signals"].get("correlated_signals")
        )

        for name, active in correlated.items():
            if active:
                counts[name] = counts.get(name, 0) + 1

    return pd.DataFrame(
        [
            {
                "behavior": key.replace("_", " "),
                "count": value
            }
            for key, value in sorted(
                counts.items(),
                key=lambda item: item[1],
                reverse=True
            )
        ]
    )


def _top_driver_rows(signal_rows):

    rows = []

    for row in signal_rows:
        drivers = (
            row["signals"].get(
                "ml_top_drivers",
                []
            )
            or
            []
        )

        for driver in drivers[:3]:
            if not isinstance(driver, dict):
                continue

            rows.append(
                {
                    "pid": row["pid"],
                    "process": row["name"],
                    "label": row["label"],
                    "driver": str(
                        driver.get("feature", "")
                    ).replace("_", " "),
                    "value": driver.get("value", 0),
                    "impact": driver.get("impact", 0)
                }
            )

    return pd.DataFrame(rows)


def _brief_card(label, value, note=""):

    st.markdown(
        f"""
        <div class="brief-card">
            <div class="brief-label">{label}</div>
            <div class="brief-value">{value}</div>
            <div class="brief-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def _format_percent(value):

    try:
        return f"{round(float(value) * 100, 1)}%"
    except Exception:
        return "n/a"


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


def _format_file_age(signature):

    try:
        modified = signature[0]
        if not modified:
            return "no file"

        age = max(
            0,
            int(
                pd.Timestamp.now().timestamp()
                -
                modified
            )
        )

        if age < 60:
            return f"{age}s ago"

        return f"{round(age / 60, 1)}m ago"

    except Exception:
        return "unknown"


def _recent_alert_rows(process_rows, healing_rows):

    rows = []

    try:
        if not process_rows.empty:
            proc = process_rows.copy()

            for col, default in {
                "severity": "low",
                "stage": "observe",
                "label": "normal",
                "response": "",
                "worm_score": 0,
                "final_trust": 1.0,
                "name": "unknown"
            }.items():
                if col not in proc.columns:
                    proc[col] = default

            proc_alerts = proc[
                (
                    proc["severity"].astype(str).str.lower().isin(
                        ["medium", "high", "critical"]
                    )
                )
                |
                (
                    proc["stage"].astype(str).str.lower()
                    !=
                    "observe"
                )
                |
                (
                    proc["label"].astype(str).str.lower()
                    !=
                    "normal"
                )
            ].tail(20)

            for _, item in proc_alerts.iterrows():
                rows.append({
                    "timestamp": item.get("timestamp"),
                    "source": "process",
                    "pid": item.get("pid"),
                    "name": item.get("name"),
                    "alert": item.get("label"),
                    "severity": item.get("severity"),
                    "stage": item.get("stage"),
                    "status": item.get("response"),
                    "worm_score": item.get("worm_score"),
                    "final_trust": item.get("final_trust")
                })

        if not healing_rows.empty:
            heal = healing_rows.copy()

            for col, default in {
                "stage": "observe",
                "status": "",
                "action_taken": False
            }.items():
                if col not in heal.columns:
                    heal[col] = default

            heal_alerts = heal[
                heal["action_taken"].astype(bool)
                |
                (
                    heal["stage"].astype(str).str.lower()
                    !=
                    "observe"
                )
            ].tail(20)

            for _, item in heal_alerts.iterrows():
                rows.append({
                    "timestamp": item.get("timestamp"),
                    "source": "healing",
                    "pid": item.get("pid"),
                    "name": "",
                    "alert": "response",
                    "severity": "low",
                    "stage": item.get("stage"),
                    "status": item.get("status"),
                    "worm_score": 0.0,
                    "final_trust": 1.0
                })

        if not rows:
            return pd.DataFrame()

        alert_df = pd.DataFrame(rows)
        alert_df["timestamp"] = pd.to_datetime(
            alert_df["timestamp"],
            errors="coerce"
        )
        alert_df = _normalize_dashboard_df(
            alert_df,
            required={
                "pid",
                "worm_score",
                "final_trust",
                "severity",
                "stage",
                "status",
                "source",
                "alert",
                "name"
            }
        )

        return (
            alert_df
            .sort_values("timestamp", ascending=False)
            .head(20)
        )

    except Exception:
        return pd.DataFrame()


def _learning_summary(kb_rows, process_rows):

    summary = {
        "patterns": 0,
        "malicious": 0,
        "families": 0,
        "avg_confidence": 0,
        "recent": pd.DataFrame()
    }

    try:
        if not kb_rows.empty:
            kb = kb_rows.copy()

            for col, default in {
                "confidence": 0,
                "disposition": "",
                "attack_family": "",
                "last_seen": 0
            }.items():
                if col not in kb.columns:
                    kb[col] = default

            summary["patterns"] = len(kb)
            summary["malicious"] = int(
                kb["disposition"].astype(str).eq("malicious").sum()
            )
            summary["families"] = int(
                kb["attack_family"].astype(str).replace("", pd.NA).nunique()
            )
            summary["avg_confidence"] = round(
                float(
                    pd.to_numeric(
                        kb["confidence"],
                        errors="coerce"
                    )
                    .fillna(0)
                    .mean()
                ),
                3
            )

            if "last_seen" in kb.columns:
                kb["last_seen_time"] = pd.to_datetime(
                    kb["last_seen"],
                    unit="s",
                    errors="coerce"
                )

            cols = [
                "attack_family",
                "disposition",
                "confidence",
                "recommended_stage",
                "observations",
                "summary",
                "last_seen_time"
            ]
            cols = [
                col for col in cols
                if col in kb.columns
            ]

            summary["recent"] = (
                kb.sort_values(
                    "last_seen",
                    ascending=False
                )
                .head(5)[cols]
            )

        if not process_rows.empty and "learning_state" in process_rows.columns:
            learned = process_rows[
                "learning_state"
            ].dropna()

            if len(learned) and summary["patterns"] == 0:
                summary["patterns"] = len(learned)

    except Exception:
        pass

    return summary

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

recent_alerts_df = _recent_alert_rows(
    df,
    healing_df
)

learning_snapshot = _learning_summary(
    learning_kb_df,
    df
)

signal_rows = _latest_signal_rows(latest)
behavior_df = _behavior_summary(signal_rows)
driver_df = _top_driver_rows(signal_rows)

model_accuracy = (
    model_metadata
    .get("classification_report", {})
    .get("accuracy")
)
model_labels = model_metadata.get(
    "labels",
    {}
)
model_top_features = pd.DataFrame(
    model_metadata.get(
        "top_features",
        []
    )
)
model_trained_rows = model_metadata.get(
    "rows",
    0
)
model_trained_at = model_metadata.get(
    "trained_at",
    0
)
model_trained_text = (
    pd.to_datetime(
        model_trained_at,
        unit="s",
        errors="coerce"
    )
    if model_trained_at
    else None
)
model_status = (
    signal_rows[-1]["signals"].get("ml_status", {})
    if signal_rows
    else {}
)
top_risk = (
    latest.sort_values(
        "worm_score",
        ascending=False
    )
    .head(1)
)
top_risk_name = (
    top_risk.iloc[0].get("name", "none")
    if not top_risk.empty
    else "none"
)
top_risk_score = (
    round(float(top_risk.iloc[0].get("worm_score", 0)), 3)
    if not top_risk.empty
    else 0
)

st.markdown(
    f"""
    <div class="command-band">
        <div class="command-title">Cyber Defense Command</div>
        <div class="command-subtitle">
            Live process risk, ML confidence, trust health, and containment status in one view.
        </div>
        <div style="margin-top: 12px;">
            <span class="status-pill">Model rows: {model_trained_rows}</span>
            <span class="status-pill">Accuracy: {_format_percent(model_accuracy)}</span>
            <span class="status-pill">Autotrain: {model_status.get("autotrain", "unknown")}</span>
            <span class="status-pill">Retraining: {model_status.get("retraining", False)}</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

brief1, brief2, brief3, brief4 = st.columns(4)

with brief1:
    _brief_card(
        "System Health",
        f"{health_score}%",
        "Combined trust, severity, and worm-risk score"
    )

with brief2:
    _brief_card(
        "Top Risk",
        top_risk_name,
        f"worm score {top_risk_score}"
    )

with brief3:
    _brief_card(
        "Trust Stability",
        f"{trust_stability}%",
        "Average final trust across live entities"
    )

with brief4:
    _brief_card(
        "Active Containment",
        healing_active,
        f"{critical_processes} critical entities"
    )

st.markdown("---")

k1, k2, k3, k4, k5 = (
    st.columns(5)
)

k1.metric(
    "⚙️ Alerted Entities",
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

fresh1, fresh2, fresh3, fresh4 = st.columns(4)

fresh1.metric(
    "Process Log Updated",
    _format_file_age(process_signature)
)

fresh2.metric(
    "Healing Log Updated",
    _format_file_age(healing_signature)
)

fresh3.metric(
    "Knowledge Base Updated",
    _format_file_age(learning_signature)
)

fresh4.metric(
    "Dashboard Rows",
    len(df)
)

st.subheader(
    "Live Alerts"
)

if recent_alerts_df.empty:
    st.info(
        "No active alerts in the current log window."
    )
else:
    alert_cols = [
        "timestamp",
        "source",
        "pid",
        "name",
        "alert",
        "severity",
        "stage",
        "status",
        "worm_score",
        "final_trust"
    ]
    alert_cols = [
        col for col in alert_cols
        if col in recent_alerts_df.columns
    ]
    st.dataframe(
        _safe_table(recent_alerts_df[alert_cols]),
        width="stretch",
        height=280
    )

st.subheader(
    "Learning Snapshot"
)

l1, l2, l3, l4 = st.columns(4)

l1.metric(
    "Learned Patterns",
    learning_snapshot["patterns"]
)

l2.metric(
    "Malicious Patterns",
    learning_snapshot["malicious"]
)

l3.metric(
    "Attack Families",
    learning_snapshot["families"]
)

l4.metric(
    "Avg KB Confidence",
    learning_snapshot["avg_confidence"]
)

if not learning_snapshot["recent"].empty:
    st.dataframe(
        _safe_table(learning_snapshot["recent"]),
        width="stretch",
        height=180
    )
else:
    st.info(
        "The knowledge base has not learned a reusable behavior pattern yet."
    )

st.markdown("---")

st.subheader(
    "AI Model Intelligence"
)

ai1, ai2, ai3 = st.columns([1, 1, 1])

with ai1:
    st.metric(
        "Training Rows",
        model_trained_rows
    )
    st.metric(
        "Validation Accuracy",
        _format_percent(model_accuracy)
    )

with ai2:
    if model_labels:
        label_df = pd.DataFrame(
            [
                {
                    "label": label,
                    "rows": count
                }
                for label, count in model_labels.items()
            ]
        )
        fig = px.bar(
            label_df,
            x="label",
            y="rows",
            title="Training Class Mix",
            color="label",
            color_discrete_map={
                "normal": "#22c55e",
                "suspicious": "#f59e0b",
                "worm": "#ef4444",
                "forkbomb": "#a855f7"
            }
        )
        fig.update_layout(
            showlegend=False,
            height=260,
            margin=dict(l=10, r=10, t=45, b=10)
        )
        st.plotly_chart(
            fig,
            width="stretch"
        )
    else:
        st.info(
            "Model metadata not available yet."
        )

with ai3:
    if not model_top_features.empty:
        fig = px.bar(
            model_top_features.head(8),
            x="importance",
            y="feature",
            orientation="h",
            title="Most Important Features",
            color="importance",
            color_continuous_scale="Teal"
        )
        fig.update_layout(
            height=260,
            margin=dict(l=10, r=10, t=45, b=10),
            yaxis={"categoryorder": "total ascending"}
        )
        st.plotly_chart(
            fig,
            width="stretch"
        )
    else:
        st.info(
            "Feature importance will appear after training."
        )

ai4, ai5 = st.columns(2)

with ai4:
    if not behavior_df.empty:
        fig = px.bar(
            behavior_df.head(10),
            x="count",
            y="behavior",
            orientation="h",
            title="Active Behavior Signals",
            color="count",
            color_continuous_scale="OrRd"
        )
        fig.update_layout(
            height=320,
            margin=dict(l=10, r=10, t=45, b=10),
            yaxis={"categoryorder": "total ascending"}
        )
        st.plotly_chart(
            fig,
            width="stretch"
        )
    else:
        st.success(
            "No active ML behavior signals in the current live window."
        )

with ai5:
    if not driver_df.empty:
        st.dataframe(
            _safe_table(
                driver_df.sort_values(
                    "impact",
                    ascending=False
                ).head(12)
            ),
            width="stretch",
            height=320
        )
    else:
        st.info(
            "Top prediction drivers will appear after new ML-scored logs arrive."
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
                },
                "bar": {"color": "#5eead4"},
                "steps": [
                    {"range": [0, 40], "color": "#3f1d24"},
                    {"range": [40, 70], "color": "#3b3116"},
                    {"range": [70, 100], "color": "#123326"}
                ],
                "threshold": {
                    "line": {"color": "#f8fafc", "width": 3},
                    "thickness": 0.75,
                    "value": health_score
                }
            }
        )
    )
    fig.update_layout(
        height=340,
        margin=dict(l=20, r=20, t=45, b=20)
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
        "Threat Severity",

        color=sev.index,

        color_discrete_map={
            "low": "#22c55e",
            "medium": "#f59e0b",
            "high": "#f97316",
            "critical": "#ef4444"
        }
    )
    fig.update_layout(
        height=340,
        margin=dict(l=20, r=20, t=45, b=20)
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
        _safe_table(display_df),
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

            _safe_table(latest_entity[
                entity_cols
            ])

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

            _safe_table(worm_df[
                worm_cols
            ]),

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
            _safe_table(kb_top[display_cols]),
            width="stretch",
            height=360
        )

        with st.expander("Knowledge Base Raw Patterns"):
            st.dataframe(
                _safe_table(kb.sort_values("observations", ascending=False)),
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
                _safe_table(learning_df),
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

        _safe_table(latest[
            audit_cols
        ])

        .sort_values(
            "worm_score",
            ascending=False
        ),

        width="stretch",
        height=500
    )
