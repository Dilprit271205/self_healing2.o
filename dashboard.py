import streamlit as st
import pandas as pd
import ast

from streamlit_autorefresh import st_autorefresh

LOG_FILE = "logs/system_log.json"

# ---------------------------
# CONFIG
# ---------------------------
st.set_page_config(page_title="Cyber Defense Dashboard", layout="wide")

# ✅ Balanced refresh (no lag)
st_autorefresh(interval=5000, key="refresh")

st.title("🛡️ Self-Healing Cyber Defense System")

# ---------------------------
# LOAD DATA
# ---------------------------
@st.cache_data(ttl=5)
def load_logs():
    try:
        df = pd.read_json(LOG_FILE, lines=True)
        return df.tail(300)
    except:
        return pd.DataFrame()

df = load_logs()

if df.empty:
    st.warning("No logs yet...")
    st.stop()

# ---------------------------
# CLEAN
# ---------------------------
df = df[df["pid"].notnull()]
df["timestamp"] = pd.to_datetime(df["timestamp"])

latest = df.sort_values("timestamp").groupby("pid").tail(1)
latest = latest.reset_index(drop=True)

# ---------------------------
# EXPAND JSON
# ---------------------------
trust_expanded = pd.json_normalize(latest["trust"])
anomaly_expanded = pd.json_normalize(latest["anomalies"])

latest = pd.concat([latest, trust_expanded, anomaly_expanded], axis=1)
latest = latest.loc[:, ~latest.columns.duplicated()]

# ---------------------------
# ACTION LEVEL
# ---------------------------
def get_level(action):
    try:
        if isinstance(action, dict):
            return action.get("level", "normal")
        if isinstance(action, str):
            return ast.literal_eval(action).get("level", "normal")
    except:
        return "normal"
    return "normal"

latest["level"] = latest["actions"].apply(get_level)

suspicious = latest[latest["level"] == "suspicious"]
critical = latest[latest["level"] == "critical"]

# ---------------------------
# KPIs
# ---------------------------
col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("💻 Avg CPU", f"{round(latest['cpu'].mean(), 2)}%")
col2.metric("🧠 Avg Memory", f"{round(latest['memory'].mean(), 2)}%")
col3.metric("🚨 Threats", len(latest[latest["level"] != "normal"]))
col4.metric("⚙️ Processes", len(latest))
col5.metric("🟢 Health", f"{round(latest['final_trust'].mean()*100, 2)}%")

st.markdown("---")

# ---------------------------
# GLOBAL TRENDS (FIXED)
# ---------------------------
col1, col2 = st.columns(2)

df_sorted = df.sort_values("timestamp")

with col1:
    st.subheader("🔥 CPU Load Over Time")
    st.line_chart(df_sorted.set_index("timestamp")["cpu"])

with col2:
    st.subheader("🧠 Memory Usage Over Time")
    st.line_chart(df_sorted.set_index("timestamp")["memory"])

# ---------------------------
# TRUST DISTRIBUTION
# ---------------------------
st.subheader("🧠 Trust Score Distribution")
st.bar_chart(latest[["static_trust", "dynamic_trust", "final_trust"]])

# ---------------------------
# PROCESS TABLE
# ---------------------------
st.subheader("📊 Process Trust Table")

display_cols = [
    "pid", "name",
    "cpu", "memory",
    "connections", "file_events",
    "static_trust", "dynamic_trust", "final_trust"
]

def highlight(row):
    if row["final_trust"] < 0.4:
        return ["background-color: rgba(255,0,0,0.3)"] * len(row)
    elif row["final_trust"] < 0.7:
        return ["background-color: rgba(255,165,0,0.3)"] * len(row)
    return [""] * len(row)

try:
    styled = latest[display_cols].sort_values("final_trust").style.apply(highlight, axis=1)
    st.dataframe(styled, height=400, use_container_width=True)
except:
    st.dataframe(
        latest[display_cols].sort_values("final_trust"),
        height=400,
        use_container_width=True
    )

# ---------------------------
# ALERT PANEL
# ---------------------------
st.subheader("🚨 Threat Monitor")

if not critical.empty:
    for _, row in critical.iterrows():
        st.error(f"🔥 CRITICAL | PID {row['pid']} ({row['name']}) | Trust: {row['final_trust']}")

if not suspicious.empty:
    for _, row in suspicious.iterrows():
        st.warning(f"⚠️ SUSPICIOUS | PID {row['pid']} ({row['name']}) | Trust: {row['final_trust']}")

if critical.empty and suspicious.empty:
    st.success("✅ System Stable")

# ---------------------------
# PROCESS ANALYTICS
# ---------------------------
st.subheader("📈 Process Deep Dive")

pid_list = latest["pid"].tolist()
selected_pid = st.selectbox("Select Process", pid_list)

proc_df = df[df["pid"] == selected_pid].sort_values("timestamp")

if not proc_df.empty:
    trust_df = pd.json_normalize(proc_df["trust"])
    trust_df.index = proc_df["timestamp"]

    anomaly_df = pd.json_normalize(proc_df["anomalies"])
    anomaly_df.index = proc_df["timestamp"]

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("CPU Trend")
        st.line_chart(proc_df.set_index("timestamp")["cpu"])

    with col2:
        st.subheader("Memory Trend")
        st.line_chart(proc_df.set_index("timestamp")["memory"])

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Trust Evolution")
        st.line_chart(trust_df[["static_trust", "dynamic_trust", "final_trust"]])

    with col2:
        st.subheader("Anomaly Signals")
        st.line_chart(anomaly_df)

# ---------------------------
# DEEP INSPECTION
# ---------------------------
st.subheader("🔍 Deep Inspection")

if not proc_df.empty:
    latest_row = proc_df.iloc[-1]

    st.json({
        "features": {
            "cpu": latest_row["cpu"],
            "memory": latest_row["memory"],
            "connections": latest_row["connections"],
            "file_events": latest_row["file_events"],
            "static_trust": latest_row["trust"]["static_trust"]
        },
        "anomalies": latest_row["anomalies"],
        "trust": latest_row["trust"],
        "actions": latest_row["actions"]
    })