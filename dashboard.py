import streamlit as st
import pandas as pd
import json

from streamlit_autorefresh import st_autorefresh

LOG_FILE = "logs/system_log.json"

# ---------------------------
# CONFIG
# ---------------------------
st.set_page_config(page_title="Cyber Defense Dashboard", layout="wide")
st_autorefresh(interval=1000, key="refresh")

st.title("🛡️ Self-Healing Cyber Defense System")

# ---------------------------
# LOAD DATA
# ---------------------------
@st.cache_data(ttl=1)
def load_logs():
    data = []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-500:]
            for line in lines:
                data.append(json.loads(line))
    except:
        pass
    return pd.DataFrame(data)


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

# 🔥 FIX 1: Reset index
latest = latest.reset_index(drop=True)

# ---------------------------
# EXPAND TRUST + ANOMALIES
# ---------------------------
trust_expanded = latest["trust"].apply(pd.Series)
anomaly_expanded = latest["anomalies"].apply(pd.Series)

latest = pd.concat([latest, trust_expanded, anomaly_expanded], axis=1)

# 🔥 FIX 2: Remove duplicate columns
latest = latest.loc[:, ~latest.columns.duplicated()]

# ---------------------------
# THREAT CLASSIFICATION (NEW 🔥)
# ---------------------------
suspicious = latest[
    latest["actions"].apply(lambda x: x["level"] == "suspicious")
]

critical = latest[
    latest["actions"].apply(lambda x: x["level"] == "critical")
]

# total threats
threats = len(suspicious) + len(critical)

# ---------------------------
# KPIs
# ---------------------------
col1, col2, col3, col4, col5 = st.columns(5)

avg_cpu = round(latest["cpu"].mean(), 2)
avg_mem = round(latest["memory"].mean(), 2)
threats = len(
    latest[
        latest["actions"].apply(lambda x: x["level"] != "normal")
    ]
)
process_count = len(latest)
health = round(latest["final_trust"].mean() * 100, 2)

col1.metric("💻 Avg CPU", f"{avg_cpu}%")
col2.metric("🧠 Avg Memory", f"{avg_mem}%")
col3.metric("🚨 Threats", threats)
col4.metric("⚙️ Processes", process_count)
col5.metric("🟢 Health", f"{health}%")

st.markdown("---")

# ---------------------------
# GLOBAL TRENDS
# ---------------------------
col1, col2 = st.columns(2)

with col1:
    st.subheader("🔥 CPU Load Over Time")
    cpu_trend = df.groupby("timestamp")["cpu"].mean()
    st.line_chart(cpu_trend)

with col2:
    st.subheader("🧠 Memory Usage Over Time")
    mem_trend = df.groupby("timestamp")["memory"].mean()
    st.line_chart(mem_trend)

# ---------------------------
# TRUST DISTRIBUTION
# ---------------------------
st.subheader("🧠 Trust Score Distribution")
st.bar_chart(latest[["static_trust", "dynamic_trust", "final_trust"]])

# ---------------------------
# MAIN TABLE (SAFE)
# ---------------------------
st.subheader("📊 Process Trust Table")

display_cols = [
    "pid", "name",
    "cpu", "memory",
    "connections", "file_events",
    "static_trust", "dynamic_trust", "final_trust"
]

table_df = latest.copy()
table_df = table_df.reset_index(drop=True)
table_df = table_df.loc[:, ~table_df.columns.duplicated()]

def highlight(row):
    if row["final_trust"] < 0.4:
        return ["background-color: rgba(255,0,0,0.3)"] * len(row)
    elif row["final_trust"] < 0.7:
        return ["background-color: rgba(255,165,0,0.3)"] * len(row)
    return [""] * len(row)

# Try styling safely
try:
    styled = table_df[display_cols].sort_values("final_trust").style.apply(highlight, axis=1)
    st.dataframe(styled, height=400, width="stretch")
except:
    st.dataframe(
        table_df[display_cols].sort_values("final_trust"),
        height=400,
        width="stretch"
    )

# ---------------------------
# ALERT PANEL
# ---------------------------
st.subheader("🚨 Threat Monitor")

danger = table_df[table_df["final_trust"] < 0.7]

if not danger.empty:
    for _, row in danger.iterrows():
        st.error(f"⚠️ PID {row['pid']} ({row['name']}) | Trust: {row['final_trust']}")
else:
    st.success("✅ System Stable")

# ---------------------------
# PROCESS ANALYTICS
# ---------------------------
st.subheader("📈 Process Deep Dive")

pid_list = table_df["pid"].tolist()
selected_pid = st.selectbox("Select Process", pid_list)

proc_df = df[df["pid"] == selected_pid].sort_values("timestamp")

# Expand safely
trust_df = proc_df["trust"].apply(pd.Series)
trust_df.index = proc_df["timestamp"]

anomaly_df = proc_df["anomalies"].apply(pd.Series)
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