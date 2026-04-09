import streamlit as st
import pandas as pd
import json

from streamlit_autorefresh import st_autorefresh

LOG_FILE = "logs/system_log.json"

# ---------------------------
# PAGE CONFIG
# ---------------------------
st.set_page_config(page_title="Cyber Defense Dashboard", layout="wide")

# ---------------------------
# AUTO REFRESH (1 sec)
# ---------------------------
st_autorefresh(interval=1000, key="refresh")

# ---------------------------
# DARK THEME STYLE
# ---------------------------
st.markdown("""
<style>
body {
    background-color: #0f172a;
    color: white;
}
.metric-card {
    padding: 20px;
    border-radius: 12px;
    background: linear-gradient(135deg, #1e293b, #0f172a);
    box-shadow: 0px 0px 20px rgba(0,0,0,0.5);
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Self-Healing Cyber Defense System")

# ---------------------------
# LOAD DATA (FAST)
# ---------------------------
@st.cache_data(ttl=1)
def load_logs():
    data = []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-500:]  # only last 500 logs
            for line in lines:
                data.append(json.loads(line))
    except:
        pass
    return pd.DataFrame(data)


df = load_logs()

# ---------------------------
# EMPTY STATE
# ---------------------------
if df.empty:
    st.warning("No logs yet...")
    st.stop()

# ---------------------------
# CLEAN DATA
# ---------------------------
df = df[df["pid"].notnull()]
df["timestamp"] = pd.to_datetime(df["timestamp"])

latest = df.sort_values("timestamp").groupby("pid").tail(1)

# ---------------------------
# KPI SECTION
# ---------------------------
col1, col2, col3, col4, col5 = st.columns(5)

avg_cpu = round(latest["cpu"].mean(), 2)
avg_mem = round(latest["memory"].mean(), 2)

flagged = latest[
    (latest["actions"].apply(lambda x: x["cpu"] != "normal")) |
    (latest["actions"].apply(lambda x: x["net"] != "normal")) |
    (latest["actions"].apply(lambda x: x["file"] != "normal"))
]

# System Health Score
health = round(
    latest["trust"].apply(lambda x: sum(x.values()) / len(x)).mean() * 100, 2
)

col1.metric("💻 Avg CPU", f"{avg_cpu}%")
col2.metric("🧠 Avg Memory", f"{avg_mem}%")
col3.metric("🚨 Threats", len(flagged))
col4.metric("⚙️ Processes", len(latest))
col5.metric("🟢 Health", f"{health}%")

st.markdown("---")

# ---------------------------
# GLOBAL CPU TREND
# ---------------------------
st.subheader("🔥 System CPU Load")

cpu_trend = df.groupby("timestamp")["cpu"].mean()
st.line_chart(cpu_trend)

# ---------------------------
# LIVE PROCESS TABLE
# ---------------------------
st.subheader("📊 Live Processes")

latest = latest.sort_values("cpu", ascending=False)

def highlight(row):
    if row["cpu"] > 70:
        return ["background-color: rgba(255,0,0,0.3)"] * len(row)
    return [""] * len(row)

st.dataframe(
    latest[[
        "pid", "name", "cpu", "memory", "connections", "file_events"
    ]].style.apply(highlight, axis=1),
    height=400,
    width="stretch"
)

# ---------------------------
# ALERT PANEL
# ---------------------------
st.subheader("🚨 Threat Monitor")

if not flagged.empty:
    for _, row in flagged.iterrows():
        st.error(
            f"⚠️ PID {row['pid']} | CPU: {row['cpu']} | STATUS: {row['actions']}"
        )
else:
    st.success("✅ System Stable")

# ---------------------------
# PROCESS ANALYTICS
# ---------------------------
st.subheader("📈 Process Analytics")

pid_list = latest["pid"].tolist()
selected_pid = st.selectbox("Select Process", pid_list)

proc_df = df[df["pid"] == selected_pid].sort_values("timestamp")

col1, col2 = st.columns(2)

with col1:
    st.subheader("CPU Trend")
    st.line_chart(proc_df.set_index("timestamp")["cpu"])

with col2:
    st.subheader("Memory Trend")
    st.line_chart(proc_df.set_index("timestamp")["memory"])

# ---------------------------
# ANOMALY & TRUST
# ---------------------------
col1, col2 = st.columns(2)

with col1:
    st.subheader("Anomaly Trend")
    anomaly_df = proc_df["anomalies"].apply(pd.Series)
    anomaly_df.index = proc_df["timestamp"]
    st.line_chart(anomaly_df)

with col2:
    st.subheader("Trust Evolution")
    trust_df = proc_df["trust"].apply(pd.Series)
    trust_df.index = proc_df["timestamp"]
    st.line_chart(trust_df)

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
            "file_events": latest_row["file_events"]
        },
        "anomalies": latest_row["anomalies"],
        "trust": latest_row["trust"],
        "actions": latest_row["actions"]
    })