import streamlit as st
import pandas as pd
import json
import time

LOG_FILE = "logs/system_log.json"

# ---------------------------
# PAGE CONFIG
# ---------------------------
st.set_page_config(page_title="Cyber Defense Dashboard", layout="wide")

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

REFRESH = 2

# ---------------------------
# LOAD DATA
# ---------------------------
def load_logs():
    data = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                data.append(json.loads(line))
    except:
        pass
    return pd.DataFrame(data)


while True:
    df = load_logs()

    if df.empty:
        st.warning("No logs yet...")
        time.sleep(REFRESH)
        st.rerun()

    df = df[df["pid"].notnull()]
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    latest = df.sort_values("timestamp").groupby("pid").tail(1)

    # ---------------------------
    # 🔥 KPI CARDS
    # ---------------------------
    col1, col2, col3, col4 = st.columns(4)

    avg_cpu = round(latest["cpu"].mean(), 2)
    avg_mem = round(latest["memory"].mean(), 2)

    flagged = latest[latest["actions"].apply(lambda x: x["cpu"] != "normal")]

    col1.metric("💻 Avg CPU", f"{avg_cpu}%")
    col2.metric("🧠 Avg Memory", f"{avg_mem}%")
    col3.metric("🚨 Threats", len(flagged))
    col4.metric("⚙️ Processes", len(latest))

    st.markdown("---")

    # ---------------------------
    # 📊 LIVE TABLE
    # ---------------------------
    st.subheader("📊 Live Processes")

    latest = latest.sort_values("cpu", ascending=False)

    def highlight(row):
        if row["actions"]["cpu"] != "normal":
            return ["background-color: red"] * len(row)
        return [""] * len(row)

    st.dataframe(latest[[
        "pid", "name", "cpu", "memory", "connections", "file_events"
    ]])

    # ---------------------------
    # 🚨 ALERT PANEL
    # ---------------------------
    st.subheader("🚨 Threat Monitor")

    if not flagged.empty:
        for _, row in flagged.iterrows():
            st.error(f"⚠️ PID {row['pid']} | CPU: {row['cpu']} | STATUS: {row['actions']['cpu']}")
    else:
        st.success("System Stable")

    # ---------------------------
    # 📈 CHARTS
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
    # 🔍 DETAILS PANEL
    # ---------------------------
    st.subheader("🔍 Deep Inspection")

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

    time.sleep(REFRESH)
    st.rerun()