import streamlit as st
import pandas as pd
import json
import time

LOG_FILE = "logs/system_log.json"

st.set_page_config(page_title="Cyber Defense Dashboard", layout="wide")

st.title("🛡️ Self-Healing Cyber Defense Dashboard")

REFRESH = 2


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

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Latest snapshot
    latest = df.sort_values("timestamp").groupby("pid").tail(1)

    # -------------------------------
    # 📊 LIVE PROCESS TABLE
    # -------------------------------
    st.subheader("📊 Live Processes")

    st.dataframe(latest[[
        "pid", "name", "cpu", "memory", "connections", "file_events"
    ]])

    # -------------------------------
    # 🚨 FLAGGED PROCESSES
    # -------------------------------
    st.subheader("🚨 Flagged Processes")

    flagged = latest[
        latest["actions"].apply(lambda x: x["cpu"] != "normal")
    ]

    if not flagged.empty:
        st.dataframe(flagged[[
            "pid", "name", "cpu", "memory"
        ]])
    else:
        st.success("No threats detected")

    # -------------------------------
    # 📈 SELECT PROCESS FOR CHARTS
    # -------------------------------
    st.subheader("📈 Process Behavior Charts")

    pid_list = latest["pid"].tolist()

    selected_pid = st.selectbox("Select PID", pid_list)

    proc_df = df[df["pid"] == selected_pid].sort_values("timestamp")

    # -------------------------------
    # 📊 CPU CHART
    # -------------------------------
    st.subheader("CPU Usage Over Time")
    st.line_chart(proc_df.set_index("timestamp")["cpu"])

    # -------------------------------
    # 📊 MEMORY CHART
    # -------------------------------
    st.subheader("Memory Usage Over Time")
    st.line_chart(proc_df.set_index("timestamp")["memory"])

    # -------------------------------
    # 📊 ANOMALY CHART
    # -------------------------------
    st.subheader("Anomaly Trend")

    anomaly_df = proc_df["anomalies"].apply(pd.Series)
    anomaly_df.index = proc_df["timestamp"]

    st.line_chart(anomaly_df)

    # -------------------------------
    # 📊 TRUST CHART
    # -------------------------------
    st.subheader("Trust Evolution")

    trust_df = proc_df["trust"].apply(pd.Series)
    trust_df.index = proc_df["timestamp"]

    st.line_chart(trust_df)

    # -------------------------------
    # 🔍 DETAILS
    # -------------------------------
    st.subheader("🔍 Current State")

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