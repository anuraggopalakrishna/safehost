import streamlit as st
import sqlite3
import pandas as pd
import time
from datetime import datetime, timedelta

DB_PATH = "network_traffic.db"
REFRESH_INTERVAL = 5  # seconds

st.set_page_config(page_title="Live Network Threat Dashboard", layout="wide")

st.title("🔐 Network Threat Dashboard")
st.markdown("Real-time monitoring with ML-based classification.")

# Sidebar
st.sidebar.header("Controls")
refresh = st.sidebar.button("🔄 Refresh Now")
st.sidebar.write(f"Auto-refreshing every {REFRESH_INTERVAL} seconds")


# Connect to DB
@st.cache_data(ttl=10)
def load_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        """
        SELECT *
        FROM flow_stats
        WHERE timestamp >= datetime('now', '-5 minutes')
        ORDER BY timestamp DESC
        LIMIT 500
    """,
        conn,
    )
    conn.close()
    return df


# Display data
df = load_data()

# Main metrics
col1, col2, col3 = st.columns(3)
col1.metric("Avg Flow Bytes/s", f"{df['flow_bytes_s'].mean():.2f}")
col2.metric("Total Packets", int(df["fwd_packets"].sum() + df["bwd_packets"].sum()))
col3.metric("Active Flows", df["flow_key"].nunique())

# Threat Meter
threat_label = df["label"].iloc[0] if not df.empty else "N/A"
confidence = df["prediction_confidence"].iloc[0] if not df.empty else 0.0

threat_level = "🟢 Normal"
if confidence > 0.9 and threat_label.lower() != "benign":
    threat_level = "🔴 Threat"
elif confidence > 0.6:
    threat_level = "🟡 Suspicious"

st.subheader("⚠️ Threat Meter")
st.markdown(
    f"""
### **{threat_level}**
- Label: {threat_label}
- Confidence: {confidence:.2f}
"""
)

# Show recent traffic
st.subheader("📊 Recent Flows")
st.dataframe(
    df[
        [
            "timestamp",
            "flow_key",
            "flow_bytes_s",
            "fwd_packets",
            "bwd_packets",
            "label",
            "prediction_confidence",
        ]
    ]
)

# Optional: Line chart
st.subheader("📈 Flow Bytes/s Over Time")
chart_df = df[["timestamp", "flow_bytes_s"]].copy()
chart_df["timestamp"] = pd.to_datetime(chart_df["timestamp"])
chart_df = chart_df.sort_values("timestamp")
st.line_chart(chart_df.rename(columns={"timestamp": "index"}).set_index("index"))

# Auto-refresh logic
if not refresh:
    time.sleep(REFRESH_INTERVAL)
    st.rerun()
