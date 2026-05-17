import streamlit as st
import pandas as pd
import numpy as np
import time
from sniffer import PacketSniffer
from detector import AnomalyDetector
import plotly.express as px

# --- Configuration ---
st.set_page_config(page_title="AI-Based NIDS", layout="wide")

# Initialize Session State
if 'sniffer' not in st.session_state:
    st.session_state.sniffer = PacketSniffer()
if 'detector' not in st.session_state:
    st.session_state.detector = AnomalyDetector()
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = []
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False

# --- Sidebar ---
st.sidebar.title("NIDS Control Panel")
mode = st.sidebar.radio("Operation Mode", ["Live Sniffing", "Simulated Traffic"])
is_simulated = (mode == "Simulated Traffic")

if st.sidebar.button("Start Real-Time Monitoring"):
    if not st.session_state.monitoring:
        st.session_state.sniffer.start(simulated=is_simulated)
        st.session_state.monitoring = True
        st.sidebar.success(f"Monitoring active ({mode})")

if st.sidebar.button("Stop Monitoring"):
    if st.session_state.monitoring:
        st.session_state.sniffer.stop()
        st.session_state.monitoring = False
        st.sidebar.warning("Monitoring stopped")

if is_simulated and st.session_state.monitoring:
    if st.sidebar.button("🔥 Simulate Attack Spike"):
        # We can directly inject a spike into the sniffer's count
        with st.session_state.sniffer.lock:
            st.session_state.sniffer.packet_count += 500
        st.sidebar.error("Attack spike injected!")

st.sidebar.divider()
st.sidebar.info("""
**System Info**
- Tech: Streamlit, Scapy, NumPy
- Method: Statistical Anomaly Detection
- Status: Volume-based Detection
""")

# --- Main UI ---
st.title("🛡️ AI-Based Network Intrusion Detection System")

# Top Metrics
m1, m2, m3, m4 = st.columns(4)
packet_metric = m1.empty()
attack_metric = m2.empty()
avg_size_metric = m3.empty()
status_metric = m4.empty()

# Layout
col_main, col_side = st.columns([2, 1])

with col_main:
    st.subheader("Traffic Volume (Packets/sec)")
    chart_placeholder = st.empty()
    
    st.subheader("Security Incident Logs")
    log_placeholder = st.empty()

with col_side:
    st.subheader("Protocol Distribution")
    proto_chart_placeholder = st.empty()
    
    st.subheader("Top IP Addresses")
    ip_table_placeholder = st.empty()

# --- Real-Time Loop ---
if st.session_state.monitoring:
    while st.session_state.monitoring:
        stats = st.session_state.sniffer.get_stats()
        count = stats['count']
        
        # Detect Anomaly
        is_anomaly, threshold = st.session_state.detector.check_anomaly(count)
        if is_anomaly:
            alert = st.session_state.detector.get_alert_message(count, threshold)
            st.session_state.alerts.append(alert)
        
        # Update History
        st.session_state.traffic_history.append(count)
        if len(st.session_state.traffic_history) > 50:
            st.session_state.traffic_history.pop(0)
            
        # Update UI Metrics
        packet_metric.metric("Current Traffic", f"{count} pkts/s")
        attack_metric.metric("Total Alerts", len(st.session_state.alerts))
        avg_size_metric.metric("Avg Packet Size", f"{stats['avg_size']:.1f} bytes")
        status_metric.metric("System Status", "SECURE" if not is_anomaly else "ATTACK", delta=None if not is_anomaly else "ALERT")

        # Update Charts
        chart_placeholder.line_chart(st.session_state.traffic_history)
        
        if stats['protocols']:
            proto_df = pd.DataFrame(list(stats['protocols'].items()), columns=['Protocol', 'Count'])
            fig = px.pie(proto_df, values='Count', names='Protocol', hole=.3)
            fig.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=200)
            proto_chart_placeholder.plotly_chart(fig, use_container_width=True)
            
        if stats['ips']:
            ip_df = pd.DataFrame(list(stats['ips'].items()), columns=['IP Address', 'Count'])
            ip_table_placeholder.table(ip_df)
            
        # Update Logs
        if st.session_state.alerts:
            log_df = pd.DataFrame(st.session_state.alerts).tail(10)
            # Reorder columns for better display
            log_df = log_df[['time', 'type', 'severity', 'message']]
            log_placeholder.dataframe(log_df, use_container_width=True)
        
        time.sleep(1)
else:
    st.info("Click 'Start Real-Time Monitoring' in the sidebar to begin.")
    # Show static data if any
    if st.session_state.traffic_history:
        chart_placeholder.line_chart(st.session_state.traffic_history)
    if st.session_state.alerts:
        log_df = pd.DataFrame(st.session_state.alerts).tail(10)
        log_placeholder.dataframe(log_df, use_container_width=True)
