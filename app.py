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

if 'blocked_count' not in st.session_state:
    st.session_state.blocked_count = 0

# --- Sidebar ---
st.sidebar.title("NIDS Control Panel")
mode = st.sidebar.radio("Operation Mode", ["Live Sniffing", "Simulated Traffic"])
is_simulated = (mode == "Simulated Traffic")

# Active Response Toggle
active_response = st.sidebar.toggle("Enable Active Response (IPS Mode)", value=True)

if st.sidebar.button("Start Monitoring"):
    if not st.session_state.monitoring:
        st.session_state.sniffer.start(simulated=is_simulated)
        st.session_state.monitoring = True

if st.sidebar.button("Stop Monitoring"):
    if st.session_state.monitoring:
        st.session_state.sniffer.stop()
        st.session_state.monitoring = False

st.sidebar.divider()
if is_simulated and st.session_state.monitoring:
    st.sidebar.subheader("Attack Simulations")
    if st.sidebar.button("🔍 Simulate Port Scan"):
        st.session_state.sniffer.set_attack_mode('port_scan')
    if st.sidebar.button("🌊 Simulate SYN Flood"):
        st.session_state.sniffer.set_attack_mode('syn_flood')
    if st.sidebar.button("✅ Reset Traffic"):
        st.session_state.sniffer.set_attack_mode(None)

st.sidebar.divider()
st.sidebar.info(f"Blocked IPs: {st.session_state.blocked_count}")
if st.sidebar.button("Clear Blocklist"):
    st.session_state.sniffer.blocked_ips.clear()
    st.session_state.blocked_count = 0

# --- Main UI ---
st.title("🛡️ AI-Based Network Intrusion Detection & Prevention System")

# Top Metrics
m1, m2, m3, m4 = st.columns(4)
packet_metric = m1.empty()
attack_metric = m2.empty()
block_metric = m3.empty()
status_metric = m4.empty()

# ... (Layout remains same)

# --- Real-Time Loop ---
if st.session_state.monitoring:
    while st.session_state.monitoring:
        stats = st.session_state.sniffer.get_stats()
        count = stats['count']
        
        # Detect Anomaly
        is_vol, is_scan, threshold, target_ip = st.session_state.detector.check_anomaly(count, stats['ips'])
        
        if is_vol:
            st.session_state.alerts.append(st.session_state.detector.get_alert_message("volume", count, threshold))
        
        if is_scan:
            st.session_state.alerts.append(st.session_state.detector.get_alert_message("scan", count, ip=target_ip))
            if active_response and target_ip:
                st.session_state.sniffer.block_ip(target_ip)
                st.session_state.blocked_count = len(st.session_state.sniffer.blocked_ips)
        
        # Update History
        st.session_state.traffic_history.append(count)
        if len(st.session_state.traffic_history) > 50:
            st.session_state.traffic_history.pop(0)
            
        # Update UI Metrics
        packet_metric.metric("Current Traffic", f"{count} pkts/s")
        attack_metric.metric("Total Alerts", len(st.session_state.alerts))
        block_metric.metric("Blocked IPs", st.session_state.blocked_count)
        sys_status = "SECURE" if not (is_vol or is_scan) else "ATTACK"
        status_metric.metric("System Status", sys_status, delta=None if sys_status == "SECURE" else "ALERT")

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
