# AI-Based Network Intrusion Detection System (NIDS)

This project is an AI-based NIDS that monitors network traffic and identifies suspicious activities in real-time using statistical anomaly detection.

## Features
- **Real-time Monitoring:** Capture live network traffic using Scapy.
- **Simulated Mode:** Test the system without root privileges using simulated traffic.
- **Anomaly Detection:** Identify volume-based spikes using a 3-sigma statistical rule.
- **Visual Dashboard:** Real-time graphs for traffic volume, protocol distribution, and top IPs.
- **Security Logs:** Detailed logs of detected anomalies.

## Installation

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt plotly
   ```

## Running the App

Start the Streamlit dashboard:
```bash
streamlit run app.py
```

*Note: For live sniffing, you may need to run as root or set specific capabilities on the python binary.*

## Project Structure
- `app.py`: Main Streamlit application and UI.
- `sniffer.py`: Packet capture logic (Live & Simulated).
- `detector.py`: Statistical anomaly detection logic.
- `test_core.py`: Verification tests for modules.
