import numpy as np
from datetime import datetime

class AnomalyDetector:
    def __init__(self, window_size=50, threshold_sigma=5, min_packets=150):
        self.window_size = window_size
        self.threshold_sigma = threshold_sigma
        self.min_packets = min_packets
        self.history = []

    def check_anomaly(self, current_value, ip_stats=None):
        # 1. Volume-based anomaly detection (DDoS/Flood)
        is_volume_anomaly = False
        threshold = 0
        if len(self.history) >= 10:
            mean = np.mean(self.history)
            std = np.std(self.history)
            threshold = mean + self.threshold_sigma * std
            is_volume_anomaly = current_value > threshold and current_value > self.min_packets
        
        self.history.append(current_value)
        if len(self.history) > self.window_size:
            self.history.pop(0)

        # 2. Behavior-based anomaly detection (Port Scan)
        is_scan_anomaly = False
        offending_ip = None
        if ip_stats:
            # If a single IP is responsible for more than 70% of traffic AND it's high volume
            for ip, count in ip_stats.items():
                if count > (current_value * 0.7) and count > 50:
                    is_scan_anomaly = True
                    offending_ip = ip
                    break
            
        return is_volume_anomaly, is_scan_anomaly, threshold, offending_ip

    def get_alert_message(self, type, value, threshold=0, ip=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if type == "volume":
            return {
                "time": timestamp,
                "type": "Traffic Flood",
                "severity": "High" if value > threshold * 2 else "Medium",
                "message": f"Volume spike: {value} pkts/s (Limit: {threshold:.1f})",
                "ip": "Multiple"
            }
        else:
            return {
                "time": timestamp,
                "type": "Port Scan",
                "severity": "Critical",
                "message": f"Host {ip} suspicious activity detected!",
                "ip": ip
            }
