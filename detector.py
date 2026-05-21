import numpy as np
from datetime import datetime

class AnomalyDetector:
    def __init__(self, window_size=50, threshold_sigma=5, min_packets=150):
        self.window_size = window_size
        self.threshold_sigma = threshold_sigma
        self.min_packets = min_packets
        self.history = []

    def check_anomaly(self, current_value):
        # We need a bit more history to make a reliable prediction
        if len(self.history) < 10:
            self.history.append(current_value)
            return False, 0
        
        mean = np.mean(self.history)
        std = np.std(self.history)
        
        # Use a higher threshold to avoid "jumpy" alerts
        threshold = mean + self.threshold_sigma * std
        
        # Only flag if it's above the statistical threshold AND a significant volume
        is_anomaly = current_value > threshold and current_value > self.min_packets
        
        self.history.append(current_value)
        if len(self.history) > self.window_size:
            self.history.pop(0)
            
        return is_anomaly, threshold

    def get_alert_message(self, value, threshold):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "time": timestamp,
            "type": "Volume Spike",
            "severity": "High" if value > threshold * 2 else "Medium",
            "message": f"Detected unusual traffic spike: {value} packets (Threshold: {threshold:.2f})"
        }
