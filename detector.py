import numpy as np
from datetime import datetime

class AnomalyDetector:
    def __init__(self, window_size=20, threshold_sigma=3):
        self.window_size = window_size
        self.threshold_sigma = threshold_sigma
        self.history = []

    def check_anomaly(self, current_value):
        if len(self.history) < 5:
            self.history.append(current_value)
            return False, 0
        
        mean = np.mean(self.history)
        std = np.std(self.history)
        
        threshold = mean + self.threshold_sigma * std
        
        is_anomaly = current_value > threshold and current_value > 10
        
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
