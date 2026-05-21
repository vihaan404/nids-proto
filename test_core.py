from sniffer import PacketSniffer
from detector import AnomalyDetector
import time
import random

def test_detector():
    print("Testing Anomaly Detector...")
    # Using low thresholds for testing purposes to trigger the alert
    detector = AnomalyDetector(window_size=10, threshold_sigma=2, min_packets=50)
    
    # Simulate normal traffic
    for _ in range(10):
        val = random.randint(5, 15)
        is_anomaly, threshold = detector.check_anomaly(val)
        print(f"Val: {val}, Threshold: {threshold:.2f}, Anomaly: {is_anomaly}")
    
    # Simulate a spike that exceeds the min_packets (50)
    spike = 100
    is_anomaly, threshold = detector.check_anomaly(spike)
    print(f"SPIKE: {spike}, Threshold: {threshold:.2f}, Anomaly: {is_anomaly}")
    assert is_anomaly == True, "Spike should be detected as anomaly"
    print("Anomaly Detector test passed!")

def test_sniffer_simulated():
    print("\nTesting Sniffer (Simulated)...")
    sniffer = PacketSniffer(simulated=True)
    sniffer.start()
    time.sleep(2)
    stats = sniffer.get_stats()
    print(f"Stats after 2s: {stats}")
    assert stats['count'] > 0, "Simulated sniffer should generate packets"
    assert len(stats['protocols']) > 0, "Simulated protocols should be recorded"
    sniffer.stop()
    print("Sniffer simulated test passed!")

if __name__ == "__main__":
    test_detector()
    test_sniffer_simulated()
