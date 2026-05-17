import threading
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import time

class PacketSniffer:
    def __init__(self, simulated=False):
        self.sniffing = False
        self.simulated = simulated
        self.packet_count = 0
        self.protocols = Counter()
        self.ips = Counter()
        self.packet_sizes = []
        self.lock = threading.Lock()

    def _packet_callback(self, packet):
        if not self.sniffing:
            return
        
        with self.lock:
            self.packet_count += 1
            if packet.haslayer(IP):
                self.ips[packet[IP].src] += 1
                self.ips[packet[IP].dst] += 1
                
                if packet.haslayer(TCP):
                    self.protocols['TCP'] += 1
                elif packet.haslayer(UDP):
                    self.protocols['UDP'] += 1
                else:
                    self.protocols['Other'] += 1
            
            if hasattr(packet, 'len'):
                self.packet_sizes.append(packet.len)
                if len(self.packet_sizes) > 1000:
                    self.packet_sizes.pop(0)

    def start(self, simulated=None):
        if simulated is not None:
            self.simulated = simulated
        self.sniffing = True
        self.packet_count = 0
        if self.simulated:
            self.thread = threading.Thread(target=self._run_simulated, daemon=True)
        else:
            self.thread = threading.Thread(target=self._run_sniff, daemon=True)
        self.thread.start()

    def _run_sniff(self):
        try:
            sniff(prn=self._packet_callback, store=0)
        except Exception as e:
            print(f"Error sniffing: {e}")
            self.sniffing = False

    def _run_simulated(self):
        import random
        while self.sniffing:
            time.sleep(random.uniform(0.01, 0.1))
            with self.lock:
                self.packet_count += 1
                self.protocols[random.choice(['TCP', 'UDP', 'Other'])] += 1
                self.ips[f"192.168.1.{random.randint(1, 254)}"] += 1
                self.packet_sizes.append(random.randint(40, 1500))
                if len(self.packet_sizes) > 1000:
                    self.packet_sizes.pop(0)

    def stop(self):
        self.sniffing = False

    def get_stats(self):
        with self.lock:
            stats = {
                "count": self.packet_count,
                "protocols": dict(self.protocols),
                "ips": dict(self.ips.most_common(10)),
                "avg_size": sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            }
            # Reset count for interval-based tracking
            self.packet_count = 0
            return stats
