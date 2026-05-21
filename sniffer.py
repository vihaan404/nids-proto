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
        self.blocked_ips = set()
        self.lock = threading.Lock()
        self.attack_mode = None # Options: 'port_scan', 'syn_flood'

    def _packet_callback(self, packet):
        if not self.sniffing:
            return
        
        with self.lock:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                if src_ip in self.blocked_ips:
                    return # Drop packet from blocked IP

                self.packet_count += 1
                self.ips[src_ip] += 1
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

    def set_attack_mode(self, mode):
        with self.lock:
            self.attack_mode = mode

    def block_ip(self, ip):
        with self.lock:
            self.blocked_ips.add(ip)

    def _run_simulated(self):
        import random
        while self.sniffing:
            time.sleep(random.uniform(0.01, 0.1))
            with self.lock:
                mode = self.attack_mode
                
                # Normal background noise
                src_ip = f"192.168.1.{random.randint(1, 254)}"
                if src_ip in self.blocked_ips: continue

                if mode == 'port_scan':
                    # One IP hitting many "virtual" targets or ports
                    attacker_ip = "10.0.0.99"
                    if attacker_ip not in self.blocked_ips:
                        for _ in range(10): # Rapid fire
                            self.packet_count += 1
                            self.ips[attacker_ip] += 1
                            self.protocols['TCP'] += 1
                    
                elif mode == 'syn_flood':
                    # Many random IPs flooding with small TCP packets
                    for _ in range(20):
                        fake_ip = f"attacker-{random.randint(1, 1000)}"
                        self.packet_count += 1
                        self.ips[fake_ip] += 1
                        self.protocols['TCP'] += 1
                        self.packet_sizes.append(64) # Small SYN packets

                else:
                    # Default simulation
                    self.packet_count += 1
                    self.protocols[random.choice(['TCP', 'UDP', 'Other'])] += 1
                    self.ips[src_ip] += 1
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
                "blocked": list(self.blocked_ips),
                "avg_size": sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            }
            self.packet_count = 0 # Interval-based
            return stats
