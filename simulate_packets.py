from packethawk.capture.models import PacketSummary
from datetime import datetime, timedelta
import random

def make_packet(src_ip, dst_ip, protocol="TCP",
                src_port=None, dst_port=None,
                src_mac=None, size=64,
                seconds_offset=0, dns_query=None):
    return PacketSummary(
        src_ip    = src_ip,
        dst_ip    = dst_ip,
        protocol  = protocol,
        size      = size,
        src_port  = src_port,
        dst_port  = dst_port,
        src_mac   = src_mac,
        dns_query = dns_query,
        timestamp = datetime.now() + timedelta(seconds=seconds_offset),
    )

def simulate_port_scan(attacker_ip="45.33.32.156", num_ports=20):
    """Simulate a port scan — one IP hitting many ports quickly."""
    print(f"[Simulator] Generating port scan from {attacker_ip}...")
    packets = []
    for i in range(num_ports):
        packets.append(make_packet(
            src_ip   = attacker_ip,
            dst_ip   = "192.168.1.100",
            protocol = "TCP",
            src_port = random.randint(40000, 60000),
            dst_port = random.randint(1, 1024),
            seconds_offset = i * 0.2,  # 0.2 seconds apart
        ))
    return packets

def simulate_arp_spoof(victim_ip="192.168.1.1"):
    """Simulate ARP spoofing — same IP with two different MACs."""
    print(f"[Simulator] Generating ARP spoof on {victim_ip}...")
    return [
        make_packet(victim_ip, "0.0.0.0", "ARP",
                    src_mac="aa:bb:cc:dd:ee:ff", seconds_offset=0),
        make_packet(victim_ip, "0.0.0.0", "ARP",
                    src_mac="aa:bb:cc:dd:ee:ff", seconds_offset=1),
        make_packet(victim_ip, "0.0.0.0", "ARP",
                    src_mac="11:22:33:44:55:66", seconds_offset=2),
    ]

def simulate_dns_tunnel(src_ip="10.0.0.5"):
    """Simulate DNS tunnelling — high entropy subdomain queries."""
    print(f"[Simulator] Generating DNS tunnel from {src_ip}...")
    tunnel_domains = [
        "aGVsbG8xMjM0NTY3.evil-tunnel.com",
        "d29ybGQtZG9taW5h.evil-tunnel.com",
        "dGVzdC1wYXlsb2Fk.c2.tcp.ngrok.io",
    ]
    packets = []
    for i, domain in enumerate(tunnel_domains):
        packets.append(make_packet(
            src_ip    = src_ip,
            dst_ip    = "8.8.8.8",
            protocol  = "UDP",
            src_port  = random.randint(1024, 65535),
            dst_port  = 53,
            dns_query = domain,
            seconds_offset = i,
        ))
    return packets

def simulate_traffic_spike(src_ip="103.21.244.0"):
    """Simulate traffic spike — sudden burst of packets."""
    print(f"[Simulator] Generating traffic spike from {src_ip}...")
    packets = []
    # Normal traffic — 3 packets per second for 5 seconds
    for sec in range(5):
        for _ in range(3):
            packets.append(make_packet(
                src_ip         = src_ip,
                dst_ip         = "192.168.1.100",
                seconds_offset = sec,
            ))
    # Spike — 50 packets in 1 second
    for _ in range(50):
        packets.append(make_packet(
            src_ip         = src_ip,
            dst_ip         = "192.168.1.100",
            seconds_offset = 6,
        ))
    return packets

def simulate_normal_traffic():
    """Simulate normal background traffic."""
    packets = []
    normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    for i in range(30):
        packets.append(make_packet(
            src_ip   = random.choice(normal_ips),
            dst_ip   = "8.8.8.8",
            protocol = random.choice(["TCP", "UDP"]),
            dst_port = random.choice([80, 443, 53]),
            seconds_offset = i * 0.5,
        ))
    return packets

def generate_all():
    packets = []
    packets += simulate_normal_traffic()
    packets += simulate_port_scan()
    packets += simulate_arp_spoof()
    packets += simulate_dns_tunnel()
    packets += simulate_traffic_spike()
    print(f"[Simulator] Total packets generated: {len(packets)}")
    return packets

if __name__ == "__main__":
    pkts = generate_all()
    print(f"\nSample packet: {pkts[0]}")