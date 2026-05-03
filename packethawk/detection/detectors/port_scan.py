from collections  import defaultdict, Counter
from packethawk.capture.models import PacketSummary, Alert
from typing import List
import yaml

def get_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def detect_port_scan(packets: List[PacketSummary]) -> List[Alert]:
    """
    Detect port scans — one IP hitting threshold+
    unique destination ports within window_seconds.

    Uses Counter to count unique ports per source IP.
    Uses a time window to only look at recent packets.
    """
    config    = get_config()
    threshold = config["detection"]["port_scan"]["threshold"]
    window    = config["detection"]["port_scan"]["window_seconds"]
    severity  = config["detection"]["port_scan"]["severity"]

    # Group packets by source IP
    # defaultdict(list) means: if key doesn't exist, create empty list
    ip_packets = defaultdict(list)
    for pkt in packets:
        if pkt.src_ip and pkt.dst_port:
            ip_packets[pkt.src_ip].append(pkt)

    alerts = []

    for src_ip, pkts in ip_packets.items():
        # Sort by timestamp so we can apply sliding window
        pkts.sort(key=lambda p: p.timestamp)

        for i, pkt in enumerate(pkts):
            # Find all packets from same IP within time window
            window_pkts = [
                p for p in pkts[i:]
                if (p.timestamp - pkt.timestamp).total_seconds() <= window
            ]

            # Count unique destination ports in this window
            # Counter({'80': 5, '443': 3, '22': 1}) etc
            port_counter  = Counter(p.dst_port for p in window_pkts)
            unique_ports  = len(port_counter)

            if unique_ports >= threshold:
                duration = (
                    window_pkts[-1].timestamp - window_pkts[0].timestamp
                ).total_seconds()

                alerts.append(Alert(
                    rule_name   = "port_scan",
                    severity    = severity,
                    src_ip      = src_ip,
                    description = (
                        f"Port scan from {src_ip} — "
                        f"{unique_ports} ports in {duration:.1f}s "
                        f"(ports: {sorted(list(port_counter.keys()))[:5]}...)"
                    ),
                ))
                break  # one alert per IP is enough

    return alerts