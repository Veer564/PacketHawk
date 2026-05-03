from collections import defaultdict
from packethawk.capture.models import PacketSummary, Alert
from typing import List
import yaml

def get_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def detect_traffic_spike(packets: List[PacketSummary]) -> List[Alert]:
    """
    Detect traffic volume spikes from a single IP.

    How it works:
    1. Split time into 1-second buckets
    2. Calculate average packets/second for each IP
    3. If any second has multiplier x the average — alert

    Example: IP normally sends 10 pkts/sec
             Suddenly sends 50 pkts/sec = 5x spike = DDoS/scan
    """
    config     = get_config()
    multiplier = config["detection"]["traffic_spike"]["multiplier"]
    severity   = config["detection"]["traffic_spike"]["severity"]

    # Group packets by source IP and second bucket
    # { "1.2.3.4": { "14:30:01": 5, "14:30:02": 8, ... } }
    ip_time_buckets = defaultdict(lambda: defaultdict(int))

    for pkt in packets:
        if pkt.src_ip:
            # Round timestamp to nearest second as bucket key
            bucket = pkt.timestamp.strftime("%H:%M:%S")
            ip_time_buckets[pkt.src_ip][bucket] += 1

    alerts = []

    for src_ip, buckets in ip_time_buckets.items():
        counts = list(buckets.values())

        if len(counts) < 3:
            # Need at least 3 seconds of data to establish baseline
            continue

        average = sum(counts) / len(counts)

        if average < 2:
            # Ignore very low traffic IPs
            continue

        max_count = max(counts)
        ratio     = max_count / average

        if ratio >= multiplier:
            peak_second = max(buckets, key=buckets.get)
            alerts.append(Alert(
                rule_name   = "traffic_spike",
                severity    = severity,
                src_ip      = src_ip,
                description = (
                    f"Traffic spike from {src_ip} — "
                    f"{ratio:.1f}x normal volume "
                    f"(peak: {max_count} pkts/s at {peak_second}, "
                    f"avg: {average:.1f} pkts/s)"
                ),
            ))

    return alerts