from collections import defaultdict
from packethawk.capture.models import PacketSummary, Alert
from typing import List
import yaml

def get_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def detect_arp_spoof(packets: List[PacketSummary]) -> List[Alert]:
    """
    Detect ARP spoofing — when the same IP address
    appears with two different MAC addresses.

    How ARP spoofing works:
    - Normal: IP 192.168.1.1 always has MAC aa:bb:cc:dd:ee:ff
    - Attack: Attacker sends fake ARP reply saying
              192.168.1.1 is now at MAC 11:22:33:44:55:66
    - Result: Your traffic gets redirected to attacker (MITM)

    Detection: track IP->MAC mappings, alert on conflict.
    """
    config   = get_config()
    severity = config["detection"]["arp_spoof"]["severity"]

    # ip_mac_map: { "192.168.1.1": {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"} }
    # defaultdict(set) means: if key doesn't exist, create empty set
    ip_mac_map = defaultdict(set)

    for pkt in packets:
        if pkt.is_arp() and pkt.src_ip and pkt.src_mac:
            ip_mac_map[pkt.src_ip].add(pkt.src_mac)

    alerts = []

    for ip, macs in ip_mac_map.items():
        if len(macs) > 1:
            # Same IP seen with multiple MACs — spoofing detected
            alerts.append(Alert(
                rule_name   = "arp_spoof",
                severity    = severity,
                src_ip      = ip,
                description = (
                    f"ARP spoofing detected — IP {ip} seen with "
                    f"{len(macs)} different MAC addresses: "
                    f"{', '.join(list(macs)[:3])}"
                ),
            ))

    return alerts