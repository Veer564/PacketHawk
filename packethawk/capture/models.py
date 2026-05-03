from dataclasses import dataclass, field
from datetime    import datetime
from typing      import Optional

@dataclass
class PacketSummary:
    """
    Represents a single captured network packet.
    A dataclass auto-generates __init__, __repr__,
    and __eq__ so you don't have to write them manually.
    """
    src_ip:   str
    dst_ip:   str
    protocol: str
    size:     int

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac:  Optional[str] = None
    dns_query: Optional[str] = None

    timestamp: datetime = field(default_factory=datetime.now)

    def is_tcp(self):
        return self.protocol == "TCP"

    def is_udp(self):
        return self.protocol == "UDP"

    def is_dns(self):
        return self.dst_port == 53 or self.src_port == 53

    def is_arp(self):
        return self.protocol == "ARP"

    def __repr__(self):
        return (
            f"PacketSummary({self.src_ip}:{self.src_port} → "
            f"{self.dst_ip}:{self.dst_port} [{self.protocol}] "
            f"{self.size}B)"
        )

@dataclass
class Alert:
    """Represents a detected security alert."""
    rule_name:   str
    severity:    str
    description: str
    src_ip:      Optional[str] = None
    dst_ip:      Optional[str] = None
    timestamp:   datetime = field(default_factory=datetime.now)