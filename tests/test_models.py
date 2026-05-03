from packethawk.capture.models import PacketSummary, Alert
from datetime import datetime

def test_packet_summary_creation():
    pkt = PacketSummary(
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        protocol="TCP",
        size=64,
        src_port=52345,
        dst_port=80,
    )
    assert pkt.src_ip    == "192.168.1.1"
    assert pkt.dst_ip    == "8.8.8.8"
    assert pkt.protocol  == "TCP"
    assert pkt.size      == 64
    assert pkt.dst_port  == 80

def test_packet_is_tcp():
    pkt = PacketSummary("1.2.3.4", "5.6.7.8", "TCP", 64)
    assert pkt.is_tcp()  == True
    assert pkt.is_udp()  == False

def test_packet_is_dns():
    pkt = PacketSummary(
        "1.2.3.4", "8.8.8.8", "UDP", 64,
        src_port=12345, dst_port=53
    )
    assert pkt.is_dns() == True

def test_packet_is_arp():
    pkt = PacketSummary("0.0.0.0", "0.0.0.0", "ARP", 42)
    assert pkt.is_arp() == True

def test_alert_creation():
    alert = Alert(
        rule_name="port_scan",
        severity="HIGH",
        description="Port scan detected from 1.2.3.4",
        src_ip="1.2.3.4",
    )
    assert alert.rule_name  == "port_scan"
    assert alert.severity   == "HIGH"
    assert alert.src_ip     == "1.2.3.4"
    assert alert.timestamp  is not None

def test_packet_timestamp_is_unique():
    import time
    pkt1 = PacketSummary("1.1.1.1", "2.2.2.2", "TCP", 64)
    time.sleep(0.01)
    pkt2 = PacketSummary("1.1.1.1", "2.2.2.2", "TCP", 64)
    assert pkt1.timestamp != pkt2.timestamp