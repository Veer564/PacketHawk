from simulate_packets import (
    simulate_port_scan,
    simulate_arp_spoof,
    simulate_dns_tunnel,
    simulate_traffic_spike,
    simulate_normal_traffic,
)
from packethawk.detection.detectors.port_scan     import detect_port_scan
from packethawk.detection.detectors.arp_spoof     import detect_arp_spoof
from packethawk.detection.detectors.dns_anomaly   import detect_dns_anomaly
from packethawk.detection.detectors.traffic_spike import detect_traffic_spike
from packethawk.detection.detectors.dns_anomaly   import _entropy

# ── Port scan tests ──────────────────────────────────────────
def test_port_scan_detected():
    packets = simulate_port_scan(num_ports=20)
    alerts  = detect_port_scan(packets)
    assert len(alerts) >= 1
    assert alerts[0].rule_name == "port_scan"
    assert alerts[0].severity  == "HIGH"

def test_port_scan_not_triggered_on_normal():
    packets = simulate_normal_traffic()
    alerts  = detect_port_scan(packets)
    assert len(alerts) == 0

# ── ARP spoof tests ──────────────────────────────────────────
def test_arp_spoof_detected():
    packets = simulate_arp_spoof()
    alerts  = detect_arp_spoof(packets)
    assert len(alerts) >= 1
    assert alerts[0].rule_name == "arp_spoof"
    assert alerts[0].severity  == "CRITICAL"

def test_arp_spoof_not_triggered_on_normal():
    packets = simulate_normal_traffic()
    alerts  = detect_arp_spoof(packets)
    assert len(alerts) == 0

# ── DNS anomaly tests ────────────────────────────────────────
def test_dns_anomaly_detected():
    packets = simulate_dns_tunnel()
    alerts  = detect_dns_anomaly(packets)
    assert len(alerts) >= 1
    assert alerts[0].rule_name == "dns_anomaly"

def test_entropy_high_for_random_string():
    score = _entropy("aGVsbG8xMjM0NTY3")
    assert score >= 3.5

def test_entropy_low_for_normal_domain():
    score = _entropy("google")
    assert score < 3.5

# ── Traffic spike tests ──────────────────────────────────────
def test_traffic_spike_detected():
    packets = simulate_traffic_spike()
    alerts  = detect_traffic_spike(packets)
    assert len(alerts) >= 1
    assert alerts[0].rule_name == "traffic_spike"
    assert alerts[0].severity  == "HIGH"

def test_traffic_spike_not_on_normal():
    packets = simulate_normal_traffic()
    alerts  = detect_traffic_spike(packets)
    assert len(alerts) == 0