from packethawk.detection.detectors.port_scan     import detect_port_scan
from packethawk.detection.detectors.arp_spoof     import detect_arp_spoof
from packethawk.detection.detectors.dns_anomaly   import detect_dns_anomaly
from packethawk.detection.detectors.traffic_spike import detect_traffic_spike
from packethawk.storage.db import store_alert
from packethawk.capture.models import Alert
from typing import List

DETECTORS = [
    detect_port_scan,
    detect_arp_spoof,
    detect_dns_anomaly,
    detect_traffic_spike,
]

def run_all_detectors(packets) -> List[Alert]:
    """Run all 4 detectors against a list of PacketSummary objects."""
    all_alerts = []

    for detector_fn in DETECTORS:
        try:
            alerts = detector_fn(packets)
            all_alerts.extend(alerts)
            if alerts:
                print(f"[Engine] {detector_fn.__name__} — "
                      f"{len(alerts)} alert(s)")
        except Exception as e:
            print(f"[Engine] Error in {detector_fn.__name__}: {e}")

    return all_alerts

def save_alerts(alerts: List[Alert]):
    for alert in alerts:
        store_alert(alert)
    if alerts:
        print(f"[Engine] Saved {len(alerts)} alerts to database.")