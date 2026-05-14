import os
import json
import csv
from packethawk.cli.exporter import export_json, export_csv
from packethawk.capture.models import Alert

def make_test_alerts():
    return [
        Alert(
            rule_name   = "port_scan",
            severity    = "HIGH",
            description = "Test port scan alert",
            src_ip      = "1.2.3.4",
        ),
        Alert(
            rule_name   = "arp_spoof",
            severity    = "CRITICAL",
            description = "Test ARP spoof alert",
            src_ip      = "192.168.1.1",
        ),
    ]

def test_export_json_creates_file():
    alerts = make_test_alerts()
    path   = export_json(alerts, "test_export")
    assert os.path.exists(path)

def test_export_json_valid_structure():
    alerts = make_test_alerts()
    path   = export_json(alerts, "test_export")
    with open(path) as f:
        data = json.load(f)
    assert data["total_alerts"] == 2
    assert len(data["alerts"])  == 2
    assert "generated_at"       in data

def test_export_csv_creates_file():
    alerts = make_test_alerts()
    path   = export_csv(alerts, "test_export")
    assert os.path.exists(path)

def test_export_csv_has_correct_rows():
    alerts = make_test_alerts()
    path   = export_csv(alerts, "test_export")
    with open(path) as f:
        reader = list(csv.DictReader(f))
    assert len(reader)           == 2
    assert reader[0]["severity"] == "HIGH"
    assert reader[1]["severity"] == "CRITICAL"