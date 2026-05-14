import json
import csv
import os
from datetime import datetime

def export_json(alerts, filename):
    os.makedirs("data/exports", exist_ok=True)
    path = f"data/exports/{filename}.json"
    serialisable = []
    for a in alerts:
        serialisable.append({
            "rule_name":   a.get("rule_name")   if isinstance(a, dict) else a.rule_name,
            "severity":    a.get("severity")    if isinstance(a, dict) else a.severity,
            "description": a.get("description") if isinstance(a, dict) else a.description,
            "src_ip":      a.get("src_ip")      if isinstance(a, dict) else a.src_ip,
            "timestamp":   (
                a.get("timestamp") if isinstance(a, dict)
                else a.timestamp.isoformat()
            ),
        })
    with open(path, "w") as f:
        json.dump({
            "generated_at": datetime.now().isoformat(),
            "total_alerts": len(serialisable),
            "alerts":       serialisable,
        }, f, indent=2)
    print(f"[Export] JSON saved to {path}")
    return path

def export_csv(alerts, filename):
    os.makedirs("data/exports", exist_ok=True)
    path   = f"data/exports/{filename}.csv"
    fields = ["timestamp", "rule_name", "severity", "description", "src_ip"]
    rows   = []
    for a in alerts:
        rows.append({
            "rule_name":   a.get("rule_name")   if isinstance(a, dict) else a.rule_name,
            "severity":    a.get("severity")    if isinstance(a, dict) else a.severity,
            "description": a.get("description") if isinstance(a, dict) else a.description,
            "src_ip":      a.get("src_ip")      if isinstance(a, dict) else a.src_ip,
            "timestamp":   (
                a.get("timestamp") if isinstance(a, dict)
                else a.timestamp.isoformat()
            ),
        })
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"[Export] CSV saved to {path}")
    return path

def export_report(alerts, filename):
    export_json(alerts, filename)
    export_csv(alerts,  filename)