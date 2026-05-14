import click
import yaml
from packethawk.cli.display         import (
    print_banner, print_alerts,
    print_stats,  print_packet_summary,
)
from packethawk.cli.exporter        import export_report
from packethawk.storage.db          import init_db, get_connection, store_packets_bulk
from packethawk.detection.engine    import run_all_detectors, save_alerts
from packethawk.capture.pcap_reader import read_pcap
from simulate_packets               import generate_all
from packethawk.capture.live import LiveCapture

def get_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

@click.group()
def cli():
    """PacketHawk — Network Packet Analyser & Anomaly Detector."""
    pass

@cli.command()
def setup():
    """Initialise the database."""
    init_db()
    click.echo("[Setup] Done.")

@cli.command()
@click.argument("pcap_file", default=None, required=False)
@click.option("--export", "export_name", default=None,
              help="Export alerts to JSON and CSV.")
@click.option("--summary", is_flag=True, default=False,
              help="Show packet summary after analysis.")
def analyse(pcap_file, export_name, summary):
    """Analyse a PCAP file or simulated packets."""
    print_banner()
    init_db()

    if pcap_file:
        click.echo(f"[PacketHawk] Analysing {pcap_file}...\n")
        packets = list(read_pcap(pcap_file))
    else:
        click.echo("[PacketHawk] No PCAP file given — using simulated packets.\n")
        packets = generate_all()

    if not packets:
        click.echo("[PacketHawk] No packets to analyse.")
        return

    click.echo(f"[PacketHawk] Loaded {len(packets)} packets.\n")

    store_packets_bulk(packets)

    alerts = run_all_detectors(packets)
    save_alerts(alerts)

    alert_dicts = [
        {
            "rule_name":   a.rule_name,
            "severity":    a.severity,
            "description": a.description,
            "src_ip":      a.src_ip,
            "timestamp":   a.timestamp.isoformat(),
        }
        for a in alerts
    ]

    print_alerts(alert_dicts)

    if summary:
        print_packet_summary(packets)

    if export_name:
        export_report(alert_dicts, export_name)

@cli.command()
@click.option("--export", "export_name", default=None,
              help="Export alerts to JSON and CSV.")
def alerts(export_name):
    """Show all saved alerts from the database."""
    print_banner()
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, rule_name, severity, description, src_ip
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    rows = cursor.fetchall()
    conn.close()

    formatted = [
        {
            "timestamp":   r[0],
            "rule_name":   r[1],
            "severity":    r[2],
            "description": r[3],
            "src_ip":      r[4],
        }
        for r in rows
    ]
    print_alerts(formatted)
    if export_name:
        export_report(formatted, export_name)

@cli.command()
def stats():
    """Show database statistics."""
    print_banner()
    conn   = get_connection()
    cursor = conn.cursor()

    def count(table, where=""):
        cursor.execute(f"SELECT COUNT(*) FROM {table} {where}")
        return cursor.fetchone()[0]

    def count_distinct(col, table):
        cursor.execute(f"SELECT COUNT(DISTINCT {col}) FROM {table}")
        return cursor.fetchone()[0]

    data = {
        "packets":  count("packets"),
        "alerts":   count("alerts"),
        "critical": count("alerts", "WHERE severity='CRITICAL'"),
        "high":     count("alerts", "WHERE severity='HIGH'"),
        "medium":   count("alerts", "WHERE severity='MEDIUM'"),
        "src_ips":  count_distinct("src_ip", "packets"),
        "dst_ips":  count_distinct("dst_ip", "packets"),
    }
    conn.close()
    print_stats(data)

@cli.command()
@click.option("--export", "export_name", default=None,
              help="Export results to JSON and CSV.")
def simulate(export_name):
    """Run attack simulation and detect anomalies."""
    print_banner()
    init_db()

    click.echo("[PacketHawk] Running attack simulation...\n")
    packets = generate_all()
    store_packets_bulk(packets)

    alerts_list = run_all_detectors(packets)
    save_alerts(alerts_list)

    alert_dicts = [
        {
            "rule_name":   a.rule_name,
            "severity":    a.severity,
            "description": a.description,
            "src_ip":      a.src_ip,
            "timestamp":   a.timestamp.isoformat(),
        }
        for a in alerts_list
    ]

    print_alerts(alert_dicts)

    if export_name:
        export_report(alert_dicts, export_name)

@cli.command()
@click.option("--interface", default="en0",
              help="Network interface to capture on (default: en0)")
@click.option("--interval", default=10,
              help="Seconds between analysis runs (default: 10)")
def live(interface, interval):
    """Start live packet capture and real-time anomaly detection."""
    print_banner()
    click.echo(f"[PacketHawk] Starting live capture on {interface}...")
    click.echo(f"[PacketHawk] Analysis runs every {interval} seconds.")
    click.echo(f"[PacketHawk] Press Ctrl+C to stop.\n")

    capture = LiveCapture(
        interface        = interface,
        analyse_interval = interval,
    )
    capture.start()

if __name__ == "__main__":
    cli()