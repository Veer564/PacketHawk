import threading
import time
from datetime         import datetime
from collections      import defaultdict
from scapy.all        import sniff, ARP, IP, TCP, UDP, DNS, DNSQR
from packethawk.capture.models  import PacketSummary
from packethawk.storage.db      import init_db, store_packets_bulk
from packethawk.detection.engine import run_all_detectors, save_alerts

# ── Packet conversion ─────────────────────────────────────────

def _scapy_to_summary(pkt) -> PacketSummary:
    """Convert a raw Scapy packet into a PacketSummary object."""
    try:
        src_ip = dst_ip = "0.0.0.0"
        src_port = dst_port = None
        src_mac  = None
        dns_query = None
        protocol  = "OTHER"
        size      = len(pkt)

        if pkt.haslayer(ARP):
            protocol = "ARP"
            src_ip   = pkt[ARP].psrc
            dst_ip   = pkt[ARP].pdst
            src_mac  = pkt[ARP].hwsrc

        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    try:
                        dns_query = pkt[DNSQR].qname.decode(
                            "utf-8", errors="ignore"
                        ).strip(".")
                    except Exception:
                        pass
            else:
                protocol = "ICMP"

        return PacketSummary(
            src_ip    = src_ip,
            dst_ip    = dst_ip,
            protocol  = protocol,
            size      = size,
            src_port  = src_port,
            dst_port  = dst_port,
            src_mac   = src_mac,
            dns_query = dns_query,
            timestamp = datetime.now(),
        )
    except Exception:
        return None

# ── Live capture engine ───────────────────────────────────────

class LiveCapture:
    """
    Captures packets live from a network interface.

    Uses threading so capture runs in background while
    the main thread analyses and displays results.

    Threading concept:
    - self._capture_thread runs _capture_worker() in background
    - self._stop_event is a flag — when set, background thread stops
    - main thread calls start(), waits, then calls stop()
    """

    def __init__(self, interface="en0", batch_size=50,
                 analyse_interval=10):
        self.interface        = interface
        self.batch_size       = batch_size
        self.analyse_interval = analyse_interval  # seconds between analysis runs

        self._packet_buffer   = []
        self._buffer_lock     = threading.Lock()
        self._stop_event      = threading.Event()
        self._capture_thread  = None
        self._total_captured  = 0
        self._total_alerts    = 0

    def _packet_callback(self, raw_pkt):
        """Called by Scapy for every captured packet."""
        pkt = _scapy_to_summary(raw_pkt)
        if pkt:
            # Lock prevents race condition between capture
            # and analysis threads accessing buffer simultaneously
            with self._buffer_lock:
                self._packet_buffer.append(pkt)
                self._total_captured += 1

    def _capture_worker(self):
        """Runs in background thread — captures packets continuously."""
        print(f"[LiveCapture] Sniffing on {self.interface}...")
        sniff(
            iface   = self.interface,
            prn     = self._packet_callback,
            store   = False,          # don't store in Scapy memory
            stop_filter = lambda _: self._stop_event.is_set(),
        )

    def _analyse_worker(self):
        """
        Runs in main thread — periodically drains buffer,
        runs detectors, displays alerts.
        """
        from packethawk.cli.display import print_alerts, console
        from rich.live  import Live
        from rich.table import Table
        from rich       import box

        while not self._stop_event.is_set():
            time.sleep(self.analyse_interval)

            # Drain the buffer safely
            with self._buffer_lock:
                batch = self._packet_buffer.copy()
                self._packet_buffer.clear()

            if not batch:
                print(f"[LiveCapture] Waiting for packets... "
                      f"(total captured: {self._total_captured})")
                continue

            print(f"\n[LiveCapture] Analysing batch of {len(batch)} packets...")

            # Store to DB
            store_packets_bulk(batch)

            # Run all 4 detectors
            alerts = run_all_detectors(batch)
            if alerts:
                save_alerts(alerts)
                self._total_alerts += len(alerts)
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
            else:
                print(f"[LiveCapture] Batch clean — "
                      f"no anomalies detected.")

            print(f"[LiveCapture] Total captured: {self._total_captured} | "
                  f"Total alerts: {self._total_alerts}")

    def start(self):
        """Start live capture — runs until Ctrl+C."""
        init_db()

        # Start capture in background thread
        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            daemon=True,
        )
        self._capture_thread.start()

        print(f"[LiveCapture] Started on {self.interface}")
        print(f"[LiveCapture] Analysing every {self.analyse_interval}s")
        print(f"[LiveCapture] Press Ctrl+C to stop\n")

        try:
            self._analyse_worker()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Signal background thread to stop cleanly."""
        print(f"\n[LiveCapture] Stopping...")
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout=3)
        print(f"[LiveCapture] Stopped.")
        print(f"[LiveCapture] Total packets captured: {self._total_captured}")
        print(f"[LiveCapture] Total alerts fired:     {self._total_alerts}")