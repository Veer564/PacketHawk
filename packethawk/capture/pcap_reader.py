import pyshark
from packethawk.capture.models import PacketSummary
from datetime import datetime

def read_pcap(filepath):
    """
    Generator that reads a PCAP file one packet at a time.
    Uses 'yield' instead of 'return' so it never loads the
    entire file into memory — works on files of any size.
    """
    print(f"[Reader] Opening {filepath}...")
    cap = pyshark.FileCapture(filepath, keep_packets=False)

    parsed  = 0
    skipped = 0

    for raw_pkt in cap:
        pkt = _parse_packet(raw_pkt)
        if pkt:
            parsed += 1
            yield pkt        # pause here, give one packet to caller
                             # resume when caller asks for next one
        else:
            skipped += 1

    cap.close()
    print(f"[Reader] Done — {parsed} parsed, {skipped} skipped.")

def _parse_packet(raw_pkt):
    """Convert a raw pyshark packet into a PacketSummary."""
    try:
        protocol = _get_protocol(raw_pkt)
        size     = int(raw_pkt.length)

        src_ip = dst_ip = "0.0.0.0"
        if hasattr(raw_pkt, "ip"):
            src_ip = raw_pkt.ip.src
            dst_ip = raw_pkt.ip.dst

        src_port = dst_port = None
        if hasattr(raw_pkt, "tcp"):
            src_port = int(raw_pkt.tcp.srcport)
            dst_port = int(raw_pkt.tcp.dstport)
        elif hasattr(raw_pkt, "udp"):
            src_port = int(raw_pkt.udp.srcport)
            dst_port = int(raw_pkt.udp.dstport)

        src_mac = None
        if hasattr(raw_pkt, "eth"):
            src_mac = raw_pkt.eth.src

        dns_query = None
        if hasattr(raw_pkt, "dns"):
            try:
                dns_query = raw_pkt.dns.qry_name
            except AttributeError:
                pass

        return PacketSummary(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            size=size,
            src_port=src_port,
            dst_port=dst_port,
            src_mac=src_mac,
            dns_query=dns_query,
        )

    except Exception:
        return None

def _get_protocol(raw_pkt):
    if hasattr(raw_pkt, "tcp"):  return "TCP"
    if hasattr(raw_pkt, "udp"):  return "UDP"
    if hasattr(raw_pkt, "arp"):  return "ARP"
    if hasattr(raw_pkt, "icmp"): return "ICMP"
    return "OTHER"