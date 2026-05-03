import sqlite3
import yaml
import os

def get_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def get_connection():
    config   = get_config()
    db_path  = config["database"]["path"]
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return sqlite3.connect(db_path)

def init_db():
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            size        INTEGER,
            src_mac     TEXT,
            dns_query   TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            rule_name   TEXT,
            severity    TEXT,
            description TEXT,
            src_ip      TEXT,
            dst_ip      TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialised successfully.")

def store_packet(pkt):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets
            (timestamp, src_ip, dst_ip, src_port, dst_port,
             protocol, size, src_mac, dns_query)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        pkt.timestamp.isoformat(),
        pkt.src_ip,
        pkt.dst_ip,
        pkt.src_port,
        pkt.dst_port,
        pkt.protocol,
        pkt.size,
        pkt.src_mac,
        pkt.dns_query,
    ))
    conn.commit()
    conn.close()

def store_packets_bulk(packets):
    if not packets:
        return
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO packets
            (timestamp, src_ip, dst_ip, src_port, dst_port,
             protocol, size, src_mac, dns_query)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (
            p.timestamp.isoformat(),
            p.src_ip, p.dst_ip,
            p.src_port, p.dst_port,
            p.protocol, p.size,
            p.src_mac, p.dns_query,
        )
        for p in packets
    ])
    conn.commit()
    conn.close()
    print(f"[DB] Stored {len(packets)} packets.")

def store_alert(alert):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts
            (timestamp, rule_name, severity, description, src_ip, dst_ip)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert.timestamp.isoformat(),
        alert.rule_name,
        alert.severity,
        alert.description,
        alert.src_ip,
        alert.dst_ip,
    ))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()