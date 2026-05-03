import math
from collections import Counter
from packethawk.capture.models import PacketSummary, Alert
from typing import List
import yaml

def get_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def _entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy = random-looking = suspicious.

    Normal domain: google.com        → entropy ~2.8
    Tunnel domain: a8f3k2.evil.com   → entropy ~3.9
    Base64 domain: aGVsbG8.evil.com  → entropy ~4.2

    Formula: -sum(p * log2(p)) for each unique character
    where p = frequency of that character.
    """
    if not text:
        return 0.0
    counter = Counter(text.lower())
    length  = len(text)
    entropy = 0.0
    for count in counter.values():
        p        = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def detect_dns_anomaly(packets: List[PacketSummary]) -> List[Alert]:
    """
    Detect DNS tunnelling — attackers hide data inside
    DNS queries using high-entropy subdomain strings.

    Example of normal DNS:  www.google.com      (entropy ~3.1)
    Example of tunnel DNS:  aGVsbG8xMjM.evil.com (entropy ~4.5)
    """
    config    = get_config()
    threshold = config["detection"]["dns_anomaly"]["entropy_threshold"]
    severity  = config["detection"]["dns_anomaly"]["severity"]

    alerts  = []
    flagged = set()  # avoid duplicate alerts for same domain

    for pkt in packets:
        if not pkt.dns_query:
            continue

        query = pkt.dns_query.strip(".")

        if query in flagged:
            continue

        # Extract the subdomain part (everything before last two labels)
        parts = query.split(".")
        if len(parts) < 2:
            continue

        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

        if not subdomain:
            continue

        score = _entropy(subdomain)

        if score >= threshold:
            flagged.add(query)
            alerts.append(Alert(
                rule_name   = "dns_anomaly",
                severity    = severity,
                src_ip      = pkt.src_ip,
                description = (
                    f"High entropy DNS query: {query} "
                    f"(entropy: {score}, threshold: {threshold}) "
                    f"— possible DNS tunnelling"
                ),
            ))

    return alerts