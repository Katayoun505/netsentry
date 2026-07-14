"""
Packet capture engine using Scapy.

Run this as its own script (not through uvicorn) — it needs raw socket
access, which on Windows means running it from an Administrator terminal,
and on Linux/Mac means running it with sudo.

Usage:
    python capture.py                  # capture on default interface
    python capture.py --iface "Wi-Fi"  # capture on a specific interface

Each captured packet is written as a row into the traffic_logs table via
the same SQLAlchemy models used by the rest of the app (database.py,
logs.py), so anything captured here immediately shows up through the
GET /logs endpoint.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

from database import SessionLocal, Base, engine
from logs import TrafficLog

# Make sure the table exists even if this script is run standalone,
# without main.py having started first.
Base.metadata.create_all(bind=engine)


def _protocol_name(packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def handle_packet(packet):
    """Callback Scapy runs for every captured packet."""
    if not packet.haslayer(IP):
        return  # skip non-IP traffic (e.g. ARP) for now

    ip_layer = packet[IP]
    protocol = _protocol_name(packet)

    source_port = None
    destination_port = None
    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    db = SessionLocal()
    try:
        log_entry = TrafficLog(
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=len(packet),
        )
        db.add(log_entry)
        db.commit()
    finally:
        db.close()

    # Simple console feedback so you can see it working live
    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"{ip_layer.src}:{source_port} -> {ip_layer.dst}:{destination_port} "
        f"[{protocol}] {len(packet)} bytes"
    )


def main():
    parser = argparse.ArgumentParser(description="NetSentry packet capture engine")
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface to capture on (default: Scapy picks automatically)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture, 0 = unlimited (default: 0)",
    )
    args = parser.parse_args()

    print("NetSentry capture engine starting...")
    print("Press Ctrl+C to stop.\n")

    sniff(
        iface=args.iface,
        prn=handle_packet,
        count=args.count,
        store=False,  # don't keep packets in memory, we already saved what we need
    )


if __name__ == "__main__":
    main()