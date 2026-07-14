"""
Detection engine — analyzes recent traffic_logs entries against
rule-based checks AND a statistical anomaly-detection check, writing
matches into the alerts table.

Rule-based checks (Phase 1-6): PORT_SCAN, DOS_ATTEMPT, SUSPICIOUS_PORT.
Anomaly-based check (Phase 8): ANOMALOUS_TRAFFIC — flags an IP whose
packet rate has deviated far from ITS OWN historical baseline, using
an incrementally-updated mean/std-dev (Welford's online algorithm).

Important design note: any traffic window that already triggered a
rule-based alert is excluded from updating an IP's baseline. Without
this, attack traffic would gradually get folded into "normal," and
the anomaly detector would slowly stop noticing it — this is known
as baseline poisoning, and avoiding it is deliberate here.

Run this alongside capture.py (in a separate terminal), or import
run_detection_cycle() elsewhere if you want to trigger it differently
later (e.g. from a scheduled task).

Usage:
    python detection.py                  # run continuously, checking every 5s
    python detection.py --once           # run a single check and exit
    python detection.py --interval 10    # check every 10 seconds instead
"""

import argparse
import math
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from sqlalchemy import func

from database import SessionLocal, Base, engine
from logs import TrafficLog
from alerts import Alert
from baseline import TrafficBaseline
from encryption import encrypt_str
from geoip import lookup_ip

Base.metadata.create_all(bind=engine)

# ---------- Tunable thresholds ----------
# These numbers are deliberately conservative for a small lab/demo network.
# On a busy real network you'd need much higher thresholds to avoid
# false positives — this tension (sensitivity vs. false positive rate)
# is worth discussing explicitly in your report.

PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_DISTINCT_PORT_THRESHOLD = 8  # N distinct ports from one IP in the window

DOS_WINDOW_SECONDS = 10
DOS_PACKET_COUNT_THRESHOLD = 50  # N total packets from one IP in the window

# Ports with no legitimate reason to be contacted on a normal host —
# commonly associated with backdoors / reverse shells / known malware.
SUSPICIOUS_PORTS = {4444, 31337, 12345, 6667, 1337}

# How far back to look when checking for suspicious-port hits, so we
# don't re-alert on the exact same packet forever.
SUSPICIOUS_PORT_LOOKBACK_SECONDS = 10

# ---------- Anomaly detection (Phase 8) ----------
ANOMALY_WINDOW_SECONDS = 10
ANOMALY_STD_DEV_THRESHOLD = 3  # "k" — how many std devs above baseline counts as anomalous
ANOMALY_MIN_SAMPLES = 5        # don't judge an IP as anomalous until we've seen it enough times


def _recent_logs(db, seconds: int):
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=seconds)
    return db.query(TrafficLog).filter(TrafficLog.captured_at >= cutoff).all()


def _already_alerted_recently(db, rule_type: str, source_ip: str, within_seconds: int = 30) -> bool:
    """Avoid spamming duplicate alerts for the same ongoing behavior."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=within_seconds)
    existing = (
        db.query(Alert)
        .filter(
            Alert.rule_type == rule_type,
            Alert.source_ip == source_ip,
            Alert.created_at >= cutoff,
        )
        .first()
    )
    return existing is not None


def _flagged_by_rule_recently(db, source_ip: str, within_seconds: int) -> bool:
    """
    True if source_ip already triggered ANY rule-based alert recently.
    Used to (a) avoid a redundant ANOMALOUS_TRAFFIC alert on top of an
    already-flagged attack, and (b) prevent that same attack traffic
    from being folded into the IP's "normal" baseline.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=within_seconds)
    existing = (
        db.query(Alert)
        .filter(
            Alert.source_ip == source_ip,
            Alert.rule_type.in_(["PORT_SCAN", "DOS_ATTEMPT", "SUSPICIOUS_PORT"]),
            Alert.created_at >= cutoff,
        )
        .first()
    )
    return existing is not None


def _geo_fields(source_ip: str) -> dict:
    """Resolve source_ip to location fields ready to unpack into an Alert(...)."""
    geo = lookup_ip(source_ip)
    return {
        "geo_country": geo["country"],
        "geo_city": geo["city"],
        "geo_lat": str(geo["lat"]),
        "geo_lon": str(geo["lon"]),
        "geo_simulated": "true" if geo["simulated"] else "false",
    }


def check_port_scan(db):
    logs = _recent_logs(db, PORT_SCAN_WINDOW_SECONDS)

    ports_by_source = defaultdict(set)
    for log in logs:
        if log.destination_port is not None:
            ports_by_source[log.source_ip].add(log.destination_port)

    for source_ip, ports in ports_by_source.items():
        if len(ports) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD:
            if _already_alerted_recently(db, "PORT_SCAN", source_ip):
                continue
            alert = Alert(
                rule_type="PORT_SCAN",
                source_ip=source_ip,
                severity="high",
                description=encrypt_str(
                    f"{len(ports)} distinct destination ports contacted "
                    f"within {PORT_SCAN_WINDOW_SECONDS} seconds"
                ),
                **_geo_fields(source_ip),
            )
            db.add(alert)
            print(f"[ALERT] PORT_SCAN from {source_ip} — {len(ports)} ports")

    db.commit()


def check_dos(db):
    logs = _recent_logs(db, DOS_WINDOW_SECONDS)

    packet_count_by_source = defaultdict(int)
    for log in logs:
        packet_count_by_source[log.source_ip] += 1

    for source_ip, count in packet_count_by_source.items():
        if count >= DOS_PACKET_COUNT_THRESHOLD:
            if _already_alerted_recently(db, "DOS_ATTEMPT", source_ip):
                continue
            alert = Alert(
                rule_type="DOS_ATTEMPT",
                source_ip=source_ip,
                severity="critical",
                description=encrypt_str(
                    f"{count} packets sent within {DOS_WINDOW_SECONDS} seconds "
                    f"(threshold: {DOS_PACKET_COUNT_THRESHOLD})"
                ),
                **_geo_fields(source_ip),
            )
            db.add(alert)
            print(f"[ALERT] DOS_ATTEMPT from {source_ip} — {count} packets")

    db.commit()


def check_suspicious_ports(db):
    logs = _recent_logs(db, SUSPICIOUS_PORT_LOOKBACK_SECONDS)

    for log in logs:
        if log.destination_port in SUSPICIOUS_PORTS:
            if _already_alerted_recently(db, "SUSPICIOUS_PORT", log.source_ip, within_seconds=10):
                continue
            alert = Alert(
                rule_type="SUSPICIOUS_PORT",
                source_ip=log.source_ip,
                severity="medium",
                description=encrypt_str(
                    f"Traffic to commonly-abused port {log.destination_port} "
                    f"on {log.destination_ip}"
                ),
                **_geo_fields(log.source_ip),
            )
            db.add(alert)
            print(f"[ALERT] SUSPICIOUS_PORT from {log.source_ip} — port {log.destination_port}")

    db.commit()


def check_anomalous_traffic(db):
    """
    Flags a source IP whose packet count in this window is more than
    ANOMALY_STD_DEV_THRESHOLD standard deviations above ITS OWN
    historical mean, using Welford's online algorithm for the running
    mean/variance (baseline.mean_packet_count / baseline.m2).

    Windows already covered by a rule-based alert are skipped
    entirely — no anomaly alert on top, and no baseline update
    (protects the baseline from being poisoned by attack traffic).
    """
    logs = _recent_logs(db, ANOMALY_WINDOW_SECONDS)

    packet_count_by_source = defaultdict(int)
    for log in logs:
        packet_count_by_source[log.source_ip] += 1

    for source_ip, count in packet_count_by_source.items():
        if _flagged_by_rule_recently(db, source_ip, within_seconds=30):
            continue

        baseline = (
            db.query(TrafficBaseline)
            .filter(TrafficBaseline.source_ip == source_ip)
            .first()
        )
        if baseline is None:
            baseline = TrafficBaseline(source_ip=source_ip)
            db.add(baseline)
            db.flush()  # so baseline.id / defaults are populated before we touch it

        if baseline.sample_count >= ANOMALY_MIN_SAMPLES:
            variance = baseline.m2 / baseline.sample_count
            std_dev = math.sqrt(variance)

            if std_dev > 0 and count > baseline.mean_packet_count + ANOMALY_STD_DEV_THRESHOLD * std_dev:
                if not _already_alerted_recently(db, "ANOMALOUS_TRAFFIC", source_ip):
                    z_score = (count - baseline.mean_packet_count) / std_dev
                    alert = Alert(
                        rule_type="ANOMALOUS_TRAFFIC",
                        source_ip=source_ip,
                        severity="high",
                        description=encrypt_str(
                            f"{count} packets in {ANOMALY_WINDOW_SECONDS}s is {z_score:.1f} std devs "
                            f"above this IP's baseline (mean={baseline.mean_packet_count:.1f}, "
                            f"based on {baseline.sample_count} prior windows)"
                        ),
                        **_geo_fields(source_ip),
                    )
                    db.add(alert)
                    print(
                        f"[ALERT] ANOMALOUS_TRAFFIC from {source_ip} — {count} packets "
                        f"(baseline mean={baseline.mean_packet_count:.1f}, std={std_dev:.1f}, z={z_score:.1f})"
                    )
                # Deliberately do NOT update the baseline with this
                # anomalous value — that would teach the model to
                # accept the anomaly as normal over time.
                continue

        # "Normal enough" window — fold it into the baseline via
        # Welford's incremental mean/variance update.
        baseline.sample_count += 1
        delta = count - baseline.mean_packet_count
        baseline.mean_packet_count += delta / baseline.sample_count
        delta2 = count - baseline.mean_packet_count
        baseline.m2 += delta * delta2

    db.commit()


def run_detection_cycle():
    db = SessionLocal()
    try:
        check_port_scan(db)
        check_dos(db)
        check_suspicious_ports(db)
        check_anomalous_traffic(db)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="NetSentry detection engine")
    parser.add_argument("--once", action="store_true", help="Run a single check and exit")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between checks (default: 5)")
    args = parser.parse_args()

    print("NetSentry detection engine starting...")
    print(f"Rules: PORT_SCAN (>{PORT_SCAN_DISTINCT_PORT_THRESHOLD} ports/{PORT_SCAN_WINDOW_SECONDS}s), "
          f"DOS_ATTEMPT (>{DOS_PACKET_COUNT_THRESHOLD} pkts/{DOS_WINDOW_SECONDS}s), "
          f"SUSPICIOUS_PORT ({sorted(SUSPICIOUS_PORTS)}), "
          f"ANOMALOUS_TRAFFIC (>{ANOMALY_STD_DEV_THRESHOLD} std devs, min {ANOMALY_MIN_SAMPLES} samples)")
    print("Press Ctrl+C to stop.\n")

    if args.once:
        run_detection_cycle()
        return

    try:
        while True:
            run_detection_cycle()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nDetection engine stopped.")


if __name__ == "__main__":
    main()