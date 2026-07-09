"""
replay.py
----------
Live packet capture needs admin/root privileges and an actual network
with traffic on it - not always convenient when you're learning or
testing. This script lets you run the EXACT SAME detection engines
against a CSV file instead, so you can:

  - Test your detection logic without touching real network hardware
  - Work with public labeled datasets like NSL-KDD or CIC-IDS2017
  - Demonstrate the project even on a machine with no admin rights

HOW TO GET A DATASET (see README for full details):
  - NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
  - CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
  - UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset

This script expects a CSV with (at minimum) columns for source IP,
destination IP, destination port, and protocol. Real-world dataset
column names vary a lot, so there's a small MAPPING dict below you
edit to match whatever CSV you actually downloaded. There's also a
built-in synthetic generator (generate_demo_csv) so you can try
everything immediately with zero downloads.
"""
import argparse
import csv
import random
import time

from detection.signature_detection import SignatureDetector
from detection.anomaly_detection import AnomalyDetector
from alerts.alert_manager import AlertManager
from utils.logger import get_logger

logger = get_logger("Replay")

# Edit these to match your actual dataset's column names.
# Left side = what our code needs, right side = the column name in your CSV.
MAPPING = {
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "flags": "flags",   # optional, can be missing/blank
}


def generate_demo_csv(path="data/demo_traffic.csv", rows=2000):
    """
    Creates a synthetic CSV that mixes normal traffic with an
    embedded port scan, a DoS burst, and a brute-force attempt, so you
    can see the detectors fire without needing a real dataset or
    real network access. This is purely for learning/testing.
    """
    normal_ips = [f"192.168.1.{i}" for i in range(10, 30)]
    server_ip = "192.168.1.100"
    attacker_ip = "10.0.0.99"

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "dst_ip", "dst_port", "protocol", "flags"])

        # Normal background traffic
        for _ in range(rows):
            writer.writerow([
                random.choice(normal_ips), server_ip,
                random.choice([80, 443, 53]), "TCP", "PA"
            ])

        # Embedded port scan: attacker hits many ports on the server fast
        for port in range(1, 40):
            writer.writerow([attacker_ip, server_ip, port, "TCP", "S"])

        # Embedded DoS burst: attacker floods the server
        for _ in range(300):
            writer.writerow([attacker_ip, server_ip, 80, "TCP", "S"])

        # Embedded brute force: repeated SSH connection attempts
        for _ in range(12):
            writer.writerow([attacker_ip, server_ip, 22, "TCP", "S"])

    logger.info(f"Demo CSV written to {path} ({rows + 40 + 300 + 12} rows)")
    return path


def replay_csv(path, delay=0.0):
    sig_detector = SignatureDetector()
    anomaly_detector = AnomalyDetector()
    alert_manager = AlertManager()

    total = 0
    alert_count = 0

    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packet = {
                "timestamp": time.time(),
                "src_ip": row.get(MAPPING["src_ip"], "0.0.0.0"),
                "dst_ip": row.get(MAPPING["dst_ip"], "0.0.0.0"),
                "dst_port": _to_int(row.get(MAPPING["dst_port"])),
                "protocol": row.get(MAPPING["protocol"], "TCP"),
                "flags": row.get(MAPPING["flags"], ""),
                "size": 0,
            }

            alerts = []
            alerts += sig_detector.inspect(packet)
            alerts += anomaly_detector.inspect(packet)

            for alert in alerts:
                alert_manager.raise_alert(alert)
                alert_count += 1

            total += 1
            if delay:
                time.sleep(delay)  # slow playback down to feel "live"

    logger.info(f"Replay finished. {total} rows processed, {alert_count} alerts raised.")
    logger.info(f"Check logs/alerts.csv and logs/alerts.log for details.")


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay a CSV traffic log through the NIDS detectors")
    parser.add_argument("--file", help="Path to CSV file. If omitted, a demo CSV is generated.")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to sleep between rows (simulate live speed)")
    args = parser.parse_args()

    csv_path = args.file or generate_demo_csv()
    replay_csv(csv_path, delay=args.delay)
