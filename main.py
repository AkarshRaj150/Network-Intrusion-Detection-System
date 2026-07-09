"""
main.py
--------
This is the file you actually run. It:
  1. Starts the packet sniffer (live capture from your network card)
  2. Feeds every packet into BOTH detection engines (signature + anomaly)
  3. Sends any resulting alerts to the AlertManager (log/email)
  4. Keeps rolling traffic counters and writes them to
     logs/traffic_stats.json every second, so the dashboard can show them

Run this in one terminal, and `python dashboard/app.py` in another to
view the web dashboard at http://127.0.0.1:5000

IMPORTANT: live packet capture needs Administrator (Windows) or root/
sudo (Mac/Linux) privileges. See README "Running the sniffer".
"""
import json
import threading
import time
from collections import defaultdict

import config
from capture.packet_sniffer import PacketSniffer
from detection.signature_detection import SignatureDetector
from detection.anomaly_detection import AnomalyDetector
from alerts.alert_manager import AlertManager
from utils.logger import get_logger

logger = get_logger("Main")


class TrafficStats:
    """Keeps simple running counters and periodically dumps them to a
    JSON file so the (separate) dashboard process can read them."""

    def __init__(self, path="logs/traffic_stats.json"):
        self.path = path
        self.total_packets = 0
        self.protocol_counts = defaultdict(int)
        self.alerts_by_type = defaultdict(int)
        self.top_talkers = defaultdict(int)
        self._lock = threading.Lock()

    def record_packet(self, packet):
        with self._lock:
            self.total_packets += 1
            proto = (packet.get("protocol") or "OTHER").lower()
            self.protocol_counts[proto] += 1
            self.top_talkers[packet["src_ip"]] += 1

    def record_alert(self, alert):
        with self._lock:
            self.alerts_by_type[alert["type"]] += 1

    def dump(self):
        with self._lock:
            data = {
                "total_packets": self.total_packets,
                "tcp": self.protocol_counts.get("tcp", 0),
                "udp": self.protocol_counts.get("udp", 0),
                "icmp": self.protocol_counts.get("icmp", 0),
                "other": self.protocol_counts.get("other", 0),
                "alerts_by_type": dict(self.alerts_by_type),
                # Keep the JSON file small: only the top 20 talkers
                "top_talkers": dict(
                    sorted(self.top_talkers.items(), key=lambda kv: -kv[1])[:20]
                ),
            }
        with open(self.path, "w") as f:
            json.dump(data, f)


class NIDS:
    def __init__(self):
        self.sniffer = PacketSniffer(interface=config.INTERFACE)
        self.sig_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.alert_manager = AlertManager()
        self.stats = TrafficStats()
        self._stop_periodic_dump = threading.Event()

    def handle_packet(self, packet):
        self.stats.record_packet(packet)

        alerts = []
        alerts += self.sig_detector.inspect(packet)
        alerts += self.anomaly_detector.inspect(packet)

        for alert in alerts:
            self.alert_manager.raise_alert(alert)
            self.stats.record_alert(alert)

    def _periodic_dump(self):
        # Write traffic_stats.json roughly once a second in the
        # background so the dashboard always has fresh numbers.
        while not self._stop_periodic_dump.is_set():
            self.stats.dump()
            time.sleep(1)

    def run(self):
        dump_thread = threading.Thread(target=self._periodic_dump, daemon=True)
        dump_thread.start()

        logger.info("NIDS starting up. Press Ctrl+C to stop.")
        logger.info(f"Alerts are being written to {config.ALERT_LOG_CSV} and {config.ALERT_LOG_TEXT}")
        logger.info("Start the dashboard separately with: python dashboard/app.py")

        try:
            self.sniffer.start(self.handle_packet)
        except KeyboardInterrupt:
            logger.info("Stopping NIDS (Ctrl+C received).")
        finally:
            self._stop_periodic_dump.set()
            self.stats.dump()


if __name__ == "__main__":
    nids = NIDS()
    nids.run()
