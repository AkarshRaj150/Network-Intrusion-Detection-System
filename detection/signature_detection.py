"""
detection/signature_detection.py
---------------------------------
"Signature-based" detection means: we know exactly what a specific
attack pattern looks like, and we check incoming traffic against that
known pattern. This is the same idea as antivirus signatures, just for
network behavior instead of files.

We implement three classic, well-known patterns:

1. PORT SCAN - one source IP touches many different ports on your
   machine in a short time. This is how attackers map out what
   services you're running before attacking one of them.

2. DoS / FLOOD - one source sends a very large number of packets to a
   single destination in a short time, trying to overwhelm it.

3. BRUTE FORCE - one source repeatedly opens connections to a
   sensitive port (SSH, RDP, FTP, etc), consistent with automated
   password-guessing tools like Hydra.

Beginner note on the data structure: we use `deque` (a list that's
efficient to add/remove from both ends) to store recent timestamps per
source IP, and periodically drop entries older than our time window.
This is a simple, common way to implement a "sliding window" without
a database.
"""
from collections import defaultdict, deque
import time

import config
from utils.logger import get_logger

logger = get_logger("SignatureDetection")


class SignatureDetector:
    def __init__(self):
        # Maps src_ip -> deque of (timestamp, dst_port) for port scan detection
        self._port_touches = defaultdict(deque)

        # Maps (src_ip, dst_ip) -> deque of timestamps, for DoS detection
        self._dst_traffic = defaultdict(deque)

        # Maps (src_ip, dst_port) -> deque of timestamps, for brute force detection
        self._brute_force_attempts = defaultdict(deque)

        # Prevents re-alerting every single packet once a threshold is
        # crossed - we only want ONE alert per "incident", not thousands.
        self._recent_alerts = {}
        self._alert_cooldown = 15  # seconds before the same alert type can fire again

    def _cooldown_ok(self, key):
        now = time.time()
        last = self._recent_alerts.get(key, 0)
        if now - last > self._alert_cooldown:
            self._recent_alerts[key] = now
            return True
        return False

    def _trim(self, dq, window):
        """Remove timestamps older than `window` seconds from the front of dq."""
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def inspect(self, packet):
        """
        Feed one parsed packet dict in. Returns a list of alert dicts
        (usually empty, sometimes one or more) describing anything
        suspicious detected on THIS packet.
        """
        alerts = []
        src = packet["src_ip"]
        dst = packet["dst_ip"]
        dst_port = packet["dst_port"]
        now = packet["timestamp"]

        # ---------------- PORT SCAN ----------------
        if dst_port is not None:
            key = src
            dq = self._port_touches[key]
            dq.append((now, dst_port))
            self._trim_ports(dq)

            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= config.PORT_SCAN_UNIQUE_PORTS:
                if self._cooldown_ok(("PORT_SCAN", src)):
                    alerts.append({
                        "type": "Port Scan",
                        "severity": "Medium",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": f"{len(unique_ports)} distinct ports touched "
                                  f"in {config.PORT_SCAN_WINDOW_SECONDS}s"
                    })

        # ---------------- DoS / FLOOD ----------------
        key = (src, dst)
        dq = self._dst_traffic[key]
        dq.append(now)
        self._trim(dq, config.DOS_WINDOW_SECONDS)

        if len(dq) >= config.DOS_PACKET_COUNT:
            if self._cooldown_ok(("DOS", src, dst)):
                alerts.append({
                    "type": "DoS / Flood",
                    "severity": "High",
                    "src_ip": src,
                    "dst_ip": dst,
                    "detail": f"{len(dq)} packets in {config.DOS_WINDOW_SECONDS}s"
                })

        # ---------------- BRUTE FORCE ----------------
        # A SYN packet (flags == 'S') represents a new connection attempt.
        if dst_port in config.BRUTE_FORCE_PORTS and packet.get("flags") == "S":
            key = (src, dst_port)
            dq = self._brute_force_attempts[key]
            dq.append(now)
            self._trim(dq, config.BRUTE_FORCE_WINDOW_SECONDS)

            if len(dq) >= config.BRUTE_FORCE_ATTEMPTS:
                if self._cooldown_ok(("BRUTE_FORCE", src, dst_port)):
                    alerts.append({
                        "type": "Brute Force",
                        "severity": "High",
                        "src_ip": src,
                        "dst_ip": dst,
                        "detail": f"{len(dq)} connection attempts to port "
                                  f"{dst_port} in {config.BRUTE_FORCE_WINDOW_SECONDS}s"
                    })

        return alerts

    def _trim_ports(self, dq):
        cutoff = time.time() - config.PORT_SCAN_WINDOW_SECONDS
        while dq and dq[0][0] < cutoff:
            dq.popleft()
