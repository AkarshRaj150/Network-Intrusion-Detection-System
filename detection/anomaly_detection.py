"""
detection/anomaly_detection.py
--------------------------------
"Anomaly-based" detection is different from signature-based: instead of
matching a KNOWN attack pattern, we learn what "normal" looks like for
each source IP, and flag anything that's statistically far outside
normal. This can catch NEW or unknown attacks that don't match any
existing signature - but it can also be noisier (more false positives).

The method here is a simple, classic one: the Z-SCORE.

    z = (current_value - mean) / standard_deviation

A z-score tells you "how many standard deviations away from average is
this?". If a source IP normally sends ~5 packets/second, and suddenly
sends 80 packets/second, that will produce a huge z-score, and we flag
it. This is the same statistical idea used in fraud detection and
quality control charts - nothing fancier is needed to get real value.

Beginner note: we compute one z-score for "packets per second" and one
for "distinct connections per minute", per source IP. We keep a short
rolling history (deque) to compute the mean/stdev instead of using a
fixed hand-picked "normal" number, so the system adapts to your actual
network over time.
"""
from collections import defaultdict, deque
import statistics
import time

import config
from utils.logger import get_logger

logger = get_logger("AnomalyDetection")


class AnomalyDetector:
    def __init__(self):
        # src_ip -> deque of packet timestamps (last ANOMALY_BASELINE_WINDOW seconds)
        self._packet_times = defaultdict(deque)

        # src_ip -> deque of (timestamp, dst_ip) for connection-count tracking
        self._connections = defaultdict(deque)

        # src_ip -> deque of historical "packets per second" samples,
        # used to build the mean/stdev baseline
        self._rate_history = defaultdict(lambda: deque(maxlen=120))

        self._last_sample_time = defaultdict(float)
        self._recent_alerts = {}
        self._alert_cooldown = 20

    def _cooldown_ok(self, key):
        now = time.time()
        last = self._recent_alerts.get(key, 0)
        if now - last > self._alert_cooldown:
            self._recent_alerts[key] = now
            return True
        return False

    def inspect(self, packet):
        alerts = []
        src = packet["src_ip"]
        dst = packet["dst_ip"]
        now = packet["timestamp"]

        # Track raw packet timestamps for this source
        dq = self._packet_times[src]
        dq.append(now)
        cutoff = now - config.ANOMALY_BASELINE_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()

        # Sample the current rate roughly once per second per source,
        # so our history is "packets/sec over time" rather than being
        # recomputed on every single packet.
        if now - self._last_sample_time[src] >= 1.0:
            current_rate = len(dq) / max(1, config.ANOMALY_BASELINE_WINDOW)
            history = self._rate_history[src]
            history.append(current_rate)
            self._last_sample_time[src] = now

            if len(history) >= config.ANOMALY_MIN_SAMPLES:
                mean = statistics.mean(history)
                stdev = statistics.pstdev(history) or 0.0001  # avoid divide-by-zero
                z = (current_rate - mean) / stdev

                if z >= config.ANOMALY_ZSCORE_THRESHOLD:
                    if self._cooldown_ok(("ANOMALY_RATE", src)):
                        alerts.append({
                            "type": "Anomalous Traffic Rate",
                            "severity": "Medium",
                            "src_ip": src,
                            "dst_ip": dst,
                            "detail": f"Packet rate z-score={z:.2f} "
                                      f"(current={current_rate:.2f}/s, "
                                      f"baseline avg={mean:.2f}/s)"
                        })

        # Track distinct destination IPs contacted (connection fan-out)
        cdq = self._connections[src]
        cdq.append((now, dst))
        cutoff = now - 60
        while cdq and cdq[0][0] < cutoff:
            cdq.popleft()
        distinct_dsts = len({d for _, d in cdq})

        # A source suddenly talking to a huge number of different
        # destinations in a minute is unusual for normal client behavior
        # (this can indicate scanning or a compromised host beaconing out).
        if distinct_dsts >= 25:
            if self._cooldown_ok(("ANOMALY_FANOUT", src)):
                alerts.append({
                    "type": "Anomalous Connection Fan-out",
                    "severity": "Medium",
                    "src_ip": src,
                    "dst_ip": dst,
                    "detail": f"{distinct_dsts} distinct destinations contacted in 60s"
                })

        return alerts
