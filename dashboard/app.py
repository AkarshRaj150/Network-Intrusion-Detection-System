"""
dashboard/app.py
------------------
A small Flask web server that reads the alert CSV and a live traffic
stats file, and serves them to a browser page (templates/index.html)
which draws charts with Chart.js.

Beginner note on architecture: the sniffer/detectors run in one Python
process (main.py) and write to files (logs/alerts.csv,
logs/traffic_stats.json). This Flask app runs as a SEPARATE process
and just reads those files. This is a simple, robust way to connect a
background monitoring process to a web UI without dealing with
sockets or shared memory - the filesystem is the "message bus".
"""
import csv
import json
import os
import sys

from flask import Flask, jsonify, render_template

# Allow importing config.py from the project root when this file is
# run directly (python dashboard/app.py)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", refresh_ms=config.DASHBOARD_REFRESH_MS)


@app.route("/api/alerts")
def api_alerts():
    """Return the most recent alerts as JSON for the table on the dashboard."""
    alerts = []
    if os.path.exists(config.ALERT_LOG_CSV):
        with open(config.ALERT_LOG_CSV, newline="") as f:
            reader = csv.DictReader(f)
            alerts = list(reader)
    # Most recent first, cap at 200 rows so the page stays fast
    alerts = list(reversed(alerts))[:200]
    return jsonify(alerts)


@app.route("/api/stats")
def api_stats():
    """Return live traffic counters written by main.py."""
    stats_path = "logs/traffic_stats.json"
    if os.path.exists(stats_path):
        with open(stats_path) as f:
            try:
                return jsonify(json.load(f))
            except json.JSONDecodeError:
                pass
    return jsonify({
        "total_packets": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
        "alerts_by_type": {}, "top_talkers": {}
    })


if __name__ == "__main__":
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=True)
