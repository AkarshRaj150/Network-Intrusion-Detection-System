"""
alerts/alert_manager.py
-------------------------
Takes alert dictionaries produced by the detection engines and:
  1. Writes them to a CSV file (so the dashboard and Excel can read them)
  2. Writes a human-readable line to a text log
  3. Optionally sends an email (if you enabled it in config.py)

Beginner note on email: we use Python's built-in `smtplib` and `email`
libraries - no extra installs needed. Gmail (and most providers) will
NOT accept your normal account password for this; you need an
"app password". Full instructions are in the README.
"""
import csv
import os
import smtplib
import time
from datetime import datetime
from email.mime.text import MIMEText

import config
from utils.logger import get_logger

logger = get_logger("AlertManager")


class AlertManager:
    def __init__(self):
        os.makedirs(os.path.dirname(config.ALERT_LOG_CSV), exist_ok=True)
        self._init_csv()
        self._last_email_sent = {}

    def _init_csv(self):
        # Only write the header row if the file doesn't exist yet,
        # so we don't wipe out alert history every time we restart.
        if not os.path.exists(config.ALERT_LOG_CSV):
            with open(config.ALERT_LOG_CSV, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "attack_type", "severity",
                    "src_ip", "dst_ip", "detail"
                ])

    def raise_alert(self, alert):
        """
        alert is a dict with keys: type, severity, src_ip, dst_ip, detail
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. CSV log (structured, used by the dashboard)
        with open(config.ALERT_LOG_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, alert["type"], alert["severity"],
                alert["src_ip"], alert["dst_ip"], alert["detail"]
            ])

        # 2. Human-readable text log
        line = (f"[{timestamp}] {alert['severity']:<6} {alert['type']:<28} "
                f"src={alert['src_ip']:<15} dst={alert['dst_ip']:<15} "
                f"{alert['detail']}")
        with open(config.ALERT_LOG_TEXT, "a") as f:
            f.write(line + "\n")

        logger.warning(line)

        # 3. Email (optional, rate-limited so you don't get flooded)
        if config.EMAIL_ALERTS_ENABLED:
            self._maybe_send_email(alert, timestamp)

    def _maybe_send_email(self, alert, timestamp):
        key = (alert["type"], alert["src_ip"])
        last = self._last_email_sent.get(key, 0)
        if time.time() - last < config.EMAIL_COOLDOWN_SECONDS:
            return  # still in cooldown, skip to avoid spamming your inbox
        self._last_email_sent[key] = time.time()

        subject = f"[NIDS ALERT] {alert['type']} from {alert['src_ip']}"
        body = (
            f"Time: {timestamp}\n"
            f"Attack type: {alert['type']}\n"
            f"Severity: {alert['severity']}\n"
            f"Source IP: {alert['src_ip']}\n"
            f"Destination IP: {alert['dst_ip']}\n"
            f"Details: {alert['detail']}\n"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = config.EMAIL_FROM
        msg["To"] = config.EMAIL_TO

        try:
            with smtplib.SMTP(config.EMAIL_SMTP_SERVER, config.EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(config.EMAIL_FROM, config.EMAIL_APP_PASSWORD)
                server.sendmail(config.EMAIL_FROM, [config.EMAIL_TO], msg.as_string())
            logger.info(f"Email alert sent for {alert['type']} from {alert['src_ip']}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
