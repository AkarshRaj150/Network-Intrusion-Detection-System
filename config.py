"""
config.py
---------
All the "tunable knobs" for the NIDS live here. Beginner note:
Instead of hunting through every file to change a number (like how many
ports-per-second counts as a port scan), you change it once, here.
"""

# ----------------------------------------------------------------------
# NETWORK INTERFACE
# ----------------------------------------------------------------------
# The network card Scapy should listen on.
# On Linux, run `ip a` in a terminal to see interface names (eth0, wlan0, ...)
# On Windows, Scapy will print a list of interfaces if you get this wrong.
# Leave as None to let Scapy pick automatically (not always reliable).
INTERFACE = None

# ----------------------------------------------------------------------
# SIGNATURE-BASED DETECTION THRESHOLDS
# ----------------------------------------------------------------------
# Port scan: an attacker who touches many different ports on your machine
# in a short window is almost certainly scanning you.
PORT_SCAN_UNIQUE_PORTS = 15      # distinct ports from one source IP...
PORT_SCAN_WINDOW_SECONDS = 5     # ...within this many seconds

# DoS / flood: a huge number of packets aimed at one destination in a
# short time suggests a denial-of-service attempt.
DOS_PACKET_COUNT = 200           # packets to a single destination...
DOS_WINDOW_SECONDS = 5           # ...within this many seconds

# Brute force: repeated connection attempts to a "sensitive" port
# (SSH, RDP, FTP, Telnet, login-type services) from the same source.
BRUTE_FORCE_ATTEMPTS = 8         # connection attempts...
BRUTE_FORCE_WINDOW_SECONDS = 30  # ...within this many seconds
BRUTE_FORCE_PORTS = {21, 22, 23, 3389, 445, 3306, 5900}

# ----------------------------------------------------------------------
# ANOMALY-BASED DETECTION (statistical)
# ----------------------------------------------------------------------
# We keep a rolling baseline of "how many packets per second is normal"
# and "how many distinct connections per minute is normal" for each
# source IP, then flag anything that is statistically way outside that.
ANOMALY_BASELINE_WINDOW = 60      # seconds of history used to build the baseline
ANOMALY_ZSCORE_THRESHOLD = 3.0    # how many standard deviations = "anomalous"
ANOMALY_MIN_SAMPLES = 10          # don't judge anomalies until we have this many data points

# ----------------------------------------------------------------------
# ALERTING
# ----------------------------------------------------------------------
ALERT_LOG_CSV = "logs/alerts.csv"
ALERT_LOG_TEXT = "logs/alerts.log"

# Email alerts are OFF by default. Flip to True and fill in the fields
# below (see README "Setting up email alerts") to get real emails.
EMAIL_ALERTS_ENABLED = False
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_FROM = "your_email@gmail.com"
EMAIL_APP_PASSWORD = "your_app_password_here"   # NOT your normal password, see README
EMAIL_TO = "your_email@gmail.com"
# Don't spam: only send a real email if we haven't sent one for the same
# attack type + source IP in the last N seconds.
EMAIL_COOLDOWN_SECONDS = 300

# ----------------------------------------------------------------------
# DASHBOARD
# ----------------------------------------------------------------------
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
DASHBOARD_REFRESH_MS = 3000   # how often the browser polls for new data
