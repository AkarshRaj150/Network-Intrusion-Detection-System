# Network Intrusion Detection System (NIDS)

A working, from-scratch NIDS: a live packet sniffer, signature-based
rules (port scan / DoS / brute force), statistical anomaly detection,
an alert log with optional email notifications, and a web dashboard.

This README assumes you've never done a project like this before.
Follow it top to bottom in order.

---

## 0. What We Have Here!

Three pieces work together:

1. **Capture** (`capture/packet_sniffer.py`) — grabs raw packets off
   your network card using a library called Scapy, and pulls out the
   useful fields (who's talking to who, on what port, over TCP/UDP/ICMP).
2. **Detection** (`detection/`) — two independent engines look at each
   packet:
   - *Signature-based* (`signature_detection.py`): "does this match a
     known attack pattern?" (port scan, flood, brute force)
   - *Anomaly-based* (`anomaly_detection.py`): "is this statistically
     weird compared to what's normal?" (z-score on packet rate)
3. **Alerting + Dashboard** (`alerts/`, `dashboard/`) — anything
   flagged gets written to a log file and shown on a live web page.

`main.py` wires all three together for **live traffic**.
`replay.py` runs the exact same detection logic against a **CSV file**
instead — this is how you test everything without needing admin
privileges or a real attack happening on your network.

---

## 1. Install Python

You need Python 3.9 or newer.

- **Windows**: download from https://python.org/downloads, run the
  installer, and make sure you tick **"Add Python to PATH"** on the
  first screen.
- **Mac**: `brew install python3` (install Homebrew first from
  https://brew.sh if you don't have it), or download from python.org.
- **Linux**: usually already installed. Check with `python3 --version`;
  if missing, `sudo apt install python3 python3-pip` (Debian/Ubuntu).

Verify it worked by opening a terminal (Terminal on Mac/Linux,
Command Prompt or PowerShell on Windows) and running:
```
python3 --version
```
(On Windows this might just be `python --version` — if `python3`
isn't recognized, try `python`.)

---

## 2. Get the project files onto your machine

Download/copy the whole `nids_project` folder to somewhere easy to
find, e.g. `Documents/nids_project`. Open a terminal and move into it:
```
cd path/to/nids_project
```
Everything below assumes your terminal is sitting inside this folder.

---

## 3. Create a virtual environment (keeps this project's packages separate)

A virtual environment is just a private folder of Python packages so
this project doesn't mess with other Python projects on your machine.

```
python3 -m venv venv
```

Activate it (you'll need to do this every time you open a new
terminal to work on this project):

- **Mac/Linux**: `source venv/bin/activate`
- **Windows (PowerShell)**: `venv\Scripts\Activate.ps1`
- **Windows (Command Prompt)**: `venv\Scripts\activate.bat`

You'll know it worked because your terminal prompt now starts with
`(venv)`.

---

## 4. Install the dependencies

```
pip install -r requirements.txt
```

This installs **Scapy** (packet capture/parsing) and **Flask** (the
dashboard web server).

### A note about Scapy on Windows
Scapy needs **Npcap** to actually capture packets on Windows. Download
and install it from https://npcap.com/#download (check "Install Npcap
in WinPcap API-compatible mode" during install). Mac and Linux don't
need this extra step — they use the OS's built-in packet capture.

---

## 5. Try it WITHOUT touching real network traffic first (recommended)

Live packet capture needs admin/root privileges (step 6), so before
dealing with that, prove the detection logic works using the built-in
demo data:

```
python replay.py
```

This auto-generates a synthetic CSV (`data/demo_traffic.csv`) with
normal traffic plus an embedded port scan, DoS burst, and brute-force
attempt baked in, and runs it through the real detection engines.
You should see colored warning lines print in your terminal like:

```
2026-07-08 10:22:01 [WARNING] AlertManager: [10:22:01] Medium Port Scan   src=10.0.0.99 dst=192.168.1.100 15 distinct ports touched in 5s
2026-07-08 10:22:01 [WARNING] AlertManager: [10:22:01] High   DoS / Flood src=10.0.0.99 dst=192.168.1.100 200 packets in 5s
2026-07-08 10:22:01 [WARNING] AlertManager: [10:22:01] High   Brute Force src=10.0.0.99 dst=192.168.1.100 8 connection attempts to port 22 in 30s
```

Check `logs/alerts.csv` and `logs/alerts.log` — that's your alert log
deliverable, already populated.

---

## 6. Running the live packet sniffer

This is the real deal: capturing actual traffic off your network card.
**It requires elevated privileges** because reading raw packets is a
low-level OS operation normal programs aren't allowed to do.

- **Mac/Linux**:
  ```
  sudo venv/bin/python3 main.py
  ```
  (Using `venv/bin/python3` directly, instead of just `python3`, makes
  sure `sudo` still uses your virtual environment's installed packages.)

- **Windows**: Right-click Command Prompt or PowerShell → "Run as
  Administrator", then activate your venv and run:
  ```
  python main.py
  ```

You'll see it start up and then sit there printing alerts as they
happen. Press `Ctrl+C` to stop.

### If it picks the wrong network interface
Scapy tries to guess your active network card. If it's not capturing
anything, open `config.py` and set `INTERFACE` to the right name:
- Linux: run `ip a` in a terminal, look for something like `eth0` or `wlan0`
- Mac: run `ifconfig`, usually `en0`
- Windows: run `python3 -c "from scapy.all import show_interfaces; show_interfaces()"`
  with your venv activated, and copy the interface name shown

---

## 7. Running the dashboard

Open a **second terminal** (leave `main.py` or `replay.py` running in
the first one), activate the same virtual environment again, and run:

```
python dashboard/app.py
```

Then open your browser to **http://127.0.0.1:5000**

You'll see: live packet counters (TCP/UDP/ICMP), a running alert
table, a bar chart of alerts by type, and a "top talkers" list. It
polls the log files automatically every 3 seconds — no need to
refresh.

---

## 8. Testing it safely against yourself

You don't need a real attacker to see this work. From another
terminal (with `main.py` running as admin/root in the background),
you can safely trigger the rules against your own machine using
**nmap** (a standard, legal network scanning tool — only ever scan
systems you own):

- Install nmap: https://nmap.org/download.html
- Port scan trigger: `nmap -p 1-100 127.0.0.1` (touches 100 ports fast)
- SYN flood-ish trigger: `nmap -sS -p 80 --min-rate 500 127.0.0.1`

Watch the alert appear in your terminal and on the dashboard within a
few seconds.

**Do not run scans like this against any network or machine you don't
own or don't have explicit permission to test** — that's the line
between learning a skill and breaking a law.

---

## 9. Using a real labeled dataset (NSL-KDD / CIC-IDS2017 / UNSW-NB15)

The project description asks for one of these. Here's how to plug one in:

1. Download a dataset:
   - NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
   - CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
   - UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. These come as CSV files, but every dataset names its columns
   differently (e.g. CIC-IDS2017 might have `Source IP`, `Destination
   IP`, `Destination Port`; NSL-KDD's raw format doesn't even include
   IPs — it's pre-aggregated into connection records).
3. Open `replay.py` and edit the `MAPPING` dictionary near the top so
   the right-hand values match your CSV's actual column headers.
4. Put the CSV in the `data/` folder, then run:
   ```
   python replay.py --file data/your_dataset.csv --delay 0.01
   ```
   `--delay` slows playback down so it feels more like live traffic
   instead of instantly consuming a huge file (omit it to run at full
   speed).

If a dataset's format doesn't map cleanly onto `src_ip`/`dst_ip`/
`dst_port`/`protocol`/`flags`, that's normal — these datasets were
built for machine-learning research, not live packet replay. You'll
likely need a small script to convert the dataset's specific columns
into that shape first. That's a good next step once you're
comfortable with the base project.

---

## 10. Setting up real email alerts (optional)

By default, email is off — alerts only go to the log files and
dashboard. To get actual emails:

1. Open `config.py`, set `EMAIL_ALERTS_ENABLED = True`
2. Fill in `EMAIL_FROM`, `EMAIL_TO`
3. If using Gmail, you **cannot** use your normal password — Google
   blocks that for security. Instead create an "App Password":
   - Turn on 2-Step Verification on your Google account (required first)
   - Go to https://myaccount.google.com/apppasswords
   - Generate a password for "Mail", copy the 16-character code
   - Paste it into `EMAIL_APP_PASSWORD` in `config.py`
4. Save, then run `main.py` or `replay.py` again — a real attack alert
   will trigger a real email (rate-limited to one per attack-type/IP
   every 5 minutes so you don't get flooded).

---

## 11. Project structure reference

```
nids_project/
├── main.py                        # run this for LIVE capture
├── replay.py                      # run this for CSV/dataset replay (no admin needed)
├── config.py                      # every threshold and setting lives here
├── requirements.txt
├── capture/
│   └── packet_sniffer.py          # Scapy capture + TCP/UDP/ICMP parsing
├── detection/
│   ├── signature_detection.py     # port scan / DoS / brute force rules
│   └── anomaly_detection.py       # z-score based statistical anomalies
├── alerts/
│   └── alert_manager.py           # CSV + text log, optional email
├── dashboard/
│   ├── app.py                     # Flask server
│   └── templates/index.html       # the web UI
├── utils/
│   └── logger.py
├── data/                          # put downloaded datasets / demo CSV here
└── logs/                          # alerts.csv, alerts.log, nids.log, traffic_stats.json (auto-created)
```

---

## 12. Tuning detection thresholds

Everything is in `config.py` with comments explaining each value. If
you're getting too many false alarms on your own network, raise the
numbers (e.g. `PORT_SCAN_UNIQUE_PORTS = 25`). If you want it more
sensitive for a demo, lower them.

---

## 13. Common problems

| Problem | Fix |
|---|---|
| `PermissionError` when running `main.py` | You need `sudo` (Mac/Linux) or "Run as Administrator" (Windows) — see step 6 |
| No packets showing up | Wrong interface — see the "wrong network interface" note in step 6 |
| `ModuleNotFoundError: No module named 'scapy'` | Your venv isn't activated, or you forgot `pip install -r requirements.txt` |
| Dashboard shows all zeros | `main.py`/`replay.py` isn't running, or hasn't written `logs/traffic_stats.json` yet — wait a couple seconds |
| Windows: Scapy can't find any interfaces | Install Npcap (step 4) |

---

## 14. Where to go from here

- Add more signatures (e.g. ARP spoofing detection, DNS tunneling)
- Swap the z-score anomaly method for an isolation forest or
  `scikit-learn`'s `EllipticEnvelope` for a more advanced ML approach
- Persist alerts to SQLite instead of CSV once volume grows
- Add authentication to the dashboard before ever exposing it beyond
  localhost
