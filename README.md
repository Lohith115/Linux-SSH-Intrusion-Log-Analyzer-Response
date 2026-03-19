# Advanced Linux Log Analyzer — SSH Intrusion Detection & Auto-Response

> A real-time SSH brute-force detection engine that monitors Linux authentication logs, automatically blocks offending IP addresses via `ipset`/`iptables`, and dispatches SMTP email alerts to administrators — with configurable thresholds, sliding time windows, and timed auto-unblock.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Linux](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![ipset](https://img.shields.io/badge/Blocking-ipset%20%2B%20iptables-red?style=flat-square)
![SMTP](https://img.shields.io/badge/Alerts-SMTP%20Email-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Detection Logic](#detection-logic)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Future Roadmap](#future-roadmap)

---

## Overview

SSH brute-force attacks are one of the most common attack vectors against internet-facing Linux servers. This tool provides an active defense layer — not just detection, but automated response.

Unlike `fail2ban` which operates as a daemon with complex configuration, this analyzer is a lightweight Python script with a single JSON config file, a transparent codebase, and a response pipeline that is easy to audit and extend.

**What it does:**
1. Tails `/var/log/auth.log` in real time
2. Counts failed SSH login attempts per IP using a sliding time window
3. Deduplicates rapid retry bursts to avoid double-counting
4. On threshold breach: blocks the IP with `ipset` (auto-expires after timeout) and sends an SMTP email alert
5. Logs all block and unblock events to a dedicated audit log

**Who it is for:** System administrators, Blue Team analysts, and security engineers who want a transparent, scriptable SSH defense layer they fully understand and control.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               /var/log/auth.log                             │
│   Real-time tail — new lines read as they appear            │
└────────────────────────┬────────────────────────────────────┘
                         │ raw log lines
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     main.py                                 │
│                                                             │
│  Line Parser                                                │
│  └─ Regex match: "Failed password for .* from <IP>"        │
│                                                             │
│  Deduplication Filter                                       │
│  └─ Ignores repeat events within FAILED_DEDUP_SECONDS      │
│                                                             │
│  Sliding Window Counter (per IP)                            │
│  └─ Counts failures within FAILED_WINDOW_SECONDS           │
│  └─ Evicts old timestamps outside the window               │
│                                                             │
│  Threshold Check                                            │
│  └─ If count >= FAILED_THRESHOLD: trigger response         │
└────────┬───────────────────────────────────────────────────┘
         │ threshold breached
         ▼
┌────────────────────────────────────────────────────────────┐
│                     utils.py                               │
│                                                            │
│  block_ip(ip)                                              │
│  └─ sudo ipset add blocked_ips <IP> timeout <N>           │
│  └─ ipset auto-expires IP after BLOCK_TIMEOUT_SECONDS     │
│                                                            │
│  send_alert_email(ip, count)                               │
│  └─ SMTP SSL or STARTTLS                                   │
│  └─ Gmail App Password supported                           │
│                                                            │
│  log_block_event(ip)                                       │
│  └─ Appends to BLOCK_LOG_PATH with timestamp              │
└────────────────────────────────────────────────────────────┘
         │ after BLOCK_TIMEOUT_SECONDS
         ▼
┌────────────────────────────────────────────────────────────┐
│  ipset auto-unblock                                        │
│  └─ IP removed from blocked_ips set automatically         │
│  └─ Unblock event logged to BLOCK_LOG_PATH                │
└────────────────────────────────────────────────────────────┘
```

---

## Features

- **Real-time log monitoring** — tails `/var/log/auth.log` continuously, processes new lines as they appear
- **Sliding time window** — counts failures only within `FAILED_WINDOW_SECONDS`, old entries automatically evicted
- **Deduplication** — ignores repeated log entries from the same IP within `FAILED_DEDUP_SECONDS` to prevent false inflation from log rotation or rapid retries
- **Configurable threshold** — set `FAILED_THRESHOLD` to tune sensitivity (default: 5 failures)
- **Automatic IP blocking** — uses `ipset` with timeout for kernel-level packet dropping
- **Auto-unblock** — `ipset` timeout handles removal automatically, no cron job needed
- **SMTP email alerts** — supports both SSL (port 465) and STARTTLS (port 587), Gmail App Password compatible
- **Private-network-only mode** — `BLOCK_ONLY_PRIVATE: true` limits blocking to RFC1918 addresses (safe for internal network monitoring)
- **IP whitelist** — comma-separated whitelist prevents blocking trusted hosts
- **Audit log** — all block and unblock events written to a dedicated log file with timestamps
- **Single JSON config** — all operational settings in `config.json`, excluded from Git via `.gitignore`

---

## Detection Logic

### Sliding Window Algorithm

For each incoming failed SSH attempt from an IP:

```
1. Record timestamp of this failure
2. Evict all timestamps older than FAILED_WINDOW_SECONDS from this IP's list
3. Count remaining timestamps
4. If count >= FAILED_THRESHOLD → trigger block + alert
```

This means: if an attacker sends 4 failures, waits 6 minutes, then sends 4 more — no alert. The window resets. This prevents false positives from slow distributed attacks while catching rapid brute-force attempts.

### Deduplication

SSH sometimes logs the same failure event twice in rapid succession (log buffering). `FAILED_DEDUP_SECONDS` (default: 2) ignores repeat events from the same IP within that window so one failure does not count as two.

### Block Mechanism

```bash
# What the tool runs under the hood:
sudo ipset add blocked_ips <IP> timeout 120

# Packets from this IP are dropped at kernel level by:
sudo iptables -I INPUT -m set --match-set blocked_ips src -j DROP
```

The `iptables` rule is set up once at startup. `ipset` manages the IP list — adding and expiring entries automatically. This is significantly faster than individual `iptables` rules per IP because `ipset` uses hash-based lookup.

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Core script | Python 3.8+ | Log parsing, window tracking, orchestration |
| IP blocking | ipset + iptables | Kernel-level packet filtering |
| Email alerts | smtplib (stdlib) | SMTP SSL/STARTTLS alert delivery |
| Configuration | JSON | Single-file operational config |
| Log monitoring | Python file tail | Real-time `/var/log/auth.log` reading |
| Audit logging | Python logging | Block/unblock event trail |

**No external Python dependencies** — uses only Python standard library (`smtplib`, `json`, `re`, `subprocess`, `logging`, `time`, `collections`).

---

## Project Structure

```
AdvancedLogAnalyzer/
├── main.py          # Core analyzer — log tailing, window tracking, threshold logic
├── utils.py         # Helper functions — block_ip(), send_email(), config_loader()
├── config.json      # Operational config (excluded from Git — see config below)
└── README.md        # Documentation
```

---

## Setup & Installation

### Prerequisites

- Linux system with `auth.log` SSH logging enabled
- Python 3.8+
- `ipset` installed: `sudo apt install ipset`
- Root or sudo access (required for `ipset` and `iptables` commands)
- Gmail account with App Password enabled (or any SMTP provider)

### 1. Clone the repository

```bash
git clone https://github.com/Lohith115/AdvancedLogAnalyzer.git
cd AdvancedLogAnalyzer
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

No pip installs needed — standard library only.

### 3. Initialize ipset

Run once to create the IP block set and the iptables rule:

```bash
sudo ipset create blocked_ips hash:ip timeout 0
sudo iptables -I INPUT -m set --match-set blocked_ips src -j DROP
```

The `timeout 0` sets no default timeout — individual IPs get their own timeout from config.

### 4. Create config.json

Create `config.json` in the project root (this file is gitignored — never commit it):

```json
{
  "LOG_FILE": "/var/log/auth.log",
  "FAILED_THRESHOLD": 5,
  "FAILED_WINDOW_SECONDS": 300,
  "FAILED_DEDUP_SECONDS": 2,

  "BLOCK_ENABLED": "true",
  "BLOCK_ONLY_PRIVATE": "false",
  "BLOCK_SET_NAME": "blocked_ips",
  "BLOCK_TIMEOUT_SECONDS": 3600,
  "BLOCK_WHITELIST": "192.168.1.1,10.0.0.1",
  "BLOCK_LOG_PATH": "/var/log/advanced_log_analyzer_blocks.log",

  "EMAIL_SENDER": "your_email@gmail.com",
  "EMAIL_RECEIVER": "admin@yourdomain.com",
  "EMAIL_APP_PASSWORD": "xxxx xxxx xxxx xxxx",
  "EMAIL_USE_SSL": "true",
  "EMAIL_SMTP_SERVER": "smtp.gmail.com",
  "EMAIL_SMTP_PORT": "465",
  "EMAIL_SUBJECT": "SSH Brute Force Alert"
}
```

### 5. Gmail App Password setup

1. Enable 2FA on your Gmail account
2. Go to: Google Account → Security → App Passwords
3. Generate a password for "Mail" → copy the 16-character code
4. Paste into `EMAIL_APP_PASSWORD` in config.json

---

## Configuration Reference

| Parameter | Type | Description |
|-----------|------|-------------|
| `LOG_FILE` | string | Path to SSH auth log (default: `/var/log/auth.log`) |
| `FAILED_THRESHOLD` | int | Number of failures before blocking (default: 5) |
| `FAILED_WINDOW_SECONDS` | int | Time window for counting failures in seconds (default: 300) |
| `FAILED_DEDUP_SECONDS` | int | Ignore duplicate events within this window (default: 2) |
| `BLOCK_ENABLED` | bool string | Enable/disable IP blocking ("true"/"false") |
| `BLOCK_ONLY_PRIVATE` | bool string | Only block RFC1918 private IPs ("true"/"false") |
| `BLOCK_SET_NAME` | string | ipset set name (must match ipset create command) |
| `BLOCK_TIMEOUT_SECONDS` | int | Seconds before auto-unblock (default: 3600 = 1 hour) |
| `BLOCK_WHITELIST` | string | Comma-separated IPs to never block |
| `BLOCK_LOG_PATH` | string | Path for block/unblock audit log |
| `EMAIL_SENDER` | string | Sender email address |
| `EMAIL_RECEIVER` | string | Alert recipient email address |
| `EMAIL_APP_PASSWORD` | string | SMTP authentication password |
| `EMAIL_USE_SSL` | bool string | SSL (port 465) vs STARTTLS (port 587) |
| `EMAIL_SMTP_SERVER` | string | SMTP server hostname |
| `EMAIL_SMTP_PORT` | string | SMTP port number |
| `EMAIL_SUBJECT` | string | Email alert subject line |

---

## Usage

### Start the analyzer

```bash
# Must run with sudo for ipset/iptables access
sudo python3 main.py
```

The analyzer begins tailing the log file and processing new entries in real time. It will print status messages as events are detected.

### Monitor block status

```bash
# View currently blocked IPs
sudo ipset list blocked_ips

# View block/unblock audit log
sudo tail -f /var/log/advanced_log_analyzer_blocks.log

# Check iptables rule is active
sudo iptables -L INPUT -n | grep blocked_ips
```

### Unblock an IP manually

```bash
sudo ipset del blocked_ips 192.168.1.100
```

### Run as a background service

Create `/etc/systemd/system/advanced-log-analyzer.service`:

```ini
[Unit]
Description=Advanced Linux Log Analyzer
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/AdvancedLogAnalyzer
ExecStart=/path/to/AdvancedLogAnalyzer/venv/bin/python3 main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable advanced-log-analyzer
sudo systemctl start advanced-log-analyzer
sudo systemctl status advanced-log-analyzer
```

---

## Testing

### Simulate a brute-force attack

From another machine on the same network, run repeated failed SSH attempts:

```bash
# Replace <server-ip> with the target machine's IP
for i in $(seq 1 10); do
    ssh wronguser@<server-ip> 2>/dev/null || true
    sleep 0.5
done
```

Within seconds of hitting the threshold, you should see:
1. Console output showing the detection
2. Email alert in your inbox
3. IP appearing in `sudo ipset list blocked_ips`
4. Block event in the audit log

### Check detection without blocking

Set `BLOCK_ENABLED: "false"` in config.json to run in detection-only mode — alerts fire but no IPs are blocked. Useful for tuning thresholds before enabling active response.

---

## Future Roadmap

- [ ] Web dashboard — real-time visualization of blocked IPs and attack timeline
- [ ] Threat intelligence enrichment — check attacker IPs against AbuseIPDB on detection
- [ ] SQLite persistence — store attack history across restarts for trend analysis
- [ ] SIEM integration — forward alerts to Splunk or ELK via syslog
- [ ] Slack/Webhook notifications — alternative to email alerts
- [ ] GeoIP lookup — include attacker country in alert email
- [ ] Docker container — portable deployment without system-level setup

---

## Author

**T Lohith** — M.Tech Networks & Cybersecurity, Amity University Gurugram

Specializing in OT/ICS security and Blue Team operations. This project is part of a cybersecurity portfolio targeting SOC Analyst and Security Engineer roles.

- GitHub: [github.com/Lohith115](https://github.com/Lohith115)
- LinkedIn: [linkedin.com/in/its-lohith-944909318](https://linkedin.com/in/its-lohith-944909318)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
