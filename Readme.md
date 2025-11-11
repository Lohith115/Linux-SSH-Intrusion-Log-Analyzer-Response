# Advanced Linux Log Analyzer

## 1. Overview
Advanced Linux Log Analyzer is a Python-based real-time SSH log monitoring tool designed to detect suspicious login activity in Linux systems. It continuously monitors `/var/log/auth.log`, identifies failed SSH login attempts, sends email alerts to administrators, and automatically blocks offending IP addresses using `ipset` and `iptables`.

The analyzer is optimized for private network monitoring and includes a temporary block feature with automatic unblocking after a configurable cooldown period.

---

## 2. Features
- Real-time monitoring of `/var/log/auth.log`
- Automatic detection of failed SSH login attempts
- Configurable threshold for failed attempts
- Sliding time window to prevent old entries from triggering alerts
- Deduplication to avoid multiple counts from one login attempt
- Email notifications via SMTP (supports SSL and STARTTLS)
- Automatic IP blocking using `ipset` with timeout
- Automatic unblocking after cooldown
- Log of all block and unblock events
- Configurable settings through `config.json`

---

## 3. Project Structure
AdvancedLogAnalyzer/
├── main.py # Core analyzer script
├── utils.py # Helper functions (email, IP utilities, config loader)
├── config.json # Configuration file (excluded from Git)
└──  README.md # Documentation


---

## 4. Configuration

The configuration file `config.json` contains the operational settings.

Example:

```json
{
  "LOG_FILE": "/var/log/auth.log",
  "FAILED_THRESHOLD": 2,
  "FAILED_WINDOW_SECONDS": 300,
  "FAILED_DEDUP_SECONDS": 2,

  "BLOCK_ENABLED": "true",
  "BLOCK_ONLY_PRIVATE": "true",
  "BLOCK_SET_NAME": "blocked_ips",
  "BLOCK_TIMEOUT_SECONDS": 120,
  "BLOCK_WHITELIST": "",
  "BLOCK_LOG_PATH": "/var/log/advanced_log_analyzer_blocks.log",

  "EMAIL_SENDER": "example@gmail.com",
  "EMAIL_RECEIVER": "example@gmail.com",
  "EMAIL_APP_PASSWORD": "app_password_here",
  "EMAIL_USE_SSL": "true",
  "EMAIL_SMTP_SERVER": "smtp.gmail.com",
  "EMAIL_SMTP_PORT": "465",
  "EMAIL_SUBJECT": "AdvancedLogAnalyzer Alert"
}
```


## 5. Installation and Setup

Step 1: Clone the repository 
```bash
git clone https://github.com/Lohith115/AdvancedLogAnalyzer.git
```
```bash
cd AdvancedLogAnalyzer
```

Step 2: Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```
Step 4: Configure email and thresholds

Edit config.json and update values as required.

5. Usage
Start the Analyzer
```bash
python3 main.py
```

The analyzer begins reading /var/log/auth.log and follows new log entries in real time.

To Test try to login with ssh from anothe device from the same network !!! 

When the threshold is reached, an alert email is sent and the IP is temporarily blocked.

Verify Block Status:
```bash
sudo ipset list blocked_ips
```
```bash
sudo tail -n 10 /var/log/advanced_log_analyzer_blocks.log
```
6. Auto Unblock

Each blocked IP is automatically unblocked after the duration specified by BLOCK_TIMEOUT_SECONDS.
Unblock events are logged in
```bash
/var/log/advanced_log_analyzer_blocks.log.
```
7. Future Enhancements

Integration with threat intelligence feeds for external IP enrichment

Web-based dashboard for visualization

Persistent storage of counters and logs in a database

Integration with SIEM tools such as Splunk or ELK

Containerization for deployment automation

8. Author

Developed by Lohith,
 
