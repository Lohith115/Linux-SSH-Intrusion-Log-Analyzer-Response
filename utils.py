# utils.py
import re
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ipaddress import ip_address, AddressValueError
import subprocess
import requests

def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

config = load_config()

# --- Log parsing ------------------------------------------------------------
def extract_failed_ips(log_path):
    """
    Parse the log file for 'Failed password' lines and count occurrences per IP.
    Returns dict: { ip: count }
    """
    pattern = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
    failed_ips = {}
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    failed_ips[ip] = failed_ips.get(ip, 0) + 1
    except FileNotFoundError:
        # If file not present, return empty
        return {}
    return failed_ips

# --- IP utilities -----------------------------------------------------------
def is_private_ip(ip):
    try:
        return ip_address(ip).is_private
    except AddressValueError:
        return False

# --- Geolocation ------------------------------------------------------------
def geo_lookup(ip: str) -> str:
    """
    Lookup public IP geolocation. For private IPs returns a friendly message.
    Uses ip-api.com as primary source; falls back to simple failure message.
    """
    if is_private_ip(ip):
        return f"Private network ({ip})"

    # Primary: ip-api.com (free, demo friendly)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            j = resp.json()
            if j.get("status") == "success":
                city = j.get("city") or "-"
                region = j.get("regionName") or "-"
                country = j.get("country") or "-"
                return f"{city}, {region}, {country}"
    except Exception:
        pass

    # If ip-api failed:
    return "Geo lookup failed"

# --- Email alert ------------------------------------------------------------
def send_alert_email(alert_text):
    sender = config.get("EMAIL_SENDER")
    receiver = config.get("EMAIL_RECEIVER")
    password = config.get("EMAIL_APP_PASSWORD")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🚨 Suspicious IPs Detected"
    msg["From"] = sender
    msg["To"] = receiver

    part = MIMEText(alert_text, "plain")
    msg.attach(part)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
            print("[+] Alert email sent successfully.")
    except Exception as e:
        print(f"[!] Email sending failed: {e}")

