#!/usr/bin/env python3
"""
Advanced Linux Log Analyzer - main.py (private-IP blocking with 2-minute cooldown)
- Live mode by default (start fresh, follow new lines)
- Per-line detection of failed SSH attempts
- Optional auto-blocking using ipset + iptables (blocks ONLY private IPs if enabled)
- Block timeout (cooldown) default 120 seconds (2 minutes)
- Maintains a block log file at /var/log/advanced_log_analyzer_blocks.log (configurable)
"""

import argparse
import os
import sys
import time
import re
import subprocess
import shutil
import ipaddress
from datetime import datetime, timezone

# import your existing utilities; keep these as they are in your project
from utils import extract_failed_ips, geo_lookup, send_alert_email, config, is_private_ip

# --------------------------
# Existing full-file analyzer (keeps current behavior)
# --------------------------
def analyze():
    print("[*] Reading log file...")
    log_file = config.get("LOG_FILE", "/var/log/auth.log")
    threshold = int(config.get("FAILED_THRESHOLD", 3))

    failed_ips = extract_failed_ips(log_file)
    suspicious = {ip: count for ip, count in failed_ips.items() if count >= threshold}

    if suspicious:
        print(f"[+] Found {len(suspicious)} suspicious IP(s).")
        alert_lines = []
        alert_text = "🚨 Suspicious IPs Detected:\n\n"

        for ip, count in suspicious.items():
            if is_private_ip(ip):
                # internal/private handling
                location = f"Private network ({ip})"
                guidance = "Action: Investigate internal host (check DHCP leases, ARP table)"
            else:
                # public handling
                location = geo_lookup(ip)
                guidance = "Action: Enrich with threat-intel and consider blocking if malicious"

            line = f"{ip} — {count} attempts — {location} — {guidance}"
            alert_lines.append(line)
            alert_text += line + "\n"

        print(alert_text)
        send_alert_email(alert_text)
    else:
        print("[+] No suspicious activity above threshold.")


# --------------------------
# Streaming/live-mode helpers and state
# --------------------------
IP_RE = r'(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})'
FAILED_PATTERNS = [
    re.compile(rf'Failed password for .* from ({IP_RE})'),
    re.compile(rf'Invalid user .* from ({IP_RE})'),
    re.compile(rf'authentication failure; .* rhost=({IP_RE})'),
]

failed_counts = {}    # ip -> failure count
alerted_ips = set()   # ips already alerted (to avoid duplicate emails)
THRESHOLD_DEFAULT = int(config.get("FAILED_THRESHOLD", 3))

# block log file path (configurable)
BLOCK_LOG_PATH = config.get("BLOCK_LOG_PATH", "/var/log/advanced_log_analyzer_blocks.log")


def log_block_action(ip: str, action: str, reason: str = "", timeout_seconds: int = 0):
    """Append a structured log line to BLOCK_LOG_PATH. Non-fatal if write fails."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = f"{ts} | {action} | ip={ip} | timeout={timeout_seconds}s | reason={reason}\n"
    try:
        # ensure directory exists
        log_dir = os.path.dirname(BLOCK_LOG_PATH)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        with open(BLOCK_LOG_PATH, "a") as f:
            f.write(entry)
    except Exception as e:
        # do not crash the analyzer for logging errors; print a warning instead
        print(f"[WARN] Could not write to block log {BLOCK_LOG_PATH}: {e}")


# --------------------------
# ipset/iptable helper functions for auto-blocking
# --------------------------
def ensure_ipset_and_rule(set_name='blocked_ips'):
    """Create ipset and iptables rule if missing. Non-fatal if fails."""
    if shutil.which('ipset') is None or shutil.which('iptables') is None:
        print("[WARN] ipset/iptables not found; blocking disabled or unavailable.")
        return False

    try:
        subprocess.run(['sudo', 'ipset', 'list', set_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        try:
            # create a set with 0 default timeout (we use per-entry timeout)
            subprocess.check_call(['sudo', 'ipset', 'create', set_name, 'hash:ip', 'timeout', '0'])
            print(f"[INFO] Created ipset {set_name}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to create ipset {set_name}: {e}")
            return False

    try:
        out = subprocess.check_output(['sudo', 'iptables', '-L', 'INPUT', '-n', '--line-numbers'], text=True)
        if set_name not in out:
            subprocess.check_call(['sudo', 'iptables', '-I', 'INPUT', '-m', 'set', '--match-set', set_name, 'src', '-j', 'DROP'])
            print(f"[INFO] Inserted iptables DROP rule for ipset {set_name}")
    except subprocess.CalledProcessError as e:
        print(f"[WARN] Could not ensure iptables rule: {e}")
        # not fatal; ipset may still block at lower levels or via nft if configured
    return True


def block_ip(ip, set_name='blocked_ips', timeout_seconds=120, whitelist=None):
    """
    Add IP to ipset with timeout_seconds (0 => permanent).
    This function is now intended to block private IPs only per user's request.
    Returns True if added or already present, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        print(f"[ERROR] invalid IP to block: {ip}")
        log_block_action(ip, "block-failed", f"invalid-ip", timeout_seconds)
        return False

    # safety: only block private IPs in this build (user request)
    if not ip_obj.is_private:
        print(f"[INFO] Blocking is configured for private IPs only. Skipping non-private IP: {ip}")
        log_block_action(ip, "skip-block-nonprivate", "not-private", 0)
        return False

    # whitelist check (whitelist may contain IPs you must never block)
    if whitelist and ip in whitelist:
        print(f"[INFO] IP {ip} is whitelisted; not blocking.")
        log_block_action(ip, "skip-block-whitelist", "whitelisted", 0)
        return False

    if shutil.which('ipset') is None:
        print("[ERROR] ipset not available; cannot block.")
        log_block_action(ip, "block-failed", "ipset-missing", timeout_seconds)
        return False

    try:
        # add the IP with timeout if specified
        if timeout_seconds and timeout_seconds > 0:
            subprocess.check_call(['sudo', 'ipset', 'add', set_name, ip, 'timeout', str(timeout_seconds)])
        else:
            subprocess.check_call(['sudo', 'ipset', 'add', set_name, ip])
        print(f"[BLOCKED] {ip} added to {set_name} (timeout={timeout_seconds}s)")
        log_block_action(ip, "blocked", "threshold-exceeded", timeout_seconds)
        return True
    except subprocess.CalledProcessError as e:
        errmsg = str(e)
        if 'already added' in errmsg or 'already exists' in errmsg:
            print(f"[INFO] {ip} already in ipset {set_name}")
            log_block_action(ip, "already-blocked", "already-existed", timeout_seconds)
            return True
        print(f"[ERROR] Failed to add {ip} to ipset: {e}")
        log_block_action(ip, "block-failed", errmsg, timeout_seconds)
        return False


# --------------------------
# Per-line analysis for live mode
# --------------------------
def extract_ip_from_line(line: str):
    for pat in FAILED_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1)
    return None

# --- sliding-window attempt tracking (required helpers + handle_failed_ip) ---
import time
from collections import deque

# attempt_windows maps ip -> deque([ts1, ts2, ...]) of attempt timestamps (oldest left)
attempt_windows = {}

# alerted_ips set is used elsewhere in the file; keep it shared
# alerted_ips = set()   # do not re-declare if already declared above; if not present, uncomment

# sliding window length in seconds (configurable via FAILED_WINDOW_SECONDS)
WINDOW_SEC = int(config.get("FAILED_WINDOW_SECONDS", 300))

def prune_and_count(ip: str):
    """Prune timestamps older than WINDOW_SEC for ip and return current count."""
    now = time.time()
    dq = attempt_windows.get(ip)
    if dq is None:
        return 0
    # remove old timestamps from left while outside window
    while dq and (now - dq[0]) > WINDOW_SEC:
        dq.popleft()
    return len(dq)

def record_attempt(ip: str):
    """
    Record an attempt timestamp for ip but de-duplicate rapid repeated log lines.
    Returns new count (after prune).
    """
    now = time.time()
    dq = attempt_windows.get(ip)
    if dq is None:
        dq = deque()
        attempt_windows[ip] = dq

    # de-dup window (seconds): treat multiple log lines within this time as one attempt
    DEDUP_SEC = int(config.get("FAILED_DEDUP_SECONDS", 2))

    # if last attempt exists and is very recent, don't append (deduplicate)
    if dq and (now - dq[-1]) < DEDUP_SEC:
        # still prune old entries and return current count
        return prune_and_count(ip)

    # otherwise, append new attempt and prune
    dq.append(now)
    return prune_and_count(ip)

def handle_failed_ip(ip: str, threshold: int):
    """
    Record an attempt and handle alerting/blocking.
    - uses record_attempt() to maintain sliding window
    - when an IP is blocked successfully, clears its in-memory state and alerted flag
    """
    if not ip:
        return

    # record and get current count within the window
    count = record_attempt(ip)

    # debug for demo visibility
    print(f"[DEBUG] {ip} recent_attempts={count} (window={WINDOW_SEC}s)")

    # if threshold reached and not yet alerted
    if count >= threshold and ip not in alerted_ips:
        alerted_ips.add(ip)

        if is_private_ip(ip):
            location = f"Private network ({ip})"
            guidance = "Action: Investigate internal host (check DHCP leases, ARP table)"
        else:
            location = geo_lookup(ip)
            guidance = "Action: Enrich with threat-intel and consider blocking if malicious"

        line = f"{ip} — {count} attempts (last {WINDOW_SEC}s) — {location} — {guidance}"
        alert_text = "🚨 Suspicious IP Detected (live):\n\n" + line + "\n"
        print(alert_text)

        try:
            send_alert_email(alert_text)
        except Exception as e:
            print(f"[WARN] Email not sent: {e}")

        # --- automatic blocking (if enabled in config) ---
        try:
            block_enabled = config.get("BLOCK_ENABLED", "false").lower() in ("1", "true", "yes")
            if block_enabled:
                set_name = config.get("BLOCK_SET_NAME", "blocked_ips")
                timeout_seconds = int(config.get("BLOCK_TIMEOUT_SECONDS", 120))
                whitelist_str = config.get("BLOCK_WHITELIST", "")
                whitelist = {x.strip() for x in whitelist_str.split(",") if x.strip()} if whitelist_str else set()

                ensure_ipset_and_rule(set_name=set_name)

                # blocking policy: this build blocks private IPs only when BLOCK_ONLY_PRIVATE true
                blocked = False
                if config.get("BLOCK_ONLY_PRIVATE", "true").lower() in ("1", "true", "yes"):
                    blocked = block_ip(ip, set_name=set_name, timeout_seconds=timeout_seconds, whitelist=whitelist)
                else:
                    blocked = block_ip(ip, set_name=set_name, timeout_seconds=timeout_seconds, whitelist=whitelist)

                if blocked:
                    print(f"[INFO] {ip} blocked for {timeout_seconds} seconds (set {set_name})")
                    # CLEAR in-memory state & alerted flag for this IP so it starts fresh after block
                    try:
                        attempt_windows.pop(ip, None)
                        alerted_ips.discard(ip)
                        log_block_action(ip, "blocked_and_state_cleared", "state-reset-after-block", timeout_seconds)
                    except Exception as e:
                        print(f"[WARN] Failed to reset in-memory state for {ip}: {e}")
        except Exception as e:
            print(f"[WARN] Blocking attempt failed: {e}")
            log_block_action(ip, "block-exception", str(e), 0)



def analyze_line_stream(line: str, threshold: int):
    ip = extract_ip_from_line(line)
    if ip:
        handle_failed_ip(ip, threshold)


# --------------------------
# File-following with rotation handling (start fresh by default)
# --------------------------
def follow_file(path, threshold=THRESHOLD_DEFAULT, sleep_sec=0.5):
    try:
        f = open(path, 'r')
    except Exception as e:
        print(f"[ERROR] cannot open {path}: {e}", file=sys.stderr)
        raise

    # Start fresh by seeking to EOF
    f.seek(0, os.SEEK_END)
    current_inode = os.fstat(f.fileno()).st_ino

    try:
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(sleep_sec)
                # check rotation
                try:
                    stat = os.stat(path)
                    if stat.st_ino != current_inode:
                        f.close()
                        f = open(path, 'r')
                        current_inode = os.fstat(f.fileno()).st_ino
                        f.seek(0, os.SEEK_END)
                except FileNotFoundError:
                    time.sleep(1)
                continue
            analyze_line_stream(line, threshold)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    finally:
        try:
            f.close()
        except Exception:
            pass


def read_from_stdin(threshold=THRESHOLD_DEFAULT):
    try:
        for raw in sys.stdin:
            analyze_line_stream(raw, threshold)
    except KeyboardInterrupt:
        pass


# --------------------------
# Main / arg parsing (default: start fresh)
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced Linux Log Analyzer")
    parser.add_argument('--log', default=config.get("LOG_FILE", "/var/log/auth.log"), help='Path to auth log')
    parser.add_argument('--stdin', action='store_true', help='Read lines from stdin (use with tail -n 0 -F)')
    parser.add_argument('--read-all', action='store_true', help='Read entire file from start (legacy behavior)')
    parser.add_argument('--threshold', type=int, default=THRESHOLD_DEFAULT,
                        help=f'Number of failed attempts before alert (default {THRESHOLD_DEFAULT})')
    args = parser.parse_args()

    threshold = args.threshold

    # If blocking is enabled, ensure ipset + iptables rule exist (best-effort)
    block_enabled = config.get("BLOCK_ENABLED", "false").lower() in ("1", "true", "yes")
    if block_enabled:
        set_name = config.get("BLOCK_SET_NAME", "blocked_ips")
        ensure_ipset_and_rule(set_name=set_name)

    if args.stdin:
        print("[INFO] Reading lines from stdin (fresh start expected from tail -n 0 -F).")
        read_from_stdin(threshold)
        return

    if not args.read_all:
        print(f"[INFO] Starting fresh and following new lines in: {args.log}")
        follow_file(args.log, threshold=threshold)
        return

    print("[INFO] Reading entire file (legacy mode).")
    analyze()


if __name__ == "__main__":
    main()
