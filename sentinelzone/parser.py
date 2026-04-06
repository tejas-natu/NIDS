import time
import re
import os
import requests
from datetime import datetime

SNORT_LOG = '/var/log/snort/alert'
FLASK_URL  = 'http://127.0.0.1:5000/alert'

# ─── Campus Zone Definitions ─────────────────────────────────────
ZONES = {
    'Admin':   '10.10.1.',
    'Staff':   '10.10.2.',
    'Student': '10.10.3.',
    'IoT':     '10.10.4.',
    'Server':  '10.10.5.',
}

# ─── Zone-based severity escalation ──────────────────────────────
ZONE_SEVERITY = {
    'Admin':   {'HIGH': 'CRITICAL', 'MEDIUM': 'HIGH',   'LOW': 'MEDIUM'},
    'Staff':   {'HIGH': 'HIGH',     'MEDIUM': 'MEDIUM', 'LOW': 'LOW'},
    'Student': {'HIGH': 'HIGH',     'MEDIUM': 'LOW',    'LOW': 'LOW'},
    'IoT':     {'HIGH': 'CRITICAL', 'MEDIUM': 'HIGH',   'LOW': 'MEDIUM'},
    'Server':  {'HIGH': 'CRITICAL', 'MEDIUM': 'HIGH',   'LOW': 'MEDIUM'},
    'External':{'HIGH': 'CRITICAL', 'MEDIUM': 'HIGH',   'LOW': 'MEDIUM'},
}

# ─── Snort fast alert format ──────────────────────────────────────
# Example line:
# 03/28-10:45:22.123456  [**] [1:1000001:1] PORT SCAN detected [**]
# [Priority: 2] {TCP} 192.168.1.5:12345 -> 192.168.1.1:80

PATTERN = re.compile(
    r'(\d+/\d+-[\d:.]+)\s+'        # timestamp
    r'\[\*\*\]\s+\[[\d:]+\]\s+'    # [**] [sid:gid:rev]
    r'(.+?)\s+\[\*\*\]'            # alert message
    r'.+?\{(\w+)\}\s+'             # {protocol}
    r'([\d.]+)(?::\d+)?\s*->\s*'  # src_ip
    r'([\d.]+)(?::\d+)?'           # dst_ip
)

# ─── Classify zone from IP ────────────────────────────────────────
def classify_zone(ip):
    for zone, prefix in ZONES.items():
        if ip.startswith(prefix):
            return zone
    return 'External'

# ─── Classify base severity from alert message ────────────────────
def classify_base_severity(message):
    msg = message.upper()
    if any(x in msg for x in ['EXPLOIT', 'SHELLCODE', 'BACKDOOR',
                               'NULL SCAN', 'XMAS', 'FLOOD']):
        return 'CRITICAL'
    if any(x in msg for x in ['SCAN', 'PROBE', 'BRUTE']):
        return 'HIGH'
    if any(x in msg for x in ['POLICY', 'ICMP', 'ATTEMPT']):
        return 'MEDIUM'
    return 'LOW'

# ─── Apply zone escalation ────────────────────────────────────────
def apply_zone_escalation(base_severity, zone):
    escalation = ZONE_SEVERITY.get(zone, {})
    return escalation.get(base_severity, base_severity)

# ─── Clean alert type from raw Snort message ─────────────────────
def extract_alert_type(message):
    msg = message.upper()
    if 'PORT SCAN' in msg or 'SCAN' in msg:   return 'PORT_SCAN'
    if 'FLOOD' in msg:                         return 'SYN_FLOOD'
    if 'NULL' in msg:                          return 'NULL_SCAN'
    if 'XMAS' in msg:                          return 'XMAS_SCAN'
    if 'ICMP' in msg:                          return 'ICMP_FLOOD'
    if 'BRUTE' in msg:                         return 'BRUTE_FORCE'
    if 'SHELLCODE' in msg:                     return 'SHELLCODE'
    if 'BACKDOOR' in msg:                      return 'BACKDOOR'
    return 'ANOMALY'

# ─── Send alert to Flask ──────────────────────────────────────────
def send_to_flask(alert):
    try:
        r = requests.post(FLASK_URL, json=alert, timeout=2)
        if r.status_code == 200:
            print(f"  → Sent to Flask successfully")
        else:
            print(f"  → Flask returned {r.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  → Flask not running yet — alert printed only")

# ─── Main parser loop ─────────────────────────────────────────────
def watch_snort_log():
    print("=" * 55)
    print("  NIDS — Snort Log Parser")
    print("=" * 55)
    print(f"  Watching: {SNORT_LOG}")
    print(f"  Flask:    {FLASK_URL}")
    print("=" * 55)

    # Wait until Snort creates the alert file
    while not os.path.exists(SNORT_LOG):
        print("[PARSER] Waiting for Snort alert file to appear...")
        time.sleep(3)

    print("[PARSER] Alert file found. Listening for new alerts...\n")

    with open(SNORT_LOG, 'r') as f:

        # Jump to end — only process NEW alerts from this point
        f.seek(0, 2)

        while True:
            line = f.readline()

            # No new line — wait and try again
            if not line:
                time.sleep(1)
                continue

            line = line.strip()

            # Skip empty lines and non-alert lines
            if not line or '[**]' not in line:
                continue

            # Try to match the Snort fast alert pattern
            match = PATTERN.search(line)
            if not match:
                continue

            # Extract fields from regex match
            timestamp, message, protocol, src_ip, dst_ip = match.groups()

            # Classify zone and severity
            zone         = classify_zone(src_ip)
            base_sev     = classify_base_severity(message)
            severity     = apply_zone_escalation(base_sev, zone)
            alert_type   = extract_alert_type(message)

            # Build alert dictionary
            alert = {
                'timestamp':  timestamp,
                'alert_type': alert_type,
                'message':    message.strip(),
                'src_ip':     src_ip,
                'dst_ip':     dst_ip,
                'protocol':   protocol,
                'zone':       zone,
                'severity':   severity,
                'source':     'Snort'
            }

            # Print to terminal
            print(f"[SNORT ALERT]")
            print(f"  Time:     {timestamp}")
            print(f"  Type:     {alert_type}")
            print(f"  Source:   {src_ip} → {dst_ip}")
            print(f"  Zone:     {zone}")
            print(f"  Severity: {severity}")
            print(f"  Message:  {message.strip()}")

            # Send to Flask
            send_to_flask(alert)
            print()

if __name__ == '__main__':
    watch_snort_log()
