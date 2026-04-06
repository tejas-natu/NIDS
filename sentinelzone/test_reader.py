import time
import re
from database import insert_alert

LOG_FILE = "/var/log/snort/alert"


# ==========================
# READ SNORT LOG FILE
# ==========================
def read_alerts():
    try:
        with open(LOG_FILE, "r") as f:
            return f.readlines()
    except:
        return []


# ==========================
# PARSE ALERTS (IPv4 + IPv6)
# ==========================
def parse_alerts(lines):
    parsed = []

    for line in lines:
        line = line.strip()

        # Match IP pattern (IPv4 + IPv6)
        match = re.search(r'([\da-fA-F:.]+)\s*->\s*([\da-fA-F:.]+)', line)

        if match:
            src_ip = match.group(1)
            dst_ip = match.group(2)

            msg = line.lower()

            # Attack type detection
            if "icmp" in msg:
                attack_type = "ICMP Flood"
            elif "syn" in msg:
                attack_type = "SYN Flood"
            elif "udp" in msg:
                attack_type = "UDP Flood"
            elif "arp" in msg:
                attack_type = "ARP Spoof"
            elif "scan" in msg:
                attack_type = "Port Scan"
            else:
                attack_type = "DDoS"

            # Zone detection
            if dst_ip.startswith("10.") or dst_ip.startswith("192.168"):
                zone = "Internal"
            else:
                zone = "External"

            parsed.append({
                "type": attack_type,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "zone": zone
            })

    return parsed


# ==========================
# MAIN LOOP (DEBUG OUTPUT)
# ==========================
while True:
    lines = read_alerts()
    alerts = parse_alerts(lines)

    for alert in alerts[-5:]:   # insert latest few
        insert_alert(alert)

    print("Inserted alerts into DB...")

    time.sleep(3)