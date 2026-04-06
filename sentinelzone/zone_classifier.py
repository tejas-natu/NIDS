from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import requests

# ─── Campus Zone Definitions ────────────────────────────────────
ZONES = {
    'Admin':   '10.10.1.',
    'Staff':   '10.10.2.',
    'Student': '10.10.3.',
    'IoT':     '10.10.4.',
    'Server':  '10.10.5.',
}

# ─── Severity per zone (same attack = higher risk in Admin) ─────
ZONE_SEVERITY = {
    'Admin':   {'PORT_SCAN': 'CRITICAL', 'SYN_FLOOD': 'CRITICAL',
                'NULL_SCAN': 'CRITICAL', 'XMAS_SCAN': 'CRITICAL',
                'ICMP_FLOOD': 'HIGH'},
    'Staff':   {'PORT_SCAN': 'HIGH',     'SYN_FLOOD': 'HIGH',
                'NULL_SCAN': 'CRITICAL', 'XMAS_SCAN': 'CRITICAL',
                'ICMP_FLOOD': 'MEDIUM'},
    'Student': {'PORT_SCAN': 'MEDIUM',   'SYN_FLOOD': 'HIGH',
                'NULL_SCAN': 'HIGH',     'XMAS_SCAN': 'HIGH',
                'ICMP_FLOOD': 'LOW'},
    'IoT':     {'PORT_SCAN': 'HIGH',     'SYN_FLOOD': 'CRITICAL',
                'NULL_SCAN': 'HIGH',     'XMAS_SCAN': 'HIGH',
                'ICMP_FLOOD': 'MEDIUM'},
    'Server':  {'PORT_SCAN': 'CRITICAL', 'SYN_FLOOD': 'CRITICAL',
                'NULL_SCAN': 'CRITICAL', 'XMAS_SCAN': 'CRITICAL',
                'ICMP_FLOOD': 'HIGH'},
    'External':{'PORT_SCAN': 'HIGH',     'SYN_FLOOD': 'CRITICAL',
                'NULL_SCAN': 'CRITICAL', 'XMAS_SCAN': 'CRITICAL',
                'ICMP_FLOOD': 'MEDIUM'},
}

FLASK_URL = 'http://127.0.0.1:5000/alert'

# ─── Per-IP counters reset every 10 seconds ─────────────────────
packet_counts = {}
port_hits     = {}
last_reset    = time.time()

# ─── Classify IP into zone ───────────────────────────────────────
def classify_zone(ip):
    for zone, prefix in ZONES.items():
        if ip.startswith(prefix):
            return zone
    return 'External'

# ─── Get severity based on zone + attack type ────────────────────
def get_severity(alert_type, zone):
    return ZONE_SEVERITY.get(zone, {}).get(alert_type, 'LOW')

# ─── Send alert to Flask ─────────────────────────────────────────
def send_alert(alert_type, src_ip, dst_ip, zone, message):
    severity = get_severity(alert_type, zone)
    alert = {
        'alert_type': alert_type,
        'src_ip':     src_ip,
        'dst_ip':     dst_ip,
        'zone':       zone,
        'severity':   severity,
        'source':     'Scapy',
        'message':    message
    }
    print(f"[{zone}] [{severity}] {alert_type} | {src_ip} → {dst_ip} | {message}")
    try:
        requests.post(FLASK_URL, json=alert, timeout=2)
    except:
        pass

# ─── Main packet processor ───────────────────────────────────────
def process_packet(pkt):
    global last_reset, packet_counts, port_hits

    if not pkt.haslayer(IP):
        return

    src  = pkt[IP].src
    dst  = pkt[IP].dst
    zone = classify_zone(src)

    # Reset counters every 10 seconds
    now = time.time()
    if now - last_reset > 10:
        packet_counts = {}
        port_hits     = {}
        last_reset    = now

    packet_counts[src] = packet_counts.get(src, 0) + 1

    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        dport = pkt[TCP].dport

        # NULL scan — TCP with no flags
        if flags == 0:
            send_alert('NULL_SCAN', src, dst, zone,
                       'TCP packet with no flags')
            return

        # XMAS scan — FIN + PSH + URG
        if flags == 0x29:
            send_alert('XMAS_SCAN', src, dst, zone,
                       'FIN+PSH+URG flags set')
            return

        # SYN flood — high volume SYN packets
        if flags == 0x02:
            if packet_counts[src] > 200:
                send_alert('SYN_FLOOD', src, dst, zone,
                           f'{packet_counts[src]} SYN pkts in 10s')
                return

        # Port scan — many unique ports from one IP
        if src not in port_hits:
            port_hits[src] = set()
        port_hits[src].add(dport)
        if len(port_hits[src]) > 15:
            send_alert('PORT_SCAN', src, dst, zone,
                       f'{len(port_hits[src])} ports in 10s')
            port_hits[src] = set()

    # ICMP flood
    if pkt.haslayer(ICMP):
        if packet_counts[src] > 100:
            send_alert('ICMP_FLOOD', src, dst, zone,
                       f'{packet_counts[src]} ICMP pkts in 10s')

# ─── Start sniffing ──────────────────────────────────────────────
print("SentinelZone — Zone Classifier")
print("Zones: Admin(10.10.1.x) | Staff(10.10.2.x) | "
      "Student(10.10.3.x) | IoT(10.10.4.x) | Server(10.10.5.x)")
print("Waiting for packets...\n")

sniff(prn=process_packet, store=0)