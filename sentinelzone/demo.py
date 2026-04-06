from scapy.all import *
import time
import random
import sys
import requests

# ═══════════════════════════════════════════════════════════════════
# ZONES
# ═══════════════════════════════════════════════════════════════════

ZONES = {
    'Admin':   ['10.10.1.10', '10.10.1.20'],
    'Staff':   ['10.10.2.15', '10.10.2.25'],
    'Student': ['10.10.3.50', '10.10.3.51', '10.10.3.52'],
    'IoT':     ['10.10.4.10', '10.10.4.20'],
    'Server':  ['10.10.5.10', '10.10.5.20'],
}

TARGET = '10.10.5.10'

ATTACK_TYPES = [
    'PORT_SCAN',
    'SYN_FLOOD',
    'ICMP_FLOOD',
    'UDP_FLOOD',
    'ARP_SPOOF',
    'BRUTE_FORCE'
]

# ═══════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════

def zone_log(zone, attack, src, dst):
    sev_map = {
        'Admin': 'CRITICAL',
        'Staff': 'HIGH',
        'Student': 'MEDIUM',
        'IoT': 'HIGH',
        'Server': 'CRITICAL',
    }

    print(f"[{zone}] [{sev_map[zone]}] {attack} | SRC={src} -> DST={dst}")
    
    # POST to Flask backend for real-time dashboard
    alert_data = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'alert_type': attack,
        'src_ip': src,
        'dst_ip': dst,
        'zone': zone,
        'severity': sev_map[zone],
        'source': 'demo_simulator',
        'message': f'Simulated {attack} from {src} targeting {dst}'
    }
    try:
        requests.post('http://127.0.0.1:5000/alert', 
                     json=alert_data, 
                     headers={'Content-Type': 'application/json'},
                     timeout=2)
    except Exception as e:
        pass  # Don't block simulation if server down

# ═══════════════════════════════════════════════════════════════════
# ATTACK FUNCTIONS (FIXED)
# ═══════════════════════════════════════════════════════════════════

def port_scan(zone, src):
    ports = random.sample(range(20, 1024), 20)

    for port in ports:
        pkt = IP(src=src, dst=TARGET) / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags='S'
        )
        send(pkt, verbose=0)

    zone_log(zone, "PORT_SCAN", src, TARGET)


def syn_flood(zone, src):
    for _ in range(150):
        pkt = IP(src=src, dst=TARGET) / TCP(
            sport=random.randint(1024, 65535),
            dport=80,
            flags='S'
        )
        send(pkt, verbose=0)

    zone_log(zone, "SYN_FLOOD", src, TARGET)


def icmp_flood(zone, src):
    for _ in range(120):
        pkt = IP(src=src, dst=TARGET) / ICMP()
        send(pkt, verbose=0)

    zone_log(zone, "ICMP_FLOOD", src, TARGET)


def udp_flood(zone, src):
    for _ in range(120):
        pkt = IP(src=src, dst=TARGET) / UDP(
            sport=random.randint(1024, 65535),
            dport=random.choice([53, 123, 161])
        ) / Raw(load="X"*256)
        send(pkt, verbose=0)

    zone_log(zone, "UDP_FLOOD", src, TARGET)


def arp_spoof(zone, src):
    pkt = ARP(
        op=2,
        psrc=TARGET,
        pdst="10.10.5.1",
        hwsrc="aa:bb:cc:dd:ee:ff"
    )
    send(pkt, count=5, verbose=0)

    zone_log(zone, "ARP_SPOOF", src, TARGET)


def brute_force(zone, src):
    for _ in range(25):
        pkt = IP(src=src, dst=TARGET) / TCP(
            sport=random.randint(1024, 65535),
            dport=22,
            flags='S'
        )
        send(pkt, verbose=0)
        time.sleep(0.03)

    zone_log(zone, "BRUTE_FORCE", src, TARGET)

# ═══════════════════════════════════════════════════════════════════
# ATTACK ROUTER
# ═══════════════════════════════════════════════════════════════════

def run_attack(zone, src, attack):
    if attack == 'PORT_SCAN':
        port_scan(zone, src)
    elif attack == 'SYN_FLOOD':
        syn_flood(zone, src)
    elif attack == 'ICMP_FLOOD':
        icmp_flood(zone, src)
    elif attack == 'UDP_FLOOD':
        udp_flood(zone, src)
    elif attack == 'ARP_SPOOF':
        arp_spoof(zone, src)
    elif attack == 'BRUTE_FORCE':
        brute_force(zone, src)

# ═══════════════════════════════════════════════════════════════════
# MAIN ENGINE (IMPORTANT FIX)
# ═══════════════════════════════════════════════════════════════════

def simulate_all_zones():
    print("\n🚀 Starting Full Network Attack Simulation...\n")

    for _ in range(20):  # number of cycles → controls chart distribution
        zone = random.choice(list(ZONES.keys()))
        src = random.choice(ZONES[zone])
        attack = random.choice(ATTACK_TYPES)

        run_attack(zone, src, attack)

        time.sleep(random.uniform(0.5, 1.5))  # smoother dashboard updates

    print("\n✅ Simulation Completed\n")

# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    simulate_all_zones()