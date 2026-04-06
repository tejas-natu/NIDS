from scapy.all import send, IP, TCP

# Simulate Admin zone port scan
send(IP(src="10.10.1.50", dst="10.10.5.10")/TCP(dport=80, flags="S"), count=5)

# Simulate Student zone SYN flood
send(IP(src="10.10.3.25", dst="10.10.5.10")/TCP(flags="S"), count=250)

# Simulate IoT NULL scan
send(IP(src="10.10.4.15", dst="10.10.1.1")/TCP(flags=0), count=3)