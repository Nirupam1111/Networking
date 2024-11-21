import sys
import ipaddress
from scapy.all import IP, ICMP, sr

input = input("Enter a Network address: ")

netword_address = input
network = None

try:
    network = ipaddress.IPv4Network(netword_address, strict=True)
except ValueError as e:
    print(e)
    sys.exit(1)

hosts = network.hosts()
packets = [IP(dst=str(ip)) / ICMP() for ip in hosts]
ans, unans = sr(packets, timeout=2)

for snd, rcv in ans:
    if rcv.haslayer(IP):
        print(rcv[IP].src)
