import sys
import ipaddress
from scapy.all import IP, TCP, sr

input = input("Enter a ip address: ")
ip = input

try:
    ip = ipaddress.IPv4Address(ip)
except ipaddress.AddressValueError as e:
    print(e)
    sys.exit(1)

packets = [IP(dst=str(ip)) / TCP(dport=port, flags="S") for port in range(0, 1024)]
ans, unans = sr(packets, timeout=1)

for snd, rcv in ans:
    if rcv.haslayer(TCP) and rcv[TCP].flags == 'SA':
        print(rcv[TCP].sport)
