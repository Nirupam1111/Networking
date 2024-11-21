import sys
import ipaddress
from scapy.all import IP, UDP, sr1


def traceroute(dest_ip, max_hop):
    """ 
    Traceroutes and return a list of ips 
    11 -> Time exceeded
    3 -> Destination unreachable
    0 -> echo reply
    """
    routes = []
    for hop in range(1, max_hop+1):
        packet = IP(dst=str(dest_ip), ttl=hop) / UDP(dport=33434)
        res = sr1(packet, timeout=1, verbose=0)
        if res == None:
            routes.append('*')
        elif res.type == 11:
            routes.append(res.src)
        else:
            routes.append(res.src)
            break

    return routes


if __name__ == '__main__':
    input = input("Enter a ip address: ")
    ip = input

    try:
        ip = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as e:
        print(e)
        sys.exit(1)

    max_hop = 64
    print(f"Please wait! Sending udp packet to {max_hop} hops!")
    routes = traceroute(ip, max_hop)
    print(f"Routes are: ")
    for line, ip in enumerate(routes):
        print(f"{line+1}> {ip}")
