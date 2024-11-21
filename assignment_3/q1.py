from scapy.all import sniff, TCP, IP
from scapy.config import conf


class Flow:
    def __init__(self, src, dst, sport, dport, proto):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.data = 0
        self.packet_count = 0
        self.duration = 0
        self.timestamp = -1

    def __str__(self):
        return f"src_ip: {self.src} dst_ip: {self.dst} src_port: {self.sport} dst_port: {self.dport}"

    def receive_data(self, data):
        self.data += data
        self.packet_count += 1

    def set_duration(self, timestamp):
        if self.timestamp != -1:
            self.duration = timestamp - self.timestamp
            return

        self.timestamp = timestamp


def get_data(packet):
    ip_len = packet[IP].len
    ip_head_len = packet[IP].ihl * 4
    tcp_udp_len = 8
    if TCP in packet:
        tcp_udp_len = packet[TCP].dataofs * 4
    return ip_len - ip_head_len - tcp_udp_len


def packet_handle(packet):
    if not TCP in packet:
        return

    tuple = (packet[IP].src, packet[TCP].sport,
             packet[IP].dst, packet[TCP].dport, packet[IP].proto)
    flow = map.get(tuple, None)

    if not flow:
        flow = Flow(packet[IP].src, packet[IP].dst,
                    packet[TCP].sport, packet[TCP].dport, packet[IP].proto)
        map[tuple] = flow

    flow.receive_data(get_data(packet))
    flow.set_duration(packet.time)


map = {}
duration =  10
print(f"capturing for {duration} sec...")
sniff(filter='ip', prn=packet_handle, timeout=duration)

total_bytes = 0
total_pkts = 0
for pkt in map.values():
    print("\n")
    print(f"Total data bytes {pkt.data} for Flow {pkt}")
    print(f"Total packet {pkt.packet_count}")


top_10_flow_interms_of_bytes = sorted(map.values(), key=lambda pkt: pkt.data, reverse=True)[:10]
top_10_flow_interms_of_packets = sorted(map.values(), key=lambda pkt: pkt.packet_count, reverse=True)[:10]

print(f"\n\nTop 10 flow by bytes")
for i in top_10_flow_interms_of_bytes:
    print(f"Flow: {i} data exchanged: {i.data}")

print(f"\n\nTop 10 flow by packet count")
for i in top_10_flow_interms_of_packets:
    print(f"Flow: {i} packet count: {i.packet_count}")

print("\n\nFlow duration")
for i in map.values():
    print(f"Flow: {i} duration: {i.duration:.5f}")

machine_ip = conf.route.route("0.0.0.0")[1]
ip_dic = {}

for pkt in map.values():
    if pkt.src != machine_ip:
        ip_dic[pkt.src] = ip_dic.get(pkt.src, 0) + pkt.packet_count
    elif pkt.dst != machine_ip:
        ip_dic[pkt.dst] = ip_dic.get(pkt.dst, 0) + pkt.packet_count

top_ip = max(ip_dic, key=ip_dic.get)
print(f"\n\nActive ip: {top_ip} exchanged packet: {ip_dic[top_ip]}")
print(f"Top Flow: {top_10_flow_interms_of_bytes[0]} exchanged data: {top_10_flow_interms_of_bytes[0].data}")

ip_data = {}
ip_packet = {}

for i in map.values():
    ip_data[i.src] = ip_data.get(i.src, 0) + i.data
    ip_packet[i.src] = ip_packet.get(i.src, 0) + i.packet_count

ip_packet = sorted(ip_packet.items(), key=lambda item: item[1], reverse=True)
print(f"\n\nIp rank by packets sent:")
for ip, packet in ip_packet:
    print(f"{ip}: {packet} sent")

ip_data = sorted(ip_data.items(), key=lambda item: item[1], reverse=True)
print(f"\n\nIp rank by data sent:")
for ip, data in ip_data:
    print(f"{ip}: {data} sent")


flow_interms_of_bytes = sorted(map.values(), key=lambda pkt: pkt.data, reverse=True)
flow_interms_of_packets = sorted(map.values(), key=lambda pkt: pkt.packet_count, reverse=True)

print(f"\n\nFlow by bytes")
for i in flow_interms_of_bytes:
    print(f"Flow: {i} data exchanged: {i.data}")
print(f"\n\nFlow by packet count")
for i in flow_interms_of_packets:
    print(f"Flow: {i} packet count: {i.packet_count}")
