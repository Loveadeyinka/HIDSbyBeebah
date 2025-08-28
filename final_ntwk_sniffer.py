protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}
from scapy.all import sniff, IP
from collections import defaultdict
import time
import csv
import os

ip_tracker = defaultdict(list)
csv_file = "packets_log.csv"
protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Create the CSV with headers
if not os.path.isfile(csv_file):
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Suspicious"])

def detect_suspicious_activity(src_ip):
    current_time = time.time()
    ip_tracker[src_ip].append(current_time)
    ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if current_time - t < 10]

    if len(ip_tracker[src_ip]) > 20:
        return True
    return False

def packet_callback(packet):
    if IP in packet:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_id = packet[IP].proto
        protocol = protocol_map.get(proto_id, f"Unknown ({proto_id})")
        suspicious = detect_suspicious_activity(src_ip)

        with open(csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, protocol, "Yes" if suspicious else "No"])

        if suspicious:
            print(f"\n[ALERT] {src_ip} is flooding the network! Packets in 10s: {len(ip_tracker[src_ip])}")
        else:
            print(f"{src_ip} --> {dst_ip} | Protocol: {protocol}")

# Start sniffing
sniff(prn=packet_callback, store=False)
