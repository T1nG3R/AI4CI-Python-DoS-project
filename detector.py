from scapy.all import sniff, IP, TCP, ICMP, conf
import csv
import time
from collections import defaultdict

# Constants
LOG_FILE = "detected_attacks.csv"
TIME_WINDOW = 10  # Time window in seconds to analyze traffic
PACKET_THRESHOLD = 50  # Number of packets in the time window to consider it an attack

# Data structure to track packets by IP and attack type
traffic_data = defaultdict(lambda: {'count': 0, 'bytes': 0, 'last_time': time.time()})


# Function to log detected attacks
def log_attack(attack_info):
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(attack_info)


# Function to detect different types of attacks and log them if thresholds are exceeded
def detect_packet(packet):
    global traffic_data
    current_time = time.time()

    attack_type = None

    if packet.haslayer("IP"):
        # Extract packet information
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)
        # Check for SYN flood (TCP packets with SYN flag set)
        if packet.haslayer("TCP") and packet[TCP].flags.flagrepr() == "S":
            attack_type = "syn_flood"

        # Check for SYN-ACK flood (TCP packets with SYN-ACK flag set)
        elif packet.haslayer("TCP") and packet[TCP].flags.flagrepr() == "SA":
            attack_type = "syn_ack"

        # Check for Ping of Death (large ICMP packets)
        elif packet.haslayer("ICMP") and packet.haslayer("Raw"):
            attack_type = "pod"

        # Check for Smurf attack
        elif packet.haslayer("ICMP") and packet[ICMP].type == 8:
            attack_type = "smurf"

        # Update traffic data if an attack type is identified
        if attack_type:
            traffic_data[(source_ip, attack_type)]['count'] += 1
            traffic_data[(source_ip, attack_type)]['bytes'] += packet_size
            traffic_data[(source_ip, attack_type)]['last_time'] = current_time

            # Check if the traffic data exceeds thresholds within the time window
            if (current_time - traffic_data[(source_ip, attack_type)]['last_time']) < TIME_WINDOW:
                if traffic_data[(source_ip, attack_type)]['count'] >= PACKET_THRESHOLD:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    log_attack([timestamp, source_ip, attack_type, traffic_data[(source_ip, attack_type)]['bytes'],
                                traffic_data[(source_ip, attack_type)]['count']])
                    print(f"Detected {attack_type} from {source_ip} to {destination_ip} at {timestamp}")

                    # Reset counters for the IP and attack type after logging
                    traffic_data[(source_ip, attack_type)]['count'] = 0
                    traffic_data[(source_ip, attack_type)]['bytes'] = 0


# Main function to start sniffing network traffic
def start_detection(interface):
    # Create CSV header if the file is empty
    try:
        with open(LOG_FILE, mode='x', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Source IP", "Attack Type", "Bytes Transferred", "Packet Count"])
    except FileExistsError:
        pass

    print(f"Starting attack detection on interface {interface}...")
    sniff(iface=interface, prn=detect_packet, store=0)


if __name__ == "__main__":

    network_interface = conf.iface
    start_detection(network_interface)
