from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether
from datetime import datetime
import argparse
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser(description="PacketSniffo: Python Packet Sniffer")
    parser.add_argument(
        "--filter",
        type=str,
        choices=["tcp", "udp", "icmp", "all"],
        default="all",
        help="Filter packets by protocol"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite)"
    )
    return parser.parse_args()

packet_counts = defaultdict(int)  # Counts by protocol
total_packets = 0


def handle_packet(pkt, proto_filter="all"):
    global total_packets
    ts = datetime.now().strftime("%H:%M:%S")
    length = len(pkt)

    # Determine protocol
    proto = None
    if IP in pkt:
        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            proto = "Other"
    elif IPv6 in pkt:
        proto = "IPv6"
    else:
        proto = "Other"

    # Skip packets that don’t match filter
    if proto_filter != "all" and proto.lower() != proto_filter:
        return

    # Update counters
    total_packets += 1
    packet_counts[proto] += 1

    # MAC and IP addresses
    src_mac = dst_mac = src_ip = dst_ip = "-"
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

    # TCP/UDP/ICMP details
    details = "-"
    if TCP in pkt:
        t = pkt[TCP]
        details = f"{t.sport}->{t.dport} flags={t.flags}"
    elif UDP in pkt:
        u = pkt[UDP]
        details = f"{u.sport}->{u.dport}"
    elif ICMP in pkt:
        i = pkt[ICMP]
        details = f"type={i.type} code={i.code}"

    # Print packet summary
    print(f"[{ts}] Len={length} {src_mac}->{dst_mac} {src_ip}->{dst_ip} {proto} {details}")

    # Print live stats every 10 packets
    if total_packets % 10 == 0:
        print("\n--- Packet Statistics ---")
        print(f"Total packets: {total_packets}")
        for p, count in packet_counts.items():
            print(f"{p}: {count}")
        print("-------------------------\n")




def main():
    args = parse_args()
    print(f"Starting PacketSniffo with filter={args.filter}, count={args.count or 'infinite'} packets...\n")
    
    sniff(prn=lambda pkt: handle_packet(pkt, proto_filter=args.filter),
          count=args.count if args.count > 0 else 0,
          store=False)


    
if __name__ == "__main__":
    main()
