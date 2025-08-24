import argparse
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether
from datetime import datetime

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


def handle_packet(pkt, proto_filter="all"):
    # Determine packet protocol
    proto = None
    if IP in pkt:
        if TCP in pkt:
            proto = "tcp"
        elif UDP in pkt:
            proto = "udp"
        elif ICMP in pkt:
            proto = "icmp"
        else:
            proto = "other"
    elif IPv6 in pkt:
        proto = "ipv6"

    # Skip packets that don't match the filter
    if proto_filter != "all" and proto != proto_filter:
        return

    # Timestamp and length
    ts = datetime.now().strftime("%H:%M:%S")
    length = len(pkt)

    # MAC addresses
    src_mac = dst_mac = "-"
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    # IP addresses
    src_ip = dst_ip = "-"
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

    # Details for TCP/UDP/ICMP
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

    # Print summary
    print(f"[{ts}] Len={length} {src_mac}->{dst_mac} {src_ip}->{dst_ip} {proto.upper()} {details}")




def main():
    args = parse_args()
    print(f"Starting PacketSniffo with filter={args.filter}, count={args.count or 'infinite'} packets...\n")
    
    sniff(prn=lambda pkt: handle_packet(pkt, proto_filter=args.filter),
          count=args.count if args.count > 0 else 0,
          store=False)


    
if __name__ == "__main__":
    main()
