from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether
from datetime import datetime


def handle_packet(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    length = len(pkt)

    # Default values
    src_mac = dst_mac = src_ip = dst_ip = proto = details = "-"

    # Layer 2 info
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    # Layer 3 info
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            proto = "TCP"
            t = pkt[TCP]
            details = f"{t.sport}->{t.dport} flags={t.flags}"
        elif UDP in pkt:
            proto = "UDP"
            u = pkt[UDP]
            details = f"{u.sport}->{u.dport}"
        elif ICMP in pkt:
            proto = "ICMP"
            i = pkt[ICMP]
            details = f"type={i.type} code={i.code}"
        else:
            proto = f"IP(proto={pkt[IP].proto})"
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        proto = "IPv6"

    print(f"[{ts}] Len={length} {src_mac}->{dst_mac} {src_ip}->{dst_ip} {proto} {details}")



def main():
    print("Starting PacketSniffo: capturing packets...\n")
    # Capture 10 packets and stops
    sniff(prn=handle_packet, count=10, store=False)

    
if __name__ == "__main__":
    main()
