from scapy.all import sniff

def handle_packet(packet):
    # Display a brief summary of the packet
    print(packet.summary())


def main():
    print("Starting PacketSniffo: capturing packets...\n")
    # Capture packets indefinitely (Ctrl+C to stop)
    sniff(prn=handle_packet, store=False)
    
if __name__ == "__main__":
    main()
