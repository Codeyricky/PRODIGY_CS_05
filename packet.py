from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "OTHER"

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"

        print(f"[{proto}] {ip_src} → {ip_dst}")

        # Uncomment to print raw payload (for deeper analysis)
        # if packet.haslayer(Raw):
        #     print(f"Payload: {packet[Raw].load}\n")

# Start sniffing (may need sudo/admin privileges)
print("Sniffing started... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
