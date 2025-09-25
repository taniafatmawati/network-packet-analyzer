from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Callback function executed for each captured packet.
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocol detection
        if proto == 6 and TCP in packet:   # TCP protocol
            print(f"[TCP] {ip_src} → {ip_dst} | SrcPort: {packet[TCP].sport}, DstPort: {packet[TCP].dport}")

            # Simple anomaly check: suspicious port (e.g., 4444 often used by malware)
            if packet[TCP].dport == 4444:
                print("Anomaly detected: Connection attempt to suspicious port 4444")

        elif proto == 17 and UDP in packet:  # UDP protocol
            print(f"[UDP] {ip_src} → {ip_dst} | SrcPort: {packet[UDP].sport}, DstPort: {packet[UDP].dport}")

        elif proto == 1 and ICMP in packet:  # ICMP protocol
            print(f"[ICMP] {ip_src} → {ip_dst} | Type: {packet[ICMP].type}")

        else:
            print(f"[OTHER] {ip_src} → {ip_dst} | Protocol: {proto}")

def main():
    print("Starting Network Packet Analyzer (press Ctrl+C to stop)...\n")
    
    # Sniff packets on default interface (e.g., eth0, wlan0)
    # To capture with protocol filter, use: filter="tcp" or "udp"
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
