from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from collections import Counter, defaultdict
import time

# Store captured packets
captured_packets = []
protocol_counter = Counter()
connection_tracker = defaultdict(list)  # For DoS / port scan detection

def packet_callback(packet):
    # Callback function executed for each captured packet.
    global captured_packets, protocol_counter, connection_tracker

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Track packet
        captured_packets.append(packet)

        if proto == 6 and TCP in packet:   # TCP
            protocol_counter["TCP"] += 1
            print(f"[TCP] {ip_src} → {ip_dst} | SrcPort: {packet[TCP].sport}, DstPort: {packet[TCP].dport}")

            # Track connections for anomaly detection
            connection_tracker[ip_src].append((time.time(), packet[TCP].dport))

            # Suspicious port usage
            if packet[TCP].dport == 4444:
                print("   ⚠️ Anomaly detected: Connection attempt to suspicious port 4444")

        elif proto == 17 and UDP in packet:  # UDP
            protocol_counter["UDP"] += 1
            print(f"[UDP] {ip_src} → {ip_dst} | SrcPort: {packet[UDP].sport}, DstPort: {packet[UDP].dport}")

        elif proto == 1 and ICMP in packet:  # ICMP
            protocol_counter["ICMP"] += 1
            print(f"[ICMP] {ip_src} → {ip_dst} | Type: {packet[ICMP].type}")

        else:
            protocol_counter["OTHER"] += 1
            print(f"[OTHER] {ip_src} → {ip_dst} | Protocol: {proto}")

        # Extended anomaly detection
        detect_anomalies(ip_src)

def detect_anomalies(ip_src):
    # Detect DoS-like traffic and port scans
    timestamps_ports = connection_tracker[ip_src]

    # Check for DoS-like traffic: > 20 connections in 5 seconds
    recent_connections = [t for t, _ in timestamps_ports if time.time() - t <= 5]
    if len(recent_connections) > 20:
        print(f"   ⚠️ Possible DoS attack detected from {ip_src} ({len(recent_connections)} connections in 5s)")

    # Check for port scan: > 10 different ports in 10 seconds
    recent_ports = [p for t, p in timestamps_ports if time.time() - t <= 10]
    if len(set(recent_ports)) > 10:
        print(f"   ⚠️ Possible Port Scan detected from {ip_src} (scanned {len(set(recent_ports))} ports in 10s)")

def main():
    # Main function to start sniffing
    print("Starting Network Packet Analyzer (press Ctrl+C to stop)...\n")

    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n\nCapture stopped. Saving results...")

        # Save packets to PCAP file
        wrpcap("capture.pcap", captured_packets)
        print("[+] Packets saved to capture.pcap")

        # Print protocol statistics
        print("\n📈 Protocol Statistics:")
        for proto, count in protocol_counter.items():
            print(f"  - {proto}: {count} packets")

if __name__ == "__main__":
    main()
