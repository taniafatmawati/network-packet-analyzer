#!/usr/bin/env python3
"""
Network Packet Analyzer (Mini Wireshark Clone)
- Cross-platform (Linux & Windows)
- Captures TCP, UDP, ICMP packets
- Detects anomalies: DoS & Port Scans
- Saves capture to capture.pcap
"""

import sys
import platform
import time
import signal
import socket
from collections import Counter, defaultdict
import psutil

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, conf

# Global state
captured_packets = []
protocol_counter = Counter()
connection_tracker = defaultdict(list)
start_time = time.time()


def packet_callback(packet):
    """Callback function for each sniffed packet"""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        captured_packets.append(packet)

        if proto == 6 and TCP in packet:  # TCP
            protocol_counter["TCP"] += 1
            print(f"[TCP] {ip_src} → {ip_dst} | SrcPort: {packet[TCP].sport}, DstPort: {packet[TCP].dport}")

            connection_tracker[ip_src].append((time.time(), packet[TCP].dport))
            if packet[TCP].dport == 4444:
                print("   ⚠️ Anomaly detected: Connection attempt to suspicious port 4444")

        elif proto == 17 and UDP in packet:  # UDP
            protocol_counter["UDP"] += 1
            print(f"[UDP] {ip_src} → {ip_dst} | SrcPort: {packet[UDP].sport}, DstPort: {packet[UDP].dport}")

        elif proto == 1 and ICMP in packet:  # ICMP
            protocol_counter["ICMP"] += 1
            print(f"[ICMP] {ip_src} → {ip_dst} | Type: {packet[ICMP].type}")

        else:  # Other protocol
            protocol_counter["OTHER"] += 1
            print(f"[OTHER] {ip_src} → {ip_dst} | Protocol: {proto}")

        detect_anomalies(ip_src)


def detect_anomalies(ip_src):
    """Detect possible DoS or port scanning behavior"""
    timestamps_ports = connection_tracker[ip_src]

    # DoS detection: 20+ connections in 5 seconds
    recent_connections = [t for t, _ in timestamps_ports if time.time() - t <= 5]
    if len(recent_connections) > 20:
        print(f"   ⚠️ Possible DoS attack detected from {ip_src} ({len(recent_connections)} connections in 5s)")

    # Port scan detection: >10 ports in 10 seconds
    recent_ports = [p for t, p in timestamps_ports if time.time() - t <= 10]
    if len(set(recent_ports)) > 10:
        print(f"   ⚠️ Possible Port Scan detected from {ip_src} (scanned {len(set(recent_ports))} ports in 10s)")


def choose_interface():
    """List available interfaces with friendly names and IPs (like ipconfig), let user choose"""
    nics = psutil.net_if_addrs()
    if not nics:
        print("[!] No network interfaces detected.")
        return None

    interfaces = []
    print("Available interfaces:")
    for i, (iface, addrs) in enumerate(nics.items()):
        ipv4s = [a.address for a in addrs if a.family == socket.AF_INET]
        display_name = f"{iface} - IPv4: {', '.join(ipv4s) if ipv4s else 'N/A'}"
        interfaces.append(iface)
        print(f"  {i}: {display_name}")

    try:
        sel = int(input("Choose interface index to capture on (default 0): ") or 0)
        return interfaces[sel]
    except Exception:
        print("Invalid selection, using default interface.")
        return interfaces[0]


def print_summary():
    """Print capture summary and save results"""
    duration = time.time() - start_time
    print("\n📊 Capture stopped. Saving results...")

    if captured_packets:
        wrpcap("capture.pcap", captured_packets)
        print("[+] Packets saved to capture.pcap")

    if protocol_counter:
        total = sum(protocol_counter.values())
        print("\n📈 Protocol Statistics:")
        for proto, count in protocol_counter.items():
            print(f" - {proto}: {count} ({count/total:.1%})")
        print(f"\nTotal packets captured: {total}")
        print(f"Capture duration: {duration:.1f} seconds")


def stop_sniff(sig, frame):
    """Handle Ctrl+C cleanly"""
    print_summary()
    sys.exit(0)


def main():
    print("🔎 Starting Network Packet Analyzer (press Ctrl+C to stop)...\n")
    signal.signal(signal.SIGINT, stop_sniff)

    # On Windows, prefer Npcap (pcap mode)
    if platform.system().lower().startswith("win"):
        conf.use_pcap = True

    iface = None
    try:
        iface = choose_interface()
        print(f"[+] Starting capture on interface: {iface}")
        sniff(prn=packet_callback, store=0, iface=iface)
    except RuntimeError as re:
        print(f"[!] RuntimeError during sniff(): {re}")
        print("[!] Npcap might be missing. Install it from https://npcap.com/ and run as Administrator.")
        print("[*] Attempting L3 (IP-layer) sniffing fallback...")
        try:
            sniff(prn=packet_callback, store=0, filter="ip")
        except Exception as e:
            print(f"[!] L3 fallback failed: {e}")
            sys.exit(1)
    except PermissionError as pe:
        print(f"[!] PermissionError: {pe}")
        print("Try running this script as root (Linux) or Administrator (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()


if __name__ == "__main__":
    main()
