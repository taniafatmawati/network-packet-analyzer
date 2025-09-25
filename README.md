# 📡 Network Packet Analyzer (Mini Wireshark Clone)

## 📌 Project Overview
This project implements a simple **network packet analyzer** using Python and the **Scapy** library.  
The goal is to provide an educational demonstration of **packet sniffing, protocol analysis, and anomaly detection**.

It is inspired by Wireshark, but intentionally lightweight to serve as a **learning tool** for students and researchers in **network security**.

⚠️ **Disclaimer**: This tool is for **educational purposes only**.  
Do not use it for unauthorized packet sniffing or in production environments.

---

## ✨ Key Features
- Capture live network packets on the default interface
- Protocol detection:
  - TCP (with port analysis)
  - UDP
  - ICMP (ping requests, etc.)
- Save packets to `.pcap` format (openable in Wireshark)
- Protocol statistics (counts of TCP, UDP, ICMP packets)
- Anomaly detection:
  - Suspicious TCP port usage (e.g., port `4444`)
  - **DoS-like traffic detection** (20+ connections in 5s)
  - **Port scan detection** (10+ ports in 10s)
- CLI-based interface

---

## 🛠 Skills Demonstrated
- Applied **network security concepts**
- **Packet sniffing** and traffic monitoring
- **Protocol analysis** (TCP, UDP, ICMP)
- Basic anomaly detection
- Python programming with **Scapy**

---

## 📦 Requirements
- Python 3.x
- `scapy` library

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🏗️ Architecture Diagram

The workflow of this analyzer can be represented as follows:

```mermaid
flowchart LR
    A[🔍 Packet Capture<br>(Scapy sniff)] --> B[📑 Protocol Analysis<br>(TCP/UDP/ICMP)]
    B --> C[⚠️ Anomaly Detection<br>(Suspicious Ports, DoS, Port Scans)]
    B --> D[💾 Save Packets<br>.pcap format]
    C --> E[📊 Report<br>Protocol Statistics + Alerts]
    D --> E
```

---

## 🚀 Usage

Run the analyzer:

```bash
sudo python analyzer.py
```

Example output:

```
Starting Network Packet Analyzer (press Ctrl+C to stop)...

[TCP] 192.168.1.10 → 142.250.182.14 | SrcPort: 51512, DstPort: 443
[UDP] 192.168.1.10 → 8.8.8.8 | SrcPort: 5353, DstPort: 53
[ICMP] 192.168.1.10 → 192.168.1.1 | Type: 8
   ⚠️ Anomaly detected: Connection attempt to suspicious port 4444
   ⚠️ Possible Port Scan detected from 192.168.1.10 (scanned 12 ports in 10s)
```

When stopped with Ctrl+C, results are saved:

```
Capture stopped. Saving results...
[+] Packets saved to capture.pcap

Protocol Statistics:
  - TCP: 152 packets
  - UDP: 47 packets
  - ICMP: 8 packets
```

📸 **Example Demo Screenshot**

**1. Live capture in terminal**  
![Terminal Output](screenshots/output-terminal.png)

**2. Summary of packet statistics**  
![File Output](screenshots/output-file.png)

---

## 🔮 Future Improvements
- Add real-time visualization (graphs/charts for traffic)
- Build GUI dashboard with Tkinter or Flask
- Extend anomaly detection with ML models

---
