# 📡 Network Packet Analyzer (Mini Wireshark Clone)

## 📌 Project Overview
This project implements a lightweight **network packet analyzer** using Python and the **Scapy** library.  
It demonstrates **packet sniffing, protocol analysis, and anomaly detection** in a simplified manner, inspired by Wireshark.

⚠️ **Disclaimer**: This tool is intended for **educational purposes only**.  
Do not use it for unauthorized packet sniffing or in production environments.

---

## ✨ Key Features
- Capture live network packets from a selected network interface
- Protocol classification:
  - TCP (with port analysis)
  - UDP
  - ICMP
- Save traffic to `.pcap` format (openable in Wireshark)
- Protocol statistics summary (counts of TCP, UDP, ICMP packets)
- Anomaly detection:
  - Suspicious TCP port usage (e.g., port `4444`)
  - **DoS-like traffic detection** (20+ connections in 5s)
  - **Port scan detection** (10+ ports in 10s)

---

## 🛠 Skills Demonstrated
- Applied **network security concepts**
- **Packet sniffing** and traffic monitoring
- **Protocol analysis** (TCP, UDP, ICMP)
- Basic anomaly detection
- Python programming with **Scapy**
- Cross-platform coding (Linux + Windows)

---

## 📦 Requirements
- Python 3.x
- `scapy` library
- `psutil` (for friendly interface names)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🏗️ Architecture Diagram

```mermaid
flowchart LR
    A[Packet Capture - Scapy] --> B[Protocol Analysis - TCP/UDP/ICMP]
    B --> C[Anomaly Detection - Suspicious Ports, DoS, Port Scans]
    B --> D[Save Packets - pcap format]
    C --> E[Report - Statistics & Alerts]
    D --> E
```

---

## 🚀 Usage

### Linux / macOS

Run the analyzer with root privileges:

```bash
sudo python analyzer.py
```

Stop with **Ctrl+C** → packets will be saved to `capture.pcap`.

### Windows Setup & Usage

1) Install Npcap
- Download: [Npcap](https://npcap.com/)  
- Enable **“WinPcap API-compatible mode”** during installation
- Restart after installation

2) Open Terminal as Administrator
- Run **PowerShell** or **CMD** → **Run as Administrator**

3) Setup Virtual Environment
```powershell
cd C:\path\to\network-packet-analyzer

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If Activate.ps1 fails, try with CMD:
```cmd
.\venv\Scripts\activate.bat
```

4) Run Analyzer
Option A – Manual:
```
python analyzer.py
```

Option B – Batch file (recommended):
Right click → **Run as Administrator** → run-windows.bat

5) Troubleshooting
- `No libpcap provider available` → Install Npcap in WinPcap-compatible mode
- `PermissionError` → Run as Administrator
- `The system cannot find the path specified` → venv missing → run `python -m venv venv` again
- Layer-2 sniffing unavailable → script will fallback to **L3 (IP-only)** capture

Stop with **Ctrl+C** → packets will be saved to `capture.pcap`.


## 📊 Example Output

```
Available interfaces:
  0: \Device\NPF_{19CE0FDA-...} (IPv4: 192.168.56.1)
  1: \Device\NPF_{335B866A-...} (IPv4: 192.168.1.8)
  2: \Device\NPF_Loopback

Choose interface index to capture on (default 0): 1
[+] Starting capture on interface: \Device\NPF_{335B866A-...}
```

Live packet capture:
```
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

📈 Protocol Statistics:
 - TCP: 152 (72.0%)
 - UDP: 47 (22.3%)
 - ICMP: 8 (3.8%)

Total packets captured: 207
Capture duration: 65.2 seconds
```

📸 **Example Demo Screenshot**

![Terminal Output](screenshots/output-terminal.png)

---

## 🔮 Future Improvements
- Add real-time visualization (graphs/charts for traffic)
- Build GUI dashboard
- Extend anomaly detection with ML models

---
