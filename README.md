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

1) **Clone and enter the project folder**
```bash
git clone https://github.com/taniafatmawati/network-packet-analyzer.git
cd network-packet-analyzer
```

2) **Create a virtual environment & install dependencies**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3) **Run the analyzer (requires root privileges)**
Make sure to use the Python interpreter from your virtual environment:
```bash
sudo -E ./venv/bin/python analyzer.py
```

### Windows Setup & Usage

1) **Install Npcap**
- Download: [Npcap](https://npcap.com/)  
- Enable **“WinPcap API-compatible mode”** during installation
- Restart after installation

2) **Clone and enter the project folder**
```powershell
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

3) **Create a virtual environment & install dependencies**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the script, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

(Alternative via CMD:)
```cmd
venv\Scripts\activate.bat
```

4) **Run Analyzer**
Option A – Manual:
```powershell
python analyzer.py
```

Option B – Batch file (recommended):
Right click `run-windows.bat` → **Run as Administrator**

**Stop the capture**
- Press **Ctrl+C** in the terminal
- Results will automatically be saved to capture.pcap

📌 Tip: Open the `capture.pcap` file in **Wireshark** for further analysis.

---

## 🎬 Demo (Loopback)

This demo uses **interface 0 (loopback, 127.0.0.1)** so anyone can reproduce it locally without affecting networks.


### How to Run (Step-by-Step)

#### Terminal A — Analyzer

Start the analyzer and choose interface `0`:

```bash
sudo -E ./venv/bin/python analyzer.py
# When prompted, type: 0
````

#### Terminal B — Demo Script

Run a prepared demo sequence to generate TCP/UDP/ICMP traffic and trigger anomaly detection:

```bash
chmod +x demo-loopback.sh
./demo-loopback.sh
```

The script runs:
- TCP test (curl) — optional external request
- UDP test — send a UDP packet to localhost (port 9999)
- ICMP test — ping 127.0.0.1
- Suspicious port test — attempt to connect to port 4444, then start a listener and connect successfully
- Port scan test — scan ports 1–20 (nmap or nc fallback)
- Controlled many-connects to try to trigger port-scan/DoS alerts

Watch Terminal A — you will see live packet logs, alerts for suspicious ports, port scans, and DoS-like traffic.

Stop the analyzer with **Ctrl+C**. Results are automatically saved to `capture.pcap`.

Inspect the pcap:

```bash
ls -l capture.pcap
# Optional: view summary (requires tshark)
tshark -r capture.pcap -q -z io,phs
# Or copy to your local machine for Wireshark
scp user@server:/path/to/network-packet-analyzer/capture.pcap ~/Downloads/
```

> ⚠️ Note: `capture.pcap` is **not included** in the repository. Generate it safely using the demo script.

---

### Example Demo Output

```
Available interfaces:
  0: lo - IPv4: 127.0.0.1
  1: enp0s3 - IPv4: 192.168.1.64
  2: tun0 - IPv4: 10.8.0.1

Choose interface index to capture on (default 0): 0
[+] Starting capture on interface: lo

Live capture:
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 60032, DstPort: 4444
   ⚠️ Anomaly detected: Connection attempt to suspicious port 4444
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 60046, DstPort: 4444
   ⚠️ Anomaly detected: Connection attempt to suspicious port 4444
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 4444, DstPort: 60046
   ⚠️ Possible DoS attack detected from 127.0.0.1 (21 connections in 5s)
[UDP] 127.0.0.1 → 127.0.0.1 | SrcPort: 36138, DstPort: 9999
[ICMP] 127.0.0.1 → 127.0.0.1 | Type: 8
[ICMP] 127.0.0.1 → 127.0.0.1 | Type: 0
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 32782, DstPort: 80
   ⚠️ Possible DoS attack detected from 127.0.0.1 (25 connections in 5s)
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 53374, DstPort: 16
   ⚠️ Possible DoS attack detected from 127.0.0.1 (33 connections in 5s)
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 53496, DstPort: 9
   ⚠️ Possible DoS attack detected from 127.0.0.1 (37 connections in 5s)
   ⚠️ Possible Port Scan detected from 127.0.0.1 (scanned 11 ports in 10s)
[TCP] 127.0.0.1 → 127.0.0.1 | SrcPort: 60292, DstPort: 3
   ⚠️ Possible DoS attack detected from 127.0.0.1 (50 connections in 5s)
   ⚠️ Possible Port Scan detected from 127.0.0.1 (scanned 16 ports in 10s)

... (similar alerts repeated) ...

When stopped with **Ctrl+C**:
📊 Capture stopped. Saving results...
[+] Packets saved to capture.pcap

📈 Protocol Statistics:
 - TCP: 512 (96.2%)
 - UDP: 2 (0.4%)
 - ICMP: 18 (3.4%)

Total packets captured: 532
Capture duration: 71.2 seconds

```

### 📸 Example Demo Screenshot:

**1) Live capture (analyzer console)**  
![Live capture terminal](screenshots/demo-terminal.png)

**2) Capture summary after stop (statistics & saved pcap)**  
![Capture summary](screenshots/demo-summary.png)


> Notes:
> - Screenshots show example output from `demo-loopback.sh` run on interface `lo` (127.0.0.1).

---

### Notes

* The demo script is **loopback-only** and safe.
* For a realistic network demo, capture on your LAN interface and run tests from a different host.
* Ensure `nmap` and `nc` are installed for full test coverage:

```bash
sudo dnf install -y nmap ncat
```

---

## 🔮 Future Improvements
- Add real-time visualization (graphs/charts for traffic)
- Build GUI dashboard
- Extend anomaly detection with ML models

---
