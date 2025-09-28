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

---

**Stop the capture**
- Press **Ctrl+C** in the terminal
- Results will automatically be saved to capture.pcap

📌 Tip: Open the `capture.pcap` file in **Wireshark** for further analysis.

---

## 🎬 Demo (Loopback)

This demo shows the analyzer in action using **interface 0 (loopback, 127.0.0.1)**.  
All tests are safe and local — no external network impact.

---

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

* The script runs:

  1. TCP test (HTTPS request via `curl`)
  2. UDP test (DNS query via `nslookup`)
  3. ICMP test (`ping`)
  4. Suspicious port test (`nc` to 4444, plus temporary listener)
  5. Port scan test (ports 1–20 via `nmap` or fallback `nc`)
  6. Controlled “many connects” simulation to trigger port-scan / DoS detection

Watch Terminal A — you will see live packet logs, alerts for suspicious ports, port scans, and DoS-like traffic.

---

### Stopping & Inspecting Capture

* Stop the analyzer with **Ctrl+C**.
* Results are automatically saved to `capture.pcap`.

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
```

Live capture:

```
[TCP] 127.0.0.1 → 142.250.182.14 | SrcPort: 51512, DstPort: 443
[UDP] 127.0.0.1 → 8.8.8.8 | SrcPort: 5353, DstPort: 53
[ICMP] 127.0.0.1 → 127.0.0.1 | Type: 8
   ⚠️ Anomaly detected: Connection attempt to suspicious port 4444
   ⚠️ Possible Port Scan detected from 127.0.0.1 (scanned 12 ports in 10s)
```

When stopped with **Ctrl+C**, results:

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

📸 Example Screenshot:

![Terminal Output](screenshots/output-terminal.png)

---

### Notes

* The demo script is **loopback-only** and safe.
* If you want to reproduce external traffic, change the interface and run from another host.
* Ensure `nmap` and `nc` are installed for full test coverage:

```bash
sudo dnf install -y nmap ncat
```

## 🔮 Future Improvements
- Add real-time visualization (graphs/charts for traffic)
- Build GUI dashboard
- Extend anomaly detection with ML models

---
