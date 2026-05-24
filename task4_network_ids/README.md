# 🛡️ Task 4 – Network Intrusion Detection System (NIDS)

**CodeAlpha Cybersecurity Internship | May–June 2026 Batch**  
**Intern:** BAGATHEESHWAR A &nbsp;|&nbsp; **ID:** CA/DF1/82983  
**Domain:** Cyber Security

---

## 📌 Overview

This project implements a **real-time Network Intrusion Detection System (NIDS)** using Python and Scapy.
It sniffs live network traffic, analyses each packet against a configurable rule engine, and raises
colour-coded alerts for suspicious behaviour such as port scans, brute-force attempts, ICMP floods,
DNS exfiltration, SQL injection probes, XSS attempts, and ARP spoofing.

---

## 🎯 Detection Capabilities

| # | Attack / Technique | Detection Method |
|---|---|---|
| 1 | **SYN Port Scan** | ≥20 SYN-only packets from same src in 10 s |
| 2 | **FIN / NULL / XMAS Scan** | Flag pattern matching on TCP flags |
| 3 | **SSH Brute-Force** | ≥10 TCP SYN to port 22 in 60 s |
| 4 | **FTP Brute-Force** | ≥10 TCP SYN to port 21 in 60 s |
| 5 | **HTTP Brute-Force** | ≥10 TCP SYN to ports 80/443 in 60 s |
| 6 | **ICMP Flood** | ≥30 ICMP packets from same src in 5 s |
| 7 | **Ping of Death** | ICMP packet size > 65535 bytes |
| 8 | **DNS Exfiltration** | Subdomain label length > 40 chars |
| 9 | **DNS Tunnelling** | ≥50 DNS queries from same src in 60 s |
| 10 | **SQL Injection** | Payload signatures (UNION SELECT, DROP TABLE…) |
| 11 | **XSS Probe** | Payload signatures (`<script>`, `onerror=`…) |
| 12 | **ARP Spoofing** | MAC address change for known IP in ARP table |

All thresholds are fully customisable in **`rules.json`**.

---

## 📁 Project Structure

```
task4_network_ids/
├── ids_system.py       ← Main IDS engine (packet sniffer + alert engine)
├── rules.json          ← Detection rules and thresholds
├── requirements.txt    ← Python dependencies
├── README.md           ← This file
└── screenshots/        ← Demo output screenshots
```

---

## ⚙️ Installation

### Prerequisites

- **OS:** Kali Linux (recommended) or any Linux distro / Windows 10+
- **Python:** 3.8+
- **Privileges:** Root / Administrator (required for raw-socket sniffing)

### Step 1 – Clone the Repository

```bash
git clone https://github.com/Bagatheeshwar/codealpha_tasks.git
cd codealpha_tasks/task4_network_ids
```

### Step 2 – Install Dependencies

```bash
pip install -r requirements.txt
# or
pip3 install scapy rich
```

### Step 3 – Run on Kali Linux (Live Mode)

```bash
sudo python3 ids_system.py
```

### Step 4 – Specify Interface (Optional)

```bash
# List available interfaces
ip link show

# Use a specific interface
sudo python3 ids_system.py -i eth0
sudo python3 ids_system.py -i wlan0
```

### Step 5 – Demo / Test Mode (No Root Needed)

Run a simulation with 10 pre-defined attack scenarios — no network access or root privileges required:

```bash
python3 ids_system.py --demo
```

---

## 🚀 Usage

```
usage: ids_system.py [-h] [-i INTERFACE] [-c COUNT] [--demo] [--rules RULES]

optional arguments:
  -h, --help            Show this help message and exit
  -i, --interface       Network interface to sniff (default: auto-detect)
  -c, --count           Number of packets to capture (0 = unlimited)
  --demo                Run simulation mode (no root / Scapy needed)
  --rules               Path to custom rules JSON file
```

### Examples

```bash
# Unlimited sniffing on eth0
sudo python3 ids_system.py -i eth0

# Capture exactly 500 packets on wlan0
sudo python3 ids_system.py -i wlan0 -c 500

# Demo mode
python3 ids_system.py --demo

# Custom rules file
sudo python3 ids_system.py --rules /path/to/custom_rules.json
```

---

## 📊 Output Files

After a session, three output files are generated:

| File | Description |
|---|---|
| `ids_alerts.log` | Human-readable plain-text alert log |
| `ids_alerts.csv` | Machine-readable CSV (Timestamp, Level, Alert\_Type, Src, Dst, Detail) |
| `ids_report.txt` | Summary report: total packets, alert breakdown by type |

### Sample Alert Console Output

```
[HIGH]   2026-05-24 14:32:01  PORT_SCAN_SYN           SRC: 192.168.1.100   DST: 10.0.0.1     25 SYN packets in 10s
[HIGH]   2026-05-24 14:32:02  BRUTE_FORCE_SSH         SRC: 10.10.10.5      DST: 192.168.0.1  15 attempts in 60s
[MEDIUM] 2026-05-24 14:32:03  PORT_SCAN_XMAS          SRC: 172.16.0.50     DST: 10.0.0.2     XMAS scan probe detected
[HIGH]   2026-05-24 14:32:04  ICMP_FLOOD              SRC: 192.168.2.200   DST: 10.0.0.3     40 ICMP packets in 5s
[HIGH]   2026-05-24 14:32:05  SQL_INJECTION           SRC: 203.0.113.77    DST: 10.0.0.4     Signature matched: 'union select'
[HIGH]   2026-05-24 14:32:06  ARP_SPOOFING            SRC: 192.168.1.1     DST: LAN          MAC changed: aa:bb → cc:dd
```

---

## 🔧 Customising Rules

Edit `rules.json` to tune detection thresholds:

```json
{
  "port_scan": {
    "syn_threshold": 20,        // Raise to reduce false positives
    "window_seconds": 10
  },
  "brute_force": {
    "attempt_threshold": 10,    // Lower for stricter detection
    "window_seconds": 60
  },
  "icmp_flood": {
    "packet_threshold": 30,
    "window_seconds": 5
  }
}
```

---

## 🔑 Alert Severity Levels

| Level | Colour | Meaning |
|---|---|---|
| **HIGH** | 🔴 Red | Immediate threat – requires investigation |
| **MEDIUM** | 🟡 Yellow | Suspicious activity – monitor closely |
| **LOW** | 🔵 Cyan | Informational / low-risk anomaly |

---

## 🛠️ How It Works (Technical Flow)

```
                        ┌─────────────────────────────┐
  Network Interface  →  │   Scapy packet_handler()    │
   (raw socket)         └────────────┬────────────────┘
                                     │ dispatches to
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
    detect_port_scan()   detect_brute_force()   detect_icmp_flood()
    detect_dns_exfil()   detect_http_attack()   detect_arp_spoof()
              │                      │                      │
              └──────────────────────┼──────────────────────┘
                                     │
                              alert() function
                                     │
                      ┌──────────────┼──────────────┐
                      │              │              │
               Console (ANSI)   ids_alerts.log  ids_alerts.csv
```

---

## 🧪 Testing the IDS

### Test 1 – Demo Mode

```bash
python3 ids_system.py --demo
```
Expected: 10 simulated alerts fire across all detection categories.

### Test 2 – Port Scan (from another terminal / machine)

```bash
# On attacker machine (using nmap)
nmap -sS <target-ip>   # SYN scan
nmap -sF <target-ip>   # FIN scan
nmap -sX <target-ip>   # XMAS scan
```

### Test 3 – ICMP Flood

```bash
sudo ping -f <target-ip>
```

### Test 4 – Brute Force Simulation

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```

---

## 📚 Technologies Used

| Technology | Purpose |
|---|---|
| **Python 3** | Core programming language |
| **Scapy** | Packet capture and protocol parsing |
| **JSON** | Rule / configuration storage |
| **CSV** | Structured alert logging |
| **Threading / Locks** | Thread-safe counter updates |
| **ANSI Escape Codes** | Colour-coded terminal output |

---

## ⚠️ Legal / Ethical Notice

> This tool is developed **strictly for educational purposes** as part of the CodeAlpha Cybersecurity Internship.  
> Only run this IDS on **networks you own or have explicit written permission to monitor**.  
> Unauthorised interception of network traffic is illegal in most jurisdictions.

---

## 👤 Author

**BAGATHEESHWAR A**  
Registration: CA/DF1/82983  
CodeAlpha Cybersecurity Internship | May–June 2026  
Email: bajbp606@gmail.com

---

## 📜 License

This project is submitted as part of the CodeAlpha internship programme.  
All code is original work by the intern. Free to use for educational purposes.
