# 🔍 Task 1 — Basic Network Sniffer

> **CodeAlpha Cyber Security Internship | May–June 2026**
> **Author:** BAGATHEESHWAR A | **Reg No:** CA/DF1/82983

---

## 📌 Overview

A professional-grade **network packet sniffer** built with Python and Scapy.
It captures live network traffic, decodes multiple protocols, displays
color-coded output, tracks statistics, and saves logs — all from the terminal.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Protocol Support** | TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, SSH, FTP |
| **Color-coded output** | Each protocol shown in a distinct color |
| **Live statistics** | Packet counts, byte totals, top talkers |
| **BPF filtering** | Standard Berkeley Packet Filter expressions |
| **Protocol filter** | `--proto tcp/udp/icmp/dns/http` shortcut |
| **Payload preview** | Hex + ASCII preview of raw payloads (verbose mode) |
| **Log to file** | Save clean (ANSI-stripped) output with `-o` |
| **Interface listing** | `--list` shows all available NICs |

---

## 🖥️ Environment

- **OS:** Kali Linux (recommended) or any Linux with root access
- **Python:** 3.8+
- **Libraries:** Scapy, Colorama

---

## ⚙️ Installation

```bash
# 1. Clone the repo
git clone https://github.com/Bagatheeshwar/codealpha_tasks.git
cd codealpha_tasks/task1_network_sniffer

# 2. Install dependencies
sudo pip3 install -r requirements.txt --break-system-packages
```

---

## 🚀 Usage

> **Root / sudo is required** for raw packet capture.

### Basic capture (all traffic, all interfaces)
```bash
sudo python3 network_sniffer.py
```

### Capture on a specific interface
```bash
sudo python3 network_sniffer.py -i eth0
```

### Capture only DNS queries
```bash
sudo python3 network_sniffer.py --proto dns
```

### Capture 50 TCP packets with payload preview
```bash
sudo python3 network_sniffer.py -i eth0 --proto tcp -c 50 -v
```

### Capture HTTP with BPF filter and save to log
```bash
sudo python3 network_sniffer.py -f "tcp port 80" -o capture.log
```

### List all network interfaces
```bash
sudo python3 network_sniffer.py --list
```

---

## 🔧 Command-Line Options

```
-i, --iface     Network interface (e.g. eth0, wlan0)
-c, --count     Number of packets to capture (default: unlimited)
-f, --filter    BPF filter string (e.g. "tcp port 443")
-v, --verbose   Show hex+ASCII payload previews
-o, --output    Save output to a log file
-l, --list      List available interfaces and exit
    --proto     Protocol shortcut: tcp|udp|icmp|arp|dns|http
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════╗
║       CodeAlpha  ·  Network Sniffer v1.0         ║
║         Task 1  ·  Cyber Security Track          ║
╚══════════════════════════════════════════════════╝

  Author  : BAGATHEESHWAR A
  Reg No  : CA/DF1/82983
  Started : 2026-05-24 10:30:00

  Interface : eth0
  Filter    : none
  Count     : unlimited

  Press Ctrl+C to stop and view summary.

───────────────────────────────────────────────────
[10:30:01.234] ARP      Request  | Who has 192.168.1.1 ? Tell 192.168.1.105
[10:30:01.350] DNS      Query    | 192.168.1.105 → 8.8.8.8 | Query: google.com
[10:30:01.420] HTTPS    [SYN    ] | 192.168.1.105:54321 → 142.250.0.1:443 | len=60
[10:30:01.500] HTTP     [PSH|ACK] | 192.168.1.105:54322 → 93.184.0.1:80   | len=512
               └─ HTTP: GET / HTTP/1.1
[10:30:01.600] ICMP     Echo Request    | 192.168.1.105 → 8.8.8.8 | TTL=64 len=98

^C  [!] Capture stopped by user.

═══════════════════════════════════════════════════
  CAPTURE SUMMARY
═══════════════════════════════════════════════════
  Duration   : 0m 12s
  Total pkts : 45
  Total bytes: 18,432

  TCP   :    28   (HTTP: 6)
  UDP   :    10   (DNS : 8)
  ICMP  :     4
  ARP   :     2
  Other :     1

  Top 5 Source IPs:
    192.168.1.105                            38  ████████████████████
    8.8.8.8                                   5  ███
    142.250.0.1                               2  █
═══════════════════════════════════════════════════
```

---

## 📁 Repository Structure

```
task1_network_sniffer/
├── network_sniffer.py    ← Main sniffer script
├── requirements.txt      ← Python dependencies
├── README.md             ← This file
└── screenshots/          ← Output screenshots
    ├── dns_capture.png
    ├── http_capture.png
    └── summary.png
```

---

## 🔐 Ethical Note

> This tool is developed **strictly for educational purposes** as part of the
> CodeAlpha Cyber Security Internship. Use only on networks you **own or have
> explicit permission** to monitor. Unauthorized packet capture is illegal.

---

## 📚 Concepts Demonstrated

- Raw socket programming via Scapy
- OSI Layer 2–4 protocol analysis (ARP, IP, TCP, UDP, ICMP)
- Application-layer inspection (HTTP, DNS)
- Berkeley Packet Filter (BPF) syntax
- Signal handling (`SIGINT`) in Python
- Terminal formatting with ANSI color codes

---

## 👤 Author

**BAGATHEESHWAR A**
CodeAlpha Cyber Security Intern | CA/DF1/82983
Email: bajbp606@gmail.com
