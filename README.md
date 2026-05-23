# 🛡️ CodeAlpha — Cyber Security Internship Tasks

<div align="center">

![CodeAlpha](https://img.shields.io/badge/CodeAlpha-Cyber%20Security-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python)
![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=for-the-badge)

</div>

---

## 👤 Intern Details

| Field | Details |
|---|---|
| **Name** | BAGATHEESHWAR A |
| **Registration No.** | CA/DF1/82983 |
| **Domain** | Cyber Security |
| **Batch** | May – June 2026 |
| **Email** | bajbp606@gmail.com |
| **Duration** | 20th May 2026 – 20th June 2026 |

---

## 📋 Task Overview

| # | Task | Tools Used | Status |
|---|------|-----------|--------|
| 1 | [Basic Network Sniffer](#-task-1--basic-network-sniffer) | Python, Scapy, Colorama | ✅ Complete |
| 2 | [Phishing Awareness Training](#-task-2--phishing-awareness-training) | PowerPoint, HTML | ✅ Complete |
| 3 | [Secure Coding Review](#-task-3--secure-coding-review) | Python, Bandit, Semgrep | ✅ Complete |
| 4 | [Network Intrusion Detection System](#-task-4--network-intrusion-detection-system) | Python, Scapy, Snort | ✅ Complete |

---

## 📁 Repository Structure

```
codealpha_tasks/
│
├── README.md                          ← You are here
│
├── task1_network_sniffer/
│   ├── network_sniffer.py             ← Main sniffer script
│   ├── requirements.txt
│   ├── README.md
│   └── screenshots/
│
├── task2_phishing_awareness/
│   ├── phishing_training.pptx         ← Presentation slides
│   ├── phishing_quiz.html             ← Interactive quiz
│   ├── README.md
│   └── screenshots/
│
├── task3_secure_coding_review/
│   ├── vulnerable_code.py             ← Code with intentional flaws
│   ├── secure_code.py                 ← Fixed & hardened version
│   ├── review_report.md               ← Full audit report
│   ├── analyzer.py                    ← Automated scanning script
│   ├── README.md
│   └── screenshots/
│
└── task4_network_ids/
    ├── ids_system.py                  ← Intrusion detection engine
    ├── rules.json                     ← Detection rules
    ├── requirements.txt
    ├── README.md
    └── screenshots/
```

---

## 🔍 Task 1 — Basic Network Sniffer

A terminal-based **live packet capture tool** built with Python and Scapy.

**Highlights:**
- Captures TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, SSH, FTP packets
- Color-coded real-time output per protocol
- Live statistics: packet counts, byte totals, top talker IPs
- BPF filter support + protocol shortcut flags
- Verbose mode with hex + ASCII payload preview
- Saves clean log to file with `-o`

```bash
sudo python3 network_sniffer.py -i eth0 --proto dns
sudo python3 network_sniffer.py -i eth0 -f "tcp port 80" -v -o log.txt
```

📂 [View Task 1 →](./task1_network_sniffer/)

---

## 🎣 Task 2 — Phishing Awareness Training

An interactive **phishing awareness training module** for end-users.

**Highlights:**
- Professional presentation covering phishing types & red flags
- Real-world phishing email examples with analysis
- Interactive HTML quiz with instant scoring
- Best practices checklist and reporting guide

📂 [View Task 2 →](./task2_phishing_awareness/)

---

## 🔐 Task 3 — Secure Coding Review

A **vulnerability audit** of insecure Python code with a hardened rewrite.

**Highlights:**
- Identified vulnerabilities: SQL injection, hardcoded secrets, command injection, path traversal, weak crypto, insecure deserialization
- Side-by-side vulnerable vs. secure code comparison
- Automated scanning with Bandit
- Full written audit report with OWASP references

📂 [View Task 3 →](./task3_secure_coding_review/)

---

## 🚨 Task 4 — Network Intrusion Detection System

A **rule-based IDS** that monitors live traffic and fires alerts on suspicious patterns.

**Highlights:**
- Detects port scans, brute-force attempts, ARP spoofing, DNS tunneling, DoS patterns
- JSON-based rule engine (easily extensible)
- Alert severity levels: LOW / MEDIUM / HIGH / CRITICAL
- Real-time terminal dashboard + alert log

📂 [View Task 4 →](./task4_network_ids/)

---

## 🛠️ Environment

| Component | Version |
|---|---|
| OS | Kali Linux 2024.x |
| Python | 3.11+ |
| Key Libraries | Scapy 2.5, Colorama, Bandit |
| IDE | VS Code |

---

## ⚖️ Ethical Disclaimer

> All tools in this repository were developed **strictly for educational purposes**
> as part of the CodeAlpha Cyber Security Internship program.
> They must only be used on networks and systems you **own or have explicit
> written permission** to test. Unauthorized use is illegal and unethical.

---

## 📜 Certificate & Recognition

This repository is submitted to CodeAlpha for:
- ✅ Internship Completion Certificate
- ✅ Letter of Recommendation (LOR)
- 🏆 Top 10 Performer consideration

---

<div align="center">
  Made with ❤️ by <b>BAGATHEESHWAR A</b> · CodeAlpha Cyber Security Intern 2026
</div>
