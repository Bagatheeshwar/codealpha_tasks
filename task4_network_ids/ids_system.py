#!/usr/bin/env python3
"""
=============================================================
  Network Intrusion Detection System (NIDS)
  CodeAlpha Cybersecurity Internship - Task 4
  Intern: BAGATHEESHWAR A | ID: CA/DF1/82983
=============================================================
  Description:
    A real-time packet-sniffing IDS that detects common
    network intrusion patterns using Scapy.  Alerts are
    printed to the console, logged to a file, and a live
    summary report is generated on exit.

  Features:
    - Port scan detection  (SYN / FIN / NULL / XMAS)
    - Brute-force login detection  (SSH / FTP / HTTP)
    - ICMP flood / ping-of-death detection
    - DNS exfiltration heuristics
    - HTTP suspicious payload (SQL injection / XSS probes)
    - ARP spoofing detection
    - Customisable rule engine via rules.json
    - Colour-coded real-time console alerts
    - CSV + text log output
    - Summary report on exit
=============================================================
"""

import json
import csv
import os
import sys
import time
import signal
import argparse
import datetime
import threading
from collections import defaultdict

# ── Graceful import of Scapy ─────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
        get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed.  Run:  pip install scapy")
    print("[*] Running in DEMO / SIMULATION mode instead.\n")

# ── ANSI colour codes ─────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ─────────────────────────────────────────────────────────────────────────────
#  Configuration & globals
# ─────────────────────────────────────────────────────────────────────────────
RULES_FILE   = os.path.join(os.path.dirname(__file__), "rules.json")
LOG_FILE     = "ids_alerts.log"
CSV_FILE     = "ids_alerts.csv"
REPORT_FILE  = "ids_report.txt"

# Per-IP tracking counters (thread-safe via defaultdict)
syn_tracker      = defaultdict(list)   # {src_ip: [timestamps]}
icmp_tracker     = defaultdict(list)
ssh_tracker      = defaultdict(list)
ftp_tracker      = defaultdict(list)
http_tracker     = defaultdict(list)
dns_tracker      = defaultdict(list)
arp_table        = {}                  # {ip: mac}

alert_counter    = defaultdict(int)    # {alert_type: count}
total_packets    = 0
start_time       = time.time()
rules            = {}
csv_writer       = None
csv_file_handle  = None
lock             = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
#  Rule loader
# ─────────────────────────────────────────────────────────────────────────────
def load_rules(path: str) -> dict:
    """Load detection thresholds and signatures from rules.json."""
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        print(f"{GREEN}[+] Rules loaded from {path}{RESET}")
        return data
    except FileNotFoundError:
        print(f"{YELLOW}[!] {path} not found – using built-in defaults.{RESET}")
        return {}


def get_rule(category: str, key: str, default):
    """Retrieve a rule value with fallback to default."""
    return rules.get(category, {}).get(key, default)


# ─────────────────────────────────────────────────────────────────────────────
#  Alert engine
# ─────────────────────────────────────────────────────────────────────────────
def alert(level: str, alert_type: str, src: str, dst: str, detail: str):
    """
    Emit a colour-coded alert to stdout, append to log & CSV.
    level: HIGH | MEDIUM | LOW
    """
    global csv_writer

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colour    = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else CYAN)

    msg = (f"{colour}{BOLD}[{level}]{RESET} "
           f"{timestamp}  {alert_type:<35} "
           f"SRC: {src:<18} DST: {dst:<18}  {detail}")
    print(msg)

    # Plain-text log
    with open(LOG_FILE, "a") as lf:
        lf.write(f"[{level}] {timestamp} | {alert_type} | SRC:{src} DST:{dst} | {detail}\n")

    # CSV log
    if csv_writer:
        with lock:
            csv_writer.writerow([timestamp, level, alert_type, src, dst, detail])
            csv_file_handle.flush()

    with lock:
        alert_counter[alert_type] += 1


# ─────────────────────────────────────────────────────────────────────────────
#  Detection functions
# ─────────────────────────────────────────────────────────────────────────────
def _prune(tracker_list: list, window: int) -> list:
    """Keep only entries within the last `window` seconds."""
    now = time.time()
    return [t for t in tracker_list if now - t < window]


# ── Port Scan Detection ───────────────────────────────────────────────────────
def detect_port_scan(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    flags = pkt[TCP].flags

    window   = get_rule("port_scan", "window_seconds", 10)
    threshold = get_rule("port_scan", "syn_threshold", 20)

    # SYN Scan
    if flags == 0x02:  # SYN only
        syn_tracker[src].append(time.time())
        syn_tracker[src] = _prune(syn_tracker[src], window)
        if len(syn_tracker[src]) >= threshold:
            alert("HIGH", "PORT_SCAN_SYN",  src, dst,
                  f"{len(syn_tracker[src])} SYN packets in {window}s")
            syn_tracker[src].clear()

    # FIN Scan
    elif flags == 0x01:
        alert("MEDIUM", "PORT_SCAN_FIN", src, dst, "FIN scan probe detected")

    # NULL Scan (no flags)
    elif flags == 0x00:
        alert("MEDIUM", "PORT_SCAN_NULL", src, dst, "NULL scan probe detected")

    # XMAS Scan (FIN+PSH+URG)
    elif flags == 0x29:
        alert("HIGH", "PORT_SCAN_XMAS", src, dst, "XMAS scan probe detected")


# ── Brute-Force Detection ─────────────────────────────────────────────────────
def detect_brute_force(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    src   = pkt[IP].src
    dst   = pkt[IP].dst
    dport = pkt[TCP].dport

    window    = get_rule("brute_force", "window_seconds", 60)
    threshold = get_rule("brute_force", "attempt_threshold", 10)
    now       = time.time()

    def _check(tracker, label):
        tracker[src].append(now)
        tracker[src] = _prune(tracker[src], window)
        if len(tracker[src]) >= threshold:
            alert("HIGH", f"BRUTE_FORCE_{label}", src, dst,
                  f"{len(tracker[src])} attempts in {window}s")
            tracker[src].clear()

    if dport == 22:
        _check(ssh_tracker, "SSH")
    elif dport == 21:
        _check(ftp_tracker, "FTP")
    elif dport in (80, 443, 8080, 8443):
        _check(http_tracker, "HTTP")


# ── ICMP Flood Detection ──────────────────────────────────────────────────────
def detect_icmp_flood(pkt):
    if not pkt.haslayer(ICMP) or not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    window    = get_rule("icmp_flood", "window_seconds", 5)
    threshold = get_rule("icmp_flood", "packet_threshold", 30)

    icmp_tracker[src].append(time.time())
    icmp_tracker[src] = _prune(icmp_tracker[src], window)
    if len(icmp_tracker[src]) >= threshold:
        alert("HIGH", "ICMP_FLOOD", src, dst,
              f"{len(icmp_tracker[src])} ICMP packets in {window}s")
        icmp_tracker[src].clear()

    # Ping of Death: oversized ICMP
    if len(pkt) > 65535:
        alert("HIGH", "PING_OF_DEATH", src, dst,
              f"Oversized ICMP packet: {len(pkt)} bytes")


# ── DNS Exfiltration Heuristics ───────────────────────────────────────────────
def detect_dns_exfiltration(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    window      = get_rule("dns_exfil", "window_seconds", 60)
    threshold   = get_rule("dns_exfil", "query_threshold", 50)
    label_limit = get_rule("dns_exfil", "label_length_threshold", 40)

    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors="ignore")
        # Long subdomain label = possible exfiltration channel
        for label in qname.split("."):
            if len(label) > label_limit:
                alert("HIGH", "DNS_EXFILTRATION", src, dst,
                      f"Suspicious long label ({len(label)} chars): {qname[:60]}")
                return

        dns_tracker[src].append(time.time())
        dns_tracker[src] = _prune(dns_tracker[src], window)
        if len(dns_tracker[src]) >= threshold:
            alert("MEDIUM", "DNS_TUNNELING", src, dst,
                  f"{len(dns_tracker[src])} DNS queries in {window}s")
            dns_tracker[src].clear()


# ── HTTP Payload Inspection ───────────────────────────────────────────────────
SQL_SIGNATURES = [
    "' or '1'='1", "union select", "drop table", "insert into",
    "xp_cmdshell", "exec(", "cast(", "--", "/*", "0x"
]
XSS_SIGNATURES = [
    "<script", "javascript:", "onerror=", "onload=", "alert(",
    "document.cookie", "eval(", "src=http"
]

def detect_http_attack(pkt):
    if not pkt.haslayer(Raw) or not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    try:
        payload = pkt[Raw].load.decode(errors="ignore").lower()
    except Exception:
        return

    for sig in SQL_SIGNATURES:
        if sig in payload:
            alert("HIGH", "SQL_INJECTION", src, dst,
                  f"Signature matched: '{sig[:30]}'")
            return

    for sig in XSS_SIGNATURES:
        if sig in payload:
            alert("HIGH", "XSS_PROBE", src, dst,
                  f"Signature matched: '{sig[:30]}'")
            return


# ── ARP Spoofing Detection ────────────────────────────────────────────────────
def detect_arp_spoof(pkt):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    if arp.op != 2:   # only ARP replies
        return

    ip_addr  = arp.psrc
    mac_addr = arp.hwsrc

    if ip_addr in arp_table:
        if arp_table[ip_addr] != mac_addr:
            alert("HIGH", "ARP_SPOOFING", ip_addr, "LAN",
                  f"MAC changed: {arp_table[ip_addr]} → {mac_addr}")
    arp_table[ip_addr] = mac_addr


# ─────────────────────────────────────────────────────────────────────────────
#  Master packet handler
# ─────────────────────────────────────────────────────────────────────────────
def packet_handler(pkt):
    global total_packets
    with lock:
        total_packets += 1

    detect_port_scan(pkt)
    detect_brute_force(pkt)
    detect_icmp_flood(pkt)
    detect_dns_exfiltration(pkt)
    detect_http_attack(pkt)
    detect_arp_spoof(pkt)


# ─────────────────────────────────────────────────────────────────────────────
#  Summary report
# ─────────────────────────────────────────────────────────────────────────────
def generate_report():
    elapsed  = time.time() - start_time
    total_a  = sum(alert_counter.values())
    lines = [
        "=" * 60,
        "  NETWORK INTRUSION DETECTION SYSTEM – SESSION REPORT",
        f"  Intern : BAGATHEESHWAR A  |  ID: CA/DF1/82983",
        "=" * 60,
        f"  Session Duration : {elapsed:.1f} seconds",
        f"  Packets Analysed : {total_packets}",
        f"  Total Alerts     : {total_a}",
        "",
        "  Alert Breakdown:",
    ]
    for atype, count in sorted(alert_counter.items(), key=lambda x: -x[1]):
        lines.append(f"    {atype:<38} {count:>5} alert(s)")
    lines += [
        "",
        f"  Log files : {LOG_FILE}",
        f"              {CSV_FILE}",
        "=" * 60,
    ]
    report = "\n".join(lines)
    print(f"\n{CYAN}{report}{RESET}")
    with open(REPORT_FILE, "w") as rf:
        rf.write(report + "\n")
    print(f"{GREEN}[+] Report saved → {REPORT_FILE}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
#  Signal handler (Ctrl+C)
# ─────────────────────────────────────────────────────────────────────────────
def _sigint_handler(sig, frame):
    print(f"\n{YELLOW}[!] Stopping IDS…{RESET}")
    generate_report()
    if csv_file_handle:
        csv_file_handle.close()
    sys.exit(0)


signal.signal(signal.SIGINT, _sigint_handler)


# ─────────────────────────────────────────────────────────────────────────────
#  Demo / simulation mode (no Scapy / no root)
# ─────────────────────────────────────────────────────────────────────────────
def run_demo():
    """Simulate packet alerts so the IDS can be tested without root / Scapy."""
    print(f"{CYAN}{'='*60}")
    print("   IDS DEMO MODE – Simulated Packet Stream")
    print(f"{'='*60}{RESET}\n")

    demo_events = [
        ("HIGH",   "PORT_SCAN_SYN",   "192.168.1.100", "10.0.0.1",   "25 SYN packets in 10s"),
        ("HIGH",   "BRUTE_FORCE_SSH", "10.10.10.5",    "192.168.0.1","15 attempts in 60s"),
        ("MEDIUM", "PORT_SCAN_XMAS",  "172.16.0.50",   "10.0.0.2",   "XMAS scan probe detected"),
        ("HIGH",   "ICMP_FLOOD",      "192.168.2.200", "10.0.0.3",   "40 ICMP packets in 5s"),
        ("HIGH",   "SQL_INJECTION",   "203.0.113.77",  "10.0.0.4",   "Signature: union select"),
        ("HIGH",   "ARP_SPOOFING",    "192.168.1.1",   "LAN",        "MAC changed: aa:bb → cc:dd"),
        ("HIGH",   "DNS_EXFILTRATION","10.20.30.40",   "8.8.8.8",    "Label 52 chars: exfil.base64encoded.evil.com"),
        ("MEDIUM", "DNS_TUNNELING",   "10.10.0.9",     "8.8.4.4",    "60 DNS queries in 60s"),
        ("HIGH",   "XSS_PROBE",       "198.51.100.3",  "10.0.0.5",   "Signature: <script"),
        ("HIGH",   "BRUTE_FORCE_FTP", "172.16.1.11",   "10.0.0.6",   "12 attempts in 60s"),
    ]

    for level, atype, src, dst, detail in demo_events:
        alert(level, atype, src, dst, detail)
        time.sleep(0.6)

    print(f"\n{GREEN}[+] Demo complete – {len(demo_events)} simulated alerts fired.{RESET}")
    generate_report()


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    global rules, csv_writer, csv_file_handle

    parser = argparse.ArgumentParser(
        description="CodeAlpha Network IDS – Task 4",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to sniff (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Packet count (0 = unlimited)")
    parser.add_argument("--demo", action="store_true",
                        help="Run in simulation/demo mode (no root needed)")
    parser.add_argument("--rules", default=RULES_FILE,
                        help=f"Path to rules JSON (default: {RULES_FILE})")
    args = parser.parse_args()

    # Banner
    print(f"""
{BLUE}{BOLD}
╔══════════════════════════════════════════════════════════╗
║      Network Intrusion Detection System (NIDS)           ║
║      CodeAlpha Cybersecurity Internship – Task 4         ║
║      Intern : BAGATHEESHWAR A  |  CA/DF1/82983           ║
╚══════════════════════════════════════════════════════════╝
{RESET}""")

    # Load rules
    rules = load_rules(args.rules)

    # Initialise CSV log
    csv_file_handle = open(CSV_FILE, "w", newline="")
    csv_writer = csv.writer(csv_file_handle)
    csv_writer.writerow(["Timestamp", "Level", "Alert_Type",
                         "Source_IP", "Destination_IP", "Detail"])

    # Demo mode
    if args.demo or not SCAPY_AVAILABLE:
        run_demo()
        csv_file_handle.close()
        return

    # Live sniffing – requires root / admin
    iface = args.interface
    if iface is None:
        ifaces = get_if_list()
        iface  = ifaces[0] if ifaces else None

    print(f"{GREEN}[+] Sniffing on interface: {iface or 'default'}{RESET}")
    print(f"{YELLOW}[*] Listening for intrusions… Press Ctrl+C to stop.{RESET}\n")

    try:
        sniff(iface=iface,
              prn=packet_handler,
              count=args.count,
              store=False)
    except PermissionError:
        print(f"{RED}[!] Permission denied – run as root/Administrator "
              f"or use --demo flag.{RESET}")
        sys.exit(1)
    except Exception as exc:
        print(f"{RED}[!] Sniff error: {exc}{RESET}")
    finally:
        generate_report()
        csv_file_handle.close()


if __name__ == "__main__":
    main()
