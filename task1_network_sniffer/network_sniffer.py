#!/usr/bin/env python3
"""
=======================================================
  CodeAlpha Internship - Cyber Security
  Task 1: Basic Network Sniffer
  Author  : BAGATHEESHWAR A
  Reg No  : CA/DF1/82983
  Date    : May 2026
=======================================================
  Description:
    A professional-grade network packet sniffer built
    with Scapy. Captures and analyses TCP, UDP, ICMP,
    DNS, HTTP, and ARP packets with live statistics,
    color-coded output, and optional log-file saving.
=======================================================
"""

import os
import sys
import time
import signal
import argparse
import datetime
from collections import defaultdict

# ── Dependency check ──────────────────────────────────
try:
    from scapy.all import (sniff, IP, IPv6, TCP, UDP, ICMP,
                           ARP, DNS, DNSQR, Raw, get_if_list)
except ImportError:
    print("[ERROR] Scapy not found. Run: sudo pip3 install scapy --break-system-packages")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

# ── Color helpers ─────────────────────────────────────
def _c(color, text):
    """Apply terminal color if colorama is available."""
    if not COLORS:
        return text
    return color + text + Style.RESET_ALL

def RED(t):    return _c(Fore.RED,     t)
def GREEN(t):  return _c(Fore.GREEN,   t)
def YELLOW(t): return _c(Fore.YELLOW,  t)
def CYAN(t):   return _c(Fore.CYAN,    t)
def BLUE(t):   return _c(Fore.BLUE,    t)
def MAGENTA(t):return _c(Fore.MAGENTA, t)
def WHITE(t):  return _c(Fore.WHITE,   t)
def BOLD(t):
    return (Style.BRIGHT + t + Style.RESET_ALL) if COLORS else t

# ── Global counters ───────────────────────────────────
stats = {
    "total":   0,
    "tcp":     0,
    "udp":     0,
    "icmp":    0,
    "arp":     0,
    "dns":     0,
    "http":    0,
    "other":   0,
    "bytes":   0,
}
ip_counter  = defaultdict(int)   # top talkers
start_time  = None
log_file    = None
packet_log  = []                 # kept in memory for summary

# ── Banner ────────────────────────────────────────────
BANNER = r"""
  ╔══════════════════════════════════════════════════╗
  ║       CodeAlpha  ·  Network Sniffer v1.0         ║
  ║         Task 1  ·  Cyber Security Track          ║
  ╚══════════════════════════════════════════════════╝
"""

def print_banner():
    print(CYAN(BANNER))
    print(BOLD("  Author  : ") + "BAGATHEESHWAR A")
    print(BOLD("  Reg No  : ") + "CA/DF1/82983")
    print(BOLD("  Started : ") + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print()

# ── Protocol parsers ──────────────────────────────────
def parse_tcp(pkt):
    flags = []
    flag_map = {0x01: "FIN", 0x02: "SYN", 0x04: "RST",
                0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
    for bit, name in flag_map.items():
        if pkt[TCP].flags & bit:
            flags.append(name)
    flag_str = "|".join(flags) if flags else "NONE"

    # Detect HTTP (port 80 / 8080 / 8000)
    is_http = (pkt[TCP].dport in (80, 8080, 8000) or
               pkt[TCP].sport in (80, 8080, 8000))
    if is_http and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode("utf-8", errors="replace")
        http_line = payload.split("\r\n")[0][:80]
        return flag_str, f"HTTP: {http_line}"
    return flag_str, None

def parse_dns(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            return pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            return "?"
    return None

def get_payload_preview(pkt):
    """Return first 40 bytes of raw payload as hex + ASCII."""
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)[:40]
        hex_str  = raw.hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        return f"{hex_str}  |  {ascii_str}"
    return None

# ── Main packet handler ───────────────────────────────
def packet_handler(pkt, verbose=False):
    global stats, log_file

    stats["total"] += 1
    pkt_len = len(pkt)
    stats["bytes"] += pkt_len
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # ── ARP ──────────────────────────────────────────
    if pkt.haslayer(ARP):
        stats["arp"] += 1
        op = "Request" if pkt[ARP].op == 1 else "Reply"
        line = (f"[{timestamp}] "
                f"{YELLOW('ARP')} {op:8s} | "
                f"Who has {CYAN(pkt[ARP].pdst)} ? "
                f"Tell {CYAN(pkt[ARP].psrc)}")
        print(line)
        _log(line)
        return

    # ── IP packets ────────────────────────────────────
    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
        stats["other"] += 1
        return

    # Determine IP version
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl    = pkt[IP].ttl
        proto  = pkt[IP].proto
    else:                                          # IPv6
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        ttl    = pkt[IPv6].hlim
        proto  = pkt[IPv6].nh

    # Track top talkers
    ip_counter[src_ip] += 1

    # ── ICMP ─────────────────────────────────────────
    if pkt.haslayer(ICMP):
        stats["icmp"] += 1
        icmp_type = {0: "Echo Reply", 8: "Echo Request",
                     3: "Dest Unreachable", 11: "Time Exceeded"
                     }.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
        line = (f"[{timestamp}] "
                f"{MAGENTA('ICMP')} {icmp_type:18s} | "
                f"{CYAN(src_ip)} → {CYAN(dst_ip)} | "
                f"TTL={ttl} len={pkt_len}")
        print(line)
        _log(line)
        return

    # ── TCP ──────────────────────────────────────────
    if pkt.haslayer(TCP):
        stats["tcp"] += 1
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flag_str, http_info = parse_tcp(pkt)

        if http_info:
            stats["http"] += 1
            color = GREEN
            proto_label = "HTTP"
        elif dport == 443 or sport == 443:
            color = BLUE
            proto_label = "HTTPS"
        elif dport == 22 or sport == 22:
            color = YELLOW
            proto_label = "SSH"
        elif dport == 21 or sport == 21:
            color = RED
            proto_label = "FTP"
        else:
            color = WHITE
            proto_label = "TCP"

        line = (f"[{timestamp}] "
                f"{color(proto_label):8s} "
                f"[{flag_str:12s}] | "
                f"{CYAN(src_ip)}:{sport} → {CYAN(dst_ip)}:{dport} | "
                f"len={pkt_len}")
        if http_info and verbose:
            line += f"\n         └─ {GREEN(http_info)}"
        print(line)
        _log(line)

        if verbose and not http_info:
            preview = get_payload_preview(pkt)
            if preview:
                print(f"         └─ Payload: {preview}")
        return

    # ── UDP / DNS ─────────────────────────────────────
    if pkt.haslayer(UDP):
        stats["udp"] += 1
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        dns_query = parse_dns(pkt)
        if dns_query:
            stats["dns"] += 1
            line = (f"[{timestamp}] "
                    f"{BLUE('DNS'):8s} Query     | "
                    f"{CYAN(src_ip)} → {CYAN(dst_ip)} | "
                    f"Query: {YELLOW(dns_query)}")
        else:
            line = (f"[{timestamp}] "
                    f"{'UDP':8s} {sport:5d}→{dport:<5d} | "
                    f"{CYAN(src_ip)} → {CYAN(dst_ip)} | "
                    f"len={pkt_len}")
        print(line)
        _log(line)
        return

    # ── Other ─────────────────────────────────────────
    stats["other"] += 1

# ── Logging helper ────────────────────────────────────
def _log(line):
    if log_file:
        # Strip ANSI codes before writing to file
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        log_file.write(clean + "\n")
        log_file.flush()

# ── Statistics banner ─────────────────────────────────
def print_stats():
    elapsed = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)
    print()
    print(CYAN("=" * 55))
    print(BOLD("  CAPTURE SUMMARY"))
    print(CYAN("=" * 55))
    print(f"  Duration   : {mins}m {secs}s")
    print(f"  Total pkts : {stats['total']}")
    print(f"  Total bytes: {stats['bytes']:,}")
    print()
    print(f"  TCP   : {stats['tcp']:>5}   (HTTP: {stats['http']})")
    print(f"  UDP   : {stats['udp']:>5}   (DNS : {stats['dns']})")
    print(f"  ICMP  : {stats['icmp']:>5}")
    print(f"  ARP   : {stats['arp']:>5}")
    print(f"  Other : {stats['other']:>5}")
    print()

    # Top talkers
    if ip_counter:
        print(BOLD("  Top 5 Source IPs:"))
        for ip, cnt in sorted(ip_counter.items(),
                               key=lambda x: x[1], reverse=True)[:5]:
            bar = "█" * min(cnt, 30)
            print(f"    {CYAN(ip):40s} {cnt:>4}  {GREEN(bar)}")
    print(CYAN("=" * 55))

# ── Signal handler (Ctrl+C) ───────────────────────────
def handle_exit(sig, frame):
    print(RED("\n\n  [!] Capture stopped by user."))
    print_stats()
    if log_file:
        log_file.close()
        print(f"  [+] Log saved.")
    sys.exit(0)

# ── Interface lister ──────────────────────────────────
def list_interfaces():
    print(BOLD("\nAvailable network interfaces:"))
    for i, iface in enumerate(get_if_list(), 1):
        print(f"  {i:2}. {iface}")
    print()

# ── Argument parser ───────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        description="CodeAlpha Network Sniffer – Task 1",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-i", "--iface",
                   help="Network interface to sniff (default: auto-detect)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="Number of packets to capture (0 = unlimited)")
    p.add_argument("-f", "--filter", default="",
                   help='BPF filter string (e.g. "tcp port 80")')
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show packet payload previews")
    p.add_argument("-o", "--output",
                   help="Save output to a log file")
    p.add_argument("-l", "--list", action="store_true",
                   help="List available interfaces and exit")
    p.add_argument("--proto",
                   choices=["tcp", "udp", "icmp", "arp", "dns", "http"],
                   help="Capture only specific protocol")
    return p

# ── Entry point ───────────────────────────────────────
def main():
    global start_time, log_file

    parser = build_parser()
    args   = parser.parse_args()

    print_banner()

    if args.list:
        list_interfaces()
        sys.exit(0)

    # Root check
    if os.geteuid() != 0:
        print(RED("  [!] Root privileges required.  Run with sudo."))
        sys.exit(1)

    # Open log file
    if args.output:
        try:
            log_file = open(args.output, "w")
            print(GREEN(f"  [+] Logging to: {args.output}"))
        except IOError as e:
            print(RED(f"  [!] Cannot open log file: {e}"))
            sys.exit(1)

    # Build BPF filter
    bpf = args.filter
    if args.proto and not bpf:
        proto_filters = {
            "tcp": "tcp", "udp": "udp", "icmp": "icmp",
            "arp": "arp", "dns": "udp port 53",
            "http": "tcp port 80 or tcp port 8080"
        }
        bpf = proto_filters.get(args.proto, "")

    iface = args.iface or None
    count = args.count

    print(BOLD(f"  Interface : ") + (iface or "auto-detect"))
    print(BOLD(f"  Filter    : ") + (bpf or "none"))
    print(BOLD(f"  Count     : ") + (str(count) if count else "unlimited"))
    print(BOLD(f"  Verbose   : ") + str(args.verbose))
    print()
    print(YELLOW("  Press Ctrl+C to stop and view summary.\n"))
    print(CYAN("-" * 55))

    # Register SIGINT handler
    signal.signal(signal.SIGINT, handle_exit)
    start_time = time.time()

    # Wrapper so verbose flag is accessible inside handler
    def handler(pkt):
        packet_handler(pkt, verbose=args.verbose)

    # Start sniffing
    sniff_kwargs = {
        "prn":   handler,
        "store": False,
    }
    if iface:
        sniff_kwargs["iface"] = iface
    if bpf:
        sniff_kwargs["filter"] = bpf
    if count:
        sniff_kwargs["count"] = count

    sniff(**sniff_kwargs)

    # Reached only if count was specified
    print_stats()
    if log_file:
        log_file.close()

if __name__ == "__main__":
    main()
