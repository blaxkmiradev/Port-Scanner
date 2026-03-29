#!/usr/bin/env python3
"""
██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
        
"""

import socket
import random
import sys
import time
import argparse
import concurrent.futures
from datetime import datetime


# ─── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    @staticmethod
    def strip():
        """Disable colors (for file output or non-TTY)."""
        for attr in ['RESET','BOLD','DIM','GREEN','RED','YELLOW',
                     'CYAN','MAGENTA','WHITE','GRAY']:
            setattr(C, attr, '')


# ─── Service fingerprints ──────────────────────────────────────────────────────
KNOWN_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP-client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "MS-RPC", 137: "NetBIOS-ns", 138: "NetBIOS-dgm",
    139: "NetBIOS-ssn", 143: "IMAP", 161: "SNMP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP-submit", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2181: "Zookeeper", 3000: "Dev-server", 3306: "MySQL",
    3389: "RDP", 4369: "Erlang", 5432: "PostgreSQL", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "K8s-API", 6881: "BitTorrent",
    7001: "WebLogic", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "Jupyter", 9200: "Elasticsearch", 9300: "Elasticsearch-cluster",
    27017: "MongoDB",
}

# ─── Severity tiers ───────────────────────────────────────────────────────────
RISKY_PORTS    = {21, 23, 135, 137, 138, 139, 445, 1433, 3389, 5900}
ELEVATED_PORTS = {22, 25, 110, 143, 3306, 5432, 6379, 27017}


def get_service(port: int) -> str:
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def risk_label(port: int) -> tuple[str, str]:
    """Returns (color, label) based on port risk."""
    if port in RISKY_PORTS:
        return C.RED, "HIGH-RISK"
    if port in ELEVATED_PORTS:
        return C.YELLOW, "ELEVATED"
    return C.GREEN, "INFO"


def probe_banner(host: str, port: int, timeout: float) -> str:
    """Attempt to grab a banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(1.5)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(128).decode(errors="replace").strip()
            first_line = data.splitlines()[0] if data else ""
            return first_line[:60] if first_line else ""
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float, grab_banner: bool) -> dict | None:
    """Attempt a TCP connection. Returns result dict if open, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = get_service(port)
            banner  = probe_banner(host, port, timeout) if grab_banner else ""
            color, risk = risk_label(port)
            return {
                "port": port,
                "service": service,
                "risk": risk,
                "risk_color": color,
                "banner": banner,
            }
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None


def resolve_target(target: str) -> str:
    """Resolve hostname → IP, with friendly error."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"\n{C.RED}[✗] Cannot resolve '{target}'. Check the address.{C.RESET}")
        sys.exit(1)


def print_banner(target: str, ip: str, port_range: tuple, workers: int, timeout: float):
    width = 62
    now   = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    print(f"\n{C.CYAN}{'─' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  PORT SCAN  {C.RESET}{C.GRAY}— {now}{C.RESET}")
    print(f"{C.CYAN}{'─' * width}{C.RESET}")
    print(f"  {C.WHITE}Target   {C.RESET}: {C.YELLOW}{target}{C.RESET}  {C.GRAY}({ip}){C.RESET}")
    print(f"  {C.WHITE}Range    {C.RESET}: {C.CYAN}{port_range[0]}–{port_range[1]}{C.RESET}  "
          f"{C.GRAY}({port_range[1]-port_range[0]+1} ports, randomized){C.RESET}")
    print(f"  {C.WHITE}Threads  {C.RESET}: {C.CYAN}{workers}{C.RESET}")
    print(f"  {C.WHITE}Timeout  {C.RESET}: {C.CYAN}{timeout}s{C.RESET}")
    print(f"{C.CYAN}{'─' * width}{C.RESET}\n")


def print_result(r: dict, verbose: bool):
    color      = r["risk_color"]
    risk_tag   = f"[{r['risk']:<9}]"
    svc_tag    = f"{r['service']:<18}"
    banner_txt = f"  {C.DIM}{C.GRAY}↳ {r['banner']}{C.RESET}" if r["banner"] else ""
    port_str   = f"{r['port']:<6}"

    print(f"  {color}{C.BOLD}{risk_tag}{C.RESET}  "
          f"{C.WHITE}:{port_str}{C.RESET}  "
          f"{C.CYAN}{svc_tag}{C.RESET}"
          f"{banner_txt}")


def print_summary(open_ports: list, elapsed: float, total: int):
    width = 62
    print(f"\n{C.CYAN}{'─' * width}{C.RESET}")
    print(f"  {C.BOLD}SCAN COMPLETE{C.RESET}  "
          f"{C.GRAY}in {elapsed:.1f}s  |  {total} ports checked{C.RESET}")

    if not open_ports:
        print(f"  {C.DIM}No open ports found.{C.RESET}")
    else:
        risky = [r for r in open_ports if r["risk"] == "HIGH-RISK"]
        elev  = [r for r in open_ports if r["risk"] == "ELEVATED"]
        info  = [r for r in open_ports if r["risk"] == "INFO"]

        print(f"  {C.GREEN}Open ports  : {len(open_ports)}{C.RESET}")
        if risky: print(f"  {C.RED}High-risk   : {len(risky)}  "
                        f"{C.GRAY}ports {', '.join(str(r['port']) for r in risky)}{C.RESET}")
        if elev:  print(f"  {C.YELLOW}Elevated    : {len(elev)}{C.RESET}")
        if info:  print(f"  {C.GREEN}Info        : {len(info)}{C.RESET}")

    print(f"{C.CYAN}{'─' * width}{C.RESET}\n")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Random Port Scanner v2 — scan random ports on a target",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",         nargs="?",          help="Target IP or hostname")
    parser.add_argument("-s", "--start",  type=int, default=1,    help="Port range start (default: 1)")
    parser.add_argument("-e", "--end",    type=int, default=9999,  help="Port range end   (default: 9999)")
    parser.add_argument("-w", "--workers",type=int, default=150,   help="Concurrent threads (default: 150)")
    parser.add_argument("-t", "--timeout",type=float,default=0.8,  help="Timeout per port  (default: 0.8s)")
    parser.add_argument("-b", "--banner", action="store_true",     help="Grab service banners")
    parser.add_argument("--no-color",     action="store_true",     help="Disable ANSI colors")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.strip()

    print(__doc__)

    target = args.target or input(f"{C.CYAN}Enter target (IP/domain): {C.RESET}").strip()
    if not target:
        print(f"{C.RED}No target provided.{C.RESET}")
        sys.exit(1)

    ip = resolve_target(target)
    ports = list(range(args.start, args.end + 1))
    random.shuffle(ports)

    print_banner(target, ip, (args.start, args.end), args.workers, args.timeout)
    print(f"  {C.GRAY}Scanning...{C.RESET}\n")

    open_ports: list[dict] = []
    start_time = time.time()
    scanned    = 0

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(scan_port, ip, p, args.timeout, args.banner): p
                for p in ports
            }
            for future in concurrent.futures.as_completed(futures):
                scanned += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                    print_result(result, verbose=True)

                # Progress bar every 500 ports
                if scanned % 500 == 0:
                    pct = scanned / len(ports) * 100
                    bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                    print(f"  {C.GRAY}[{bar}] {pct:.0f}%  ({scanned}/{len(ports)}){C.RESET}",
                          end="\r", flush=True)

    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}  [!] Scan interrupted by user.{C.RESET}")

    elapsed = time.time() - start_time
    open_ports.sort(key=lambda r: r["port"])
    print_summary(open_ports, elapsed, scanned)

    if open_ports:
        save = input(f"  {C.CYAN}Save results to file? [y/N]: {C.RESET}").strip().lower()
        if save == "y":
            fname = f"scan_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w") as f:
                f.write(f"Port Scan Results — {target} ({ip})\n")
                f.write(f"Scanned: {scanned} ports  |  Open: {len(open_ports)}\n")
                f.write("=" * 50 + "\n")
                for r in open_ports:
                    f.write(f"[{r['risk']:<9}]  :{r['port']:<6}  {r['service']}")
                    if r["banner"]:
                        f.write(f"  ↳ {r['banner']}")
                    f.write("\n")
            print(f"  {C.GREEN}[✓] Saved to {fname}{C.RESET}\n")


if __name__ == "__main__":
    main()
