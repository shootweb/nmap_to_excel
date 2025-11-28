#!/usr/bin/env python3
"""
nmap_to_xlsx.py

Convert an Nmap normal text output (with multiple hosts) into an XLSX file.

Output columns:
1) IP
2) Port
3) Service and version (if any)

Usage:
    python nmap_to_xlsx.py input_nmap_output.txt output.xlsx
"""

import sys
import re
from pathlib import Path

try:
    import openpyxl
    from openpyxl import Workbook
except ImportError:
    print("[-] The 'openpyxl' package is required. Install it with:")
    print("    pip install openpyxl")
    sys.exit(1)


def parse_nmap_output(text: str):
    """
    Parse Nmap normal text output and yield tuples: (ip, port, service_version)

    We look for blocks like:
        Nmap scan report for 192.168.1.10
        ...
        PORT     STATE  SERVICE VERSION
        22/tcp   open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
        80/tcp   open   http    Apache httpd 2.4.41 ((Ubuntu))

    IP is taken from the "Nmap scan report for" line.
    Ports are taken from lines that look like "22/tcp  open  ssh  OpenSSH..."
    """
    results = []

    current_ip = None

    # Regex to capture IP from lines like:
    # Nmap scan report for 192.168.1.1
    # Nmap scan report for example.com (192.168.1.1)
    ip_line_re = re.compile(
        r"^Nmap scan report for (?:[^\(]*\()?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\))?"
    )

    # Regex for port lines, e.g.:
    # 22/tcp  open   ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
    port_line_re = re.compile(r"^(?P<port>\d+/(tcp|udp|sctp))\s+(?P<state>\S+)\s+(?P<rest>.+)$")

    for line in text.splitlines():
        line = line.rstrip("\n")

        # Detect new host
        m_ip = ip_line_re.match(line)
        if m_ip:
            current_ip = m_ip.group("ip")
            continue

        # Skip until we know what host we are in
        if current_ip is None:
            continue

        # Skip header lines like "PORT STATE SERVICE VERSION"
        if line.strip().startswith("PORT "):
            continue

        # Try matching a port line
        m_port = port_line_re.match(line)
        if not m_port:
            continue

        port_proto = m_port.group("port")      # e.g. "22/tcp"
        state = m_port.group("state")          # e.g. "open"
        rest = m_port.group("rest")            # e.g. "ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.2"

        # You can choose to filter by state here.
        # Typically we only care about "open" ports.
        # If you want to include everything, comment this out.
        if state.lower() == "closed":
            continue

        # Split "rest" into service + optional version
        # At minimum, rest will start with the SERVICE column.
        parts = rest.split()
        if not parts:
            service_version = ""
        else:
            service = parts[0]
            version = " ".join(parts[1:]) if len(parts) > 1 else ""
            service_version = service if not version else f"{service} {version}"

        results.append((current_ip, port_proto, service_version))

    return results


def write_to_xlsx(rows, output_path: Path):
    """
    Write parsed data to an XLSX file with columns:
    IP | Port | Service_Version
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Nmap Results"

    # Header
    ws.append(["IP", "Port", "Service_Version"])

    # Data
    for ip, port, service_version in rows:
        ws.append([ip, port, service_version])

    wb.save(output_path)


def main():
    if len(sys.argv) != 3:
        print("Usage: python nmap_to_xlsx.py <input_nmap_output.txt> <output.xlsx>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"[-] Input file not found: {input_file}")
        sys.exit(1)

    text = input_file.read_text(encoding="utf-8", errors="ignore")
    rows = parse_nmap_output(text)

    if not rows:
        print("[!] No ports found in the Nmap output. Check the input file or script logic.")
    else:
        print(f"[+] Parsed {len(rows)} records from Nmap output.")

    write_to_xlsx(rows, output_file)
    print(f"[+] XLSX file written to: {output_file}")


if __name__ == "__main__":
    main()
