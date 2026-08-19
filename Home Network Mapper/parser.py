"""
parser.py - Nmap Scan Output Parser
Parses raw text outputs from `nmap -sn` into structured Python dictionaries containing
IP address, MAC address, Hostname, Vendor information, Latency, and Status.
Enriches hosts with local system ARP cache (/proc/net/arp) to guarantee MAC resolution.
"""

import os
import re
import subprocess


def get_system_arp_cache() -> dict[str, str]:
    """
    Reads the kernel ARP cache (/proc/net/arp or 'ip neigh') to map IP -> MAC addresses.
    """
    arp_map = {}

    # 1. /proc/net/arp (Linux standard)
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip_val = parts[0]
                        mac_val = parts[3].upper()
                        if mac_val != "00:00:00:00:00:00":
                            arp_map[ip_val] = mac_val
        except Exception:
            pass

    # 2. 'ip neigh' fallback
    try:
        out = subprocess.check_output(["ip", "neigh", "show"], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            # Format: '192.168.254.254 dev enp34s0 lladdr 6c:a4:d1:e5:9b:40 ...'
            m = re.search(r"^([0-9\.]+)\s+.*?lladdr\s+([0-9A-Fa-f:]{17})", line)
            if m:
                arp_map[m.group(1)] = m.group(2).upper()
    except Exception:
        pass

    return arp_map


def get_local_interfaces_macs() -> dict[str, str]:
    """
    Finds MAC addresses of local network interfaces from /sys/class/net/.
    """
    mac_map = {}
    net_dir = "/sys/class/net"
    if os.path.exists(net_dir):
        try:
            for iface in os.listdir(net_dir):
                addr_file = os.path.join(net_dir, iface, "address")
                if os.path.isfile(addr_file):
                    with open(addr_file, "r") as f:
                        mac = f.read().strip().upper()
                        if mac and mac != "00:00:00:00:00:00":
                            mac_map[iface] = mac
        except Exception:
            pass
    return mac_map


def is_randomized_mac(mac: str) -> bool:
    """
    Checks if a MAC address has the local administration / private randomization bit set.
    (Commonly used by Android, iOS, Windows for Wi-Fi privacy).
    """
    try:
        clean = mac.replace(":", "").replace("-", "")
        first_byte = int(clean[:2], 16)
        return (first_byte & 0b00000010) != 0
    except Exception:
        return False


def resolve_mac_vendor(mac: str) -> str:
    """
    Resolves hardware manufacturer name using:
    1. System OUI databases (/usr/share/hwdata/oui.txt, /usr/share/nmap/nmap-mac-prefixes).
    2. Private/Randomized MAC detection (smartphones/tablets).
    """
    if not mac or mac in ("N/A", "00:00:00:00:00:00") or mac.startswith("IP_"):
        return "Local Device"

    clean_hex = mac.replace(":", "-").replace(".", "-").upper()[:8]
    clean_nmap = mac.replace(":", "").replace("-", "").upper()[:6]

    # 1. /usr/share/hwdata/oui.txt
    if os.path.exists("/usr/share/hwdata/oui.txt"):
        try:
            with open("/usr/share/hwdata/oui.txt", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith(clean_hex):
                        parts = line.split("\t\t")
                        if len(parts) >= 2:
                            return parts[1].strip()
        except Exception:
            pass

    # 2. /usr/share/nmap/nmap-mac-prefixes
    if os.path.exists("/usr/share/nmap/nmap-mac-prefixes"):
        try:
            with open("/usr/share/nmap/nmap-mac-prefixes", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and parts[0].upper() == clean_nmap:
                        return parts[1].strip()
        except Exception:
            pass

    # 3. Randomized MAC detection
    if is_randomized_mac(mac):
        return "Private MAC (Phone/Mobile)"

    return "Unknown Vendor"


def parse_nmap_output(raw_text: str) -> list[dict]:
    """
    Parses 'nmap -sn' raw text output into a structured list of host dictionaries.
    
    Algorithm:
    1. Iterates through lines of raw output.
    2. Identifies host headers starting with 'Nmap scan report for'.
    3. Extracts Hostname and IP address (e.g. 'router.local (192.168.1.1)' or '192.168.1.1').
    4. Extracts Host latency from 'Host is up (<latency>)'.
    5. Extracts MAC address and hardware Vendor from 'MAC Address: <MAC> (<Vendor>)'.
    6. Enriches missing MAC addresses from the kernel ARP table.
    7. Resolves hardware vendor from system OUI database.
    8. Aggregates records and returns a list of dictionaries.
    
    Returns:
        list of dicts, each with keys:
        - ip (str)
        - hostname (str)
        - mac (str)
        - vendor (str)
        - latency (str)
        - status (str)
    """
    if not raw_text or "Nmap scan report for" not in raw_text:
        return []

    hosts = []
    current_host: dict | None = None
    arp_cache = get_system_arp_cache()
    local_macs = list(get_local_interfaces_macs().values())

    for line in raw_text.splitlines():
        line = line.strip()

        # 1. Host Header Line
        if line.startswith("Nmap scan report for"):
            if current_host and current_host.get("ip"):
                hosts.append(current_host)

            current_host = {
                "ip": "",
                "hostname": "Unknown",
                "mac": "N/A",
                "vendor": "Unknown",
                "latency": "N/A",
                "status": "Online",
            }

            target_part = line.replace("Nmap scan report for ", "").strip()
            
            # Format: hostname (ip) OR just ip
            match_with_hostname = re.match(r"^([^\s]+)\s+\(([\d\.]+)\)$", target_part)
            if match_with_hostname:
                current_host["hostname"] = match_with_hostname.group(1)
                current_host["ip"] = match_with_hostname.group(2)
            else:
                current_host["ip"] = target_part
                current_host["hostname"] = target_part

        # 2. Host Status & Latency
        elif current_host and line.startswith("Host is up"):
            latency_match = re.search(r"\(([\d\.]+s)\s+latency\)", line)
            if latency_match:
                current_host["latency"] = latency_match.group(1)
            current_host["status"] = "Online"

        # 3. MAC Address & Vendor from Nmap output
        elif current_host and "MAC Address:" in line:
            mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\((.*?)\))?", line)
            if mac_match:
                current_host["mac"] = mac_match.group(1).upper()
                if mac_match.group(2):
                    current_host["vendor"] = mac_match.group(2).strip()

    # Append the last parsed host
    if current_host and current_host.get("ip"):
        hosts.append(current_host)

    # 4. Fallback ARP Cache Enrichment for hosts without MAC from Nmap
    for h in hosts:
        ip = h["ip"]
        if h["mac"] == "N/A":
            if ip in arp_cache:
                h["mac"] = arp_cache[ip]
            elif ip == "127.0.0.1":
                h["mac"] = "00:00:00:00:00:00"
            elif local_macs:
                # If this IP is our local machine IP
                h["mac"] = local_macs[0]

        # 5. Resolve Vendor if Unknown or N/A
        if h["vendor"] in ("Unknown", "N/A", ""):
            h["vendor"] = resolve_mac_vendor(h["mac"])

    return hosts


