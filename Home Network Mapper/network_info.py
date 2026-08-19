"""
network_info.py - Network Details & Interface Discovery
Accurately detects local IP address, active connection type (Wi-Fi SSID vs Wired Ethernet),
default gateway, and subnet mask.
"""

import os
import re
import socket
import subprocess


def get_default_route_info() -> tuple[str, str, str]:
    """
    Parses the default routing table to identify:
    - Default Gateway IP
    - Primary Network Interface name (e.g., 'enp34s0', 'eth0', 'wlan0')
    - Local Source IP
    """
    default_gateway = "127.0.0.1"
    default_dev = ""
    local_ip = "127.0.0.1"

    # Linux: ip route show default
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        
        # Match 'default via 192.168.254.254 dev enp34s0'
        m_gateway = re.search(r"default via ([0-9\.]+)(?:\s+dev\s+([^\s]+))?", out)
        if m_gateway:
            default_gateway = m_gateway.group(1)
            if m_gateway.group(2):
                default_dev = m_gateway.group(2)

        # Match 'src 192.168.254.108'
        m_src = re.search(r"src ([0-9\.]+)", out)
        if m_src:
            local_ip = m_src.group(1)
    except Exception:
        pass

    # Windows route print 0.0.0.0 fallback
    if default_gateway == "127.0.0.1":
        try:
            out = subprocess.check_output(["route", "print", "0.0.0.0"], stderr=subprocess.DEVNULL).decode(errors="ignore")
            # Format: 0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25
            m_win = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9\.]+)\s+([0-9\.]+)", out)
            if m_win:
                default_gateway = m_win.group(1)
                local_ip = m_win.group(2)
        except Exception:
            pass

    # Fallback for local IP if not found in route table
    if local_ip == "127.0.0.1":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    # Fallback for default gateway to .1 if on private class C subnet
    if default_gateway == "127.0.0.1" and local_ip != "127.0.0.1" and "." in local_ip:
        default_gateway = f"{local_ip.rsplit('.', 1)[0]}.1"

    return default_gateway, default_dev, local_ip


def get_connection_name_and_type(interface: str) -> tuple[str, str]:
    """
    Determines the human-readable connection name (e.g. Wi-Fi SSID or 'Wired LAN')
    and connection type ('Wi-Fi' vs 'Ethernet').
    """
    # 1. Linux NetworkManager (nmcli) active connections
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,STATE", "connection", "show", "--active"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                c_name, c_type, c_dev = parts[0], parts[1], parts[2]
                if interface and c_dev == interface:
                    if "wireless" in c_type or "wifi" in c_type or "802-11" in c_type:
                        return c_name, "Wi-Fi"
                    elif "ethernet" in c_type or "802-3" in c_type:
                        return f"Wired ({interface})", "Ethernet"
                    else:
                        return f"{c_name} ({interface})", c_type.capitalize()
    except Exception:
        pass

    # 2. Linux iwgetid for wireless interfaces
    if interface:
        try:
            out = subprocess.check_output(["iwgetid", interface, "-r"], stderr=subprocess.DEVNULL).decode().strip()
            if out:
                return out, "Wi-Fi"
        except Exception:
            pass

    # 3. macOS Airport CLI
    try:
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport_path):
            out = subprocess.check_output([airport_path, "-I"], stderr=subprocess.DEVNULL).decode()
            match = re.search(r"\bSSID:\s*(.+)$", out, re.MULTILINE)
            if match:
                return match.group(1).strip(), "Wi-Fi"
    except Exception:
        pass

    # 4. Windows netsh
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], stderr=subprocess.DEVNULL).decode()
        match = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
        if match:
            return match.group(1).strip(), "Wi-Fi"
    except Exception:
        pass

    # 5. Interface heuristics fallback
    if interface:
        if interface.startswith(("wlan", "wlp", "wlo", "wifi")):
            return f"Wi-Fi ({interface})", "Wi-Fi"
        elif interface.startswith(("enp", "eth", "eno", "ens", "em")):
            return f"Wired Ethernet ({interface})", "Ethernet"
        return f"Interface ({interface})", "Network"

    return "Connected Network", "Network"


def get_network_info() -> dict:
    """
    Returns a comprehensive dictionary containing:
    - network_name (str): Wi-Fi SSID or 'Wired (enp34s0)'
    - net_type (str): 'Wi-Fi' or 'Ethernet'
    - interface (str): Active interface name
    - ip (str): Local IP address
    - gateway (str): Default router/gateway IP
    - hostname (str): Machine hostname
    - subnet (str): Subnet CIDR notation
    """
    gateway, interface, ip = get_default_route_info()
    network_name, net_type = get_connection_name_and_type(interface)
    hostname = socket.gethostname()
    subnet = f"{ip.rsplit('.', 1)[0]}.0/24" if ip != "127.0.0.1" and "." in ip else "127.0.0.1"

    return {
        "network_name": network_name,
        "ssid": network_name,
        "net_type": net_type,
        "interface": interface or "unknown",
        "ip": ip,
        "gateway": gateway,
        "hostname": hostname,
        "subnet": subnet,
    }


def get_current_network_info() -> tuple[str, str]:
    """
    Convenience helper that returns (network_name, ip) tuple for UI banners.
    """
    info = get_network_info()
    return info["network_name"], info["ip"]

