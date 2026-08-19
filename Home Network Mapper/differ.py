"""
differ.py - Network State Diff & Alert Engine
Compares active scan results against the SQLite device database to detect:
1. New / Unknown devices.
2. IP address reallocations / changes.
3. Returning devices.
"""

import os
import subprocess
import storage


def send_desktop_notification(title: str, message: str, urgency: str = "critical"):
    """
    Triggers a native Linux/macOS/Windows desktop notification.
    Uses 'notify-send' on Linux, and PowerShell balloon notification on Windows.
    """
    # 1. Linux notify-send
    try:
        res = subprocess.run(
            ["notify-send", "-u", urgency, "-a", "Home Network Mapper", title, message],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            check=False
        )
        if res.returncode == 0:
            return
    except Exception:
        pass

    # 2. Windows PowerShell Toast / Balloon Notification
    if os.name == "nt":
        try:
            safe_msg = message.replace('"', "'").replace("\n", " ")
            safe_title = title.replace('"', "'")
            ps_script = (
                f'[reflection.assembly]::loadwithpartialname("System.Windows.Forms"); '
                f'$n = new-object system.windows.forms.notifyicon; '
                f'$n.icon = [system.drawing.systemicons]::Information; '
                f'$n.visible = $true; '
                f'$n.showballoontip(10, "{safe_title}", "{safe_msg}", [system.windows.forms.tooltipicon]::Info)'
            )
            subprocess.run(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass


def analyze_and_update_state(discovered_hosts: list[dict]) -> dict:
    """
    Compares newly scanned hosts with existing database records.
    Updates the database and creates security alerts for anomalous changes.

    Returns:
        dict with categorized devices:
        {
            "new_devices": [...],
            "ip_changed": [...],
            "known_online": [...],
            "total_scanned": int
        }
    """
    results = {
        "new_devices": [],
        "ip_changed": [],
        "known_online": [],
        "total_scanned": len(discovered_hosts)
    }

    for host in discovered_hosts:
        ip = host.get("ip", "").strip()
        mac = host.get("mac", "N/A").strip().upper()
        hostname = host.get("hostname", "Unknown").strip()
        vendor = host.get("vendor", "Unknown").strip()

        if not ip:
            continue

        # If MAC is missing/unavailable (e.g., localhost), use synthetic key
        device_key = mac if mac != "N/A" else f"IP_{ip}"

        existing = storage.get_device_by_mac(device_key)

        if not existing:
            # Check if this IP previously belonged to another device
            existing_ip_holder = storage.get_device_by_ip(ip)

            # 1. New device detected
            status = "unknown"
            storage.upsert_device(
                mac=device_key,
                ip=ip,
                hostname=hostname,
                vendor=vendor,
                status=status
            )
            alert_msg = f"Unknown device detected: {hostname} ({ip}) [MAC: {mac}] ({vendor})"
            storage.record_alert(mac=device_key, ip=ip, alert_type="NEW_DEVICE", message=alert_msg)
            
            # Send desktop notification
            send_desktop_notification(
                "🚨 Unknown Device Connected!",
                f"IP: {ip} • Host: {hostname}\nMAC: {mac} ({vendor})",
                urgency="critical"
            )

            results["new_devices"].append({
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "message": alert_msg
            })
        else:
            # 2. Existing device re-seen
            old_ip = existing.get("ip", "")
            if old_ip and old_ip != ip:
                dev_label = existing.get("custom_name") or existing.get("hostname") or mac
                alert_msg = f"Device [{dev_label}] changed IP from {old_ip} to {ip}"
                storage.record_alert(mac=device_key, ip=ip, alert_type="IP_CHANGE", message=alert_msg)
                
                # Send desktop notification
                send_desktop_notification(
                    "⚠️ Device IP Changed",
                    f"{dev_label}\nOld IP: {old_ip} ➔ New IP: {ip}",
                    urgency="normal"
                )

                results["ip_changed"].append({
                    "mac": mac,
                    "old_ip": old_ip,
                    "new_ip": ip,
                    "name": dev_label,
                    "message": alert_msg
                })

            storage.upsert_device(
                mac=device_key,
                ip=ip,
                hostname=hostname,
                vendor=vendor
            )
            results["known_online"].append({
                "mac": mac,
                "ip": ip,
                "name": existing.get("custom_name") or hostname,
                "status": existing.get("status", "known")
            })

    return results
