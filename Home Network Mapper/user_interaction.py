#!/usr/bin/env python3

"""
Home Network Mapper - User Interaction Module
Interactive arrow-key navigated menu system using ui.py for modern Unicode styling.
"""

import os
import sys
import time
import datetime
import socket
import subprocess

# Ensure the local directory is in Python path for importing sibling modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import ui
import scan_network
import parser
import storage
import differ
import network_info
# Platform-dependent key reading setup
try:
    import termios
    import tty
    import select
    IS_WINDOWS = False
except ImportError:
    try:
        import msvcrt
        IS_WINDOWS = True
    except ImportError:
        IS_WINDOWS = False


## ─────────────────────────────────────────────────────────────────────────────
## System Architecture & Menu Hierarchy:
## 
##           Startup: greet user, show current wifi name + IP (network_info.py)
##   └── Main menu — choices:
##        ├── Scan Networks (scan_network.py + parser.py)
##        │   ├── Run nmap scan
##        │   └── Display results
##        │              └── Plain text view -> saves to file
##        │                  └── then parses to Table view
##        │
##        ├── Logs — automated (storage.py + differ.py)
##        │     └── Alert on unknown device
##        │
##        ├── List of Devices (storage.py)
##        │     ├── Headers: Device name | IP address | MAC address | First seen | Last seen | Status
##        │     └── Select a device -> rename
##        │
##        └── Exit or Run in background
##      └── esc — return to main menu, clear screen
## ─────────────────────────────────────────────────────────────────────────────


def clear_screen():
    """Clears the terminal screen smoothly."""
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()


def hide_cursor():
    """Hides the terminal cursor during menu navigation."""
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()


def show_cursor():
    """Restores the terminal cursor."""
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def get_key() -> str:
    """
    Reads a single keypress from standard input without requiring Enter.
    Recognizes UP, DOWN, LEFT, RIGHT, ENTER, ESC, and standard alphanumeric characters.
    """
    if not sys.stdin.isatty():
        # Fallback for non-interactive / piped environments
        line = sys.stdin.readline()
        return line.strip() if line else "ESC"

    if IS_WINDOWS:
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            ch2 = msvcrt.getch()
            key_map = {b"H": "UP", b"P": "DOWN", b"K": "LEFT", b"M": "RIGHT"}
            return key_map.get(ch2, "SPECIAL")
        elif ch in (b"\r", b"\n"):
            return "ENTER"
        elif ch == b"\x1b":
            return "ESC"
        elif ch == b"\x03":
            raise KeyboardInterrupt
        try:
            return ch.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return ""

    # POSIX (Linux, macOS)
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            # Check if this is an escape sequence (arrow keys, etc.)
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                seq = os.read(fd, 16)
                if seq in (b"[A", b"OA") or (seq.startswith(b"[") and seq.endswith(b"A")):
                    return "UP"
                elif seq in (b"[B", b"OB") or (seq.startswith(b"[") and seq.endswith(b"B")):
                    return "DOWN"
                elif seq in (b"[C", b"OC") or (seq.startswith(b"[") and seq.endswith(b"C")):
                    return "RIGHT"
                elif seq in (b"[D", b"OD") or (seq.startswith(b"[") and seq.endswith(b"D")):
                    return "LEFT"
                return "ESC"
            else:
                return "ESC"
        elif ch in (b"\r", b"\n"):
            return "ENTER"
        elif ch == b"\x03":
            raise KeyboardInterrupt
        return ch.decode("utf-8", errors="ignore")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def render_interactive_menu(
    title: str,
    choices: list[tuple[str, str]],
    highlight_idx: int,
    color: str = "cyan",
    show_nav_help: bool = True
):
    """
    Renders an interactive menu box styled with Unicode borders and colors from ui.py.
    The currently highlighted choice is rendered with high-contrast reverse video.
    """
    c = ui.get_color(color)
    reset = ui.RESET
    bold = ui.BOLD
    dim = ui.DIM

    # Calculate layout widths
    max_label_len = max(len(ui.strip_ansi(text)) for text, _ in choices)
    max_desc_len = max(len(ui.strip_ansi(desc)) for _, desc in choices) if any(d for _, d in choices) else 0

    col1_width = max_label_len + 8  # Space for pointer '▶ ' + '[x] ' + label
    box_inner_width = max(len(title) + 6, col1_width + max_desc_len + 4, 62)

    border_fill = "─" * (box_inner_width - len(title) - 5)
    print(f"\n{c}╭── {bold}{title}{reset} {c}{border_fill}╮{reset}")
    empty_line = " " * box_inner_width
    print(f"{c}│{empty_line}│{reset}")

    for i, (text, desc) in enumerate(choices):
        is_selected = (i == highlight_idx)
        pointer = "▶ " if is_selected else "  "
        num = f"[{i + 1}] "

        label_col = f"{pointer}{num}{text}".ljust(col1_width)
        desc_col = desc if desc else ""
        row_plain = f"  {label_col}{desc_col}"
        pad_len = max(0, box_inner_width - len(row_plain))
        padded_row = f"{row_plain}{' ' * pad_len}"

        if is_selected:
            # Highlight with reverse video styling
            styled_content = f"\033[7m\033[1m{padded_row}\033[0m"
            print(f"{c}│{reset}{styled_content}{c}│{reset}")
        else:
            dim_desc_row = f"  {label_col}{dim}{desc_col}{reset}{' ' * pad_len}"
            print(f"{c}│{reset}{dim_desc_row}{c}│{reset}")

    print(f"{c}│{empty_line}│{reset}")
    print(f"{c}╰{'─' * box_inner_width}╯{reset}")

    if show_nav_help:
        print(f"  {dim}[↑/↓] Navigate  •  [ENTER] Select  •  [ESC/q] Back/Exit{reset}\n")


def prompt_menu_choice(
    menu_title: str,
    choices: list[tuple[str, str]],
    header_banner_title: str = "HOME NETWORK MAPPER",
    header_banner_lines: list[str] | None = None,
    color: str = "cyan"
) -> int:
    """
    Runs the interactive menu loop with UP/DOWN arrow keys and Enter to select.
    Returns the selected 0-based index, or -1 if ESC/q is pressed.
    """
    highlight = 0
    n_choices = len(choices)

    hide_cursor()
    try:
        while True:
            clear_screen()

            # Render top banner using ui.py
            if header_banner_lines is not None:
                ui.print_banner(
                    header_banner_title,
                    header_banner_lines,
                    color=color,
                    align="left"
                )

            # Render the interactive menu box
            render_interactive_menu(menu_title, choices, highlight, color=color)

            key = get_key()

            if key in ("UP", "k", "w"):
                highlight = (highlight - 1) % n_choices
            elif key in ("DOWN", "j", "s"):
                highlight = (highlight + 1) % n_choices
            elif key == "ENTER":
                return highlight
            elif key in ("ESC", "q", "Q"):
                return -1
            elif key.isdigit():
                num_val = int(key)
                if 1 <= num_val <= n_choices:
                    highlight = num_val - 1
                    return highlight
    finally:
        show_cursor()


def wait_for_key():
    """Waits for the user to press ENTER or ESC to return."""
    print(f"{ui.DIM}Press [ENTER] or [ESC] to return...{ui.RESET}")
    while True:
        key = get_key()
        if key in ("ENTER", "ESC", "q", "Q", " "):
            break


# ─────────────────────────────────────────────────────────────────────────────
# Sub-Menu Screens & Placeholder Actions
# ─────────────────────────────────────────────────────────────────────────────

def screen_scan_networks(network_name: str, ip_addr: str):
    """Sub-menu for scanning networks and viewing scan results."""
    subnet = scan_network.derive_subnet(ip_addr)

    scan_choices = [
        ("Run Nmap Scan", "Execute discovery scan on local subnet"),
        ("Display Results (Table)", "Parse and display active hosts in table format"),
        ("Display Results (Plain Text)", "View raw nmap scan text file"),
        ("Back to Main Menu", "Return to previous screen"),
    ]

    banner_lines = [
        "Network Scanner & Host Discovery",
        f"Active Subnet: {subnet}",
    ]

    while True:
        choice = prompt_menu_choice(
            "Scan Networks Menu",
            scan_choices,
            header_banner_title="NETWORK SCANNER",
            header_banner_lines=banner_lines,
            color="green",
        )

        if choice in (-1, 3):  # ESC or "Back to Main Menu"
            break

        elif choice == 0:
            if not scan_network.is_nmap_installed():
                clear_screen()
                ui.print_banner(
                    "NMAP NOT INSTALLED",
                    scan_network.get_nmap_install_instructions(),
                    color="red"
                )
                wait_for_key()
                continue

            clear_screen()
            ui.print_banner(
                "NMAP SCANNER",
                [f"Target Subnet: {subnet}", "Performing host discovery ping scan..."],
                color="green",
            )
            print()

            with ui.Spinner(f"Scanning subnet {subnet} (discovering active hosts)...", color="green") as spinner:
                success, output = scan_network.run_nmap_scan(subnet)
                if success:
                    hosts = parser.parse_nmap_output(output)
                    diff_res = differ.analyze_and_update_state(hosts)
                    storage.record_scan(subnet, len(hosts), output)
                    spinner.stop(f"Scan complete! Discovered {len(hosts)} active host(s).", color="green")
                else:
                    spinner.stop("Scan encountered an error.", color="red")

            if success:
                new_dev_count = len(diff_res["new_devices"])
                new_dev_label = f"{new_dev_count} new" if new_dev_count == 0 else f"{ui.COLORS['yellow']}{new_dev_count} UNKNOWN (Alert!){ui.RESET}"
                ui.print_result_box(
                    "Scan Summary",
                    [
                        ("Status", f"{ui.COLORS['green']}Completed Successfully{ui.RESET}"),
                        ("Target Subnet", subnet),
                        ("Active Hosts", f"{len(hosts)} discovered"),
                        ("New Devices", new_dev_label),
                        ("Database", "state/network.db (SQLite)"),
                        ("Raw Output", "logs/last_scan.txt"),
                    ],
                    color="green",
                )
            else:
                ui.print_result_box(
                    "Scan Failed",
                    [
                        ("Status", f"{ui.COLORS['red']}Error{ui.RESET}"),
                        ("Error Info", output[:45]),
                    ],
                    color="red",
                )
            wait_for_key()

        elif choice == 1:
            clear_screen()
            raw_data = scan_network.read_last_scan_raw()
            hosts = parser.parse_nmap_output(raw_data)

            ui.print_banner(
                "SCAN RESULTS - TABLE VIEW",
                [f"Subnet: {subnet}", f"Discovered Active Devices: {len(hosts)}"],
                color="green",
            )

            if not hosts:
                print(f"\n{ui.COLORS['yellow']}[!] No parsed host records found. Run a scan first.{ui.RESET}\n")
            else:
                header = f"{'IP Address'.ljust(18)} {'MAC Address'.ljust(20)} {'Hostname'.ljust(22)} {'Latency'.ljust(12)} Status"
                print(f"\n{ui.BOLD}{header}{ui.RESET}")
                print("─" * len(header))
                for h in hosts:
                    status_col = f"{ui.COLORS['green']}{h['status']}{ui.RESET}" if h['status'] == "Online" else h['status']
                    print(f"{h['ip'].ljust(18)} {h['mac'].ljust(20)} {h['hostname'].ljust(22)} {h['latency'].ljust(12)} {status_col}")
                print()
            wait_for_key()

        elif choice == 2:
            clear_screen()
            raw_data = scan_network.read_last_scan_raw()
            ui.print_banner("SCAN RESULTS - PLAIN TEXT", ["Raw Nmap Scan Output (logs/last_scan.txt)"], color="green")
            print(f"{ui.DIM}{raw_data}{ui.RESET}\n")
            wait_for_key()


def run_background_monitor(subnet: str):
    """Runs automated continuous network discovery in the background."""
    if not scan_network.is_nmap_installed():
        clear_screen()
        ui.print_banner(
            "NMAP NOT INSTALLED",
            scan_network.get_nmap_install_instructions(),
            color="red"
        )
        wait_for_key()
        return

    clear_screen()
    ui.print_banner(
        "AUTOMATED NETWORK MONITOR",
        [
            f"Active Subnet : {subnet}",
            "Continuously scanning network for unknown / rogue devices.",
            "Desktop notifications are active.",
            "Press [ESC] or [q] to stop monitoring and return to menu."
        ],
        color="yellow"
    )

    scan_iteration = 0
    hide_cursor()
    try:
        while True:
            scan_iteration += 1
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            sys.stdout.write(f"\r  {ui.COLORS['cyan']}⠋{ui.RESET} [{timestamp}] Cycle #{scan_iteration}: Scanning subnet {subnet}...  ")
            sys.stdout.flush()

            success, output = scan_network.run_nmap_scan(subnet)
            if success:
                hosts = parser.parse_nmap_output(output)
                diff_res = differ.analyze_and_update_state(hosts)
                storage.record_scan(subnet, len(hosts), output)

                new_count = len(diff_res["new_devices"])
                if new_count > 0:
                    sys.stdout.write("\r\033[K")
                    print(f"  {ui.COLORS['red']}{ui.BOLD}🚨 [{timestamp}] ALERT: {new_count} UNKNOWN DEVICE(S) DETECTED!{ui.RESET}")
                    for d in diff_res["new_devices"]:
                        print(f"     {ui.COLORS['yellow']}➔ {d['ip']} • MAC: {d['mac']} • {d['vendor']}{ui.RESET}")
                    print()
                else:
                    sys.stdout.write("\r\033[K")
                    print(f"  {ui.COLORS['green']}✔{ui.RESET} [{timestamp}] Cycle #{scan_iteration}: {len(hosts)} active host(s) verified. No rogue devices.")
            else:
                sys.stdout.write("\r\033[K")
                print(f"  {ui.COLORS['red']}[!] [{timestamp}] Scan cycle #{scan_iteration} failed.{ui.RESET}")

            # Non-blocking wait for 15 seconds, listening for ESC or 'q'
            for _ in range(30):
                time.sleep(0.5)
                if IS_WINDOWS:
                    if msvcrt.kbhit():
                        key = get_key()
                        if key in ("ESC", "q", "Q"):
                            return
                else:
                    r, _, _ = select.select([sys.stdin], [], [], 0.0)
                    if r:
                        key = get_key()
                        if key in ("ESC", "q", "Q"):
                            return
    except KeyboardInterrupt:
        pass
    finally:
        show_cursor()
        print(f"\n{ui.DIM}[*] Live network monitor stopped.{ui.RESET}\n")
        wait_for_key()


def screen_logs(network_name: str, ip_addr: str):
    """Sub-menu for automated logs and unknown device alerts."""
    subnet = scan_network.derive_subnet(ip_addr)

    log_choices = [
        ("View Scan History & Logs", "Audit history of recent scans from SQLite & logs"),
        ("Unknown Device Alerts", "Inspect security alerts for newly joined devices"),
        ("Start Live Network Monitor", "Continuous background scanner with desktop alerts"),
        ("Back to Main Menu", "Return to previous screen"),
    ]

    banner_lines = [
        "Network History & Change Detection",
        "Monitors for unauthorized and new devices on your network.",
    ]

    while True:
        choice = prompt_menu_choice(
            "Logs & Alerts Menu",
            log_choices,
            header_banner_title="LOGS & ALERTS",
            header_banner_lines=banner_lines,
            color="yellow"
        )

        if choice in (-1, 3):
            break
        elif choice == 0:
            clear_screen()
            scans = storage.get_recent_scans(limit=8)
            ui.print_banner("SCAN AUDIT HISTORY (SQLite)", [f"Recent Scans Logged: {len(scans)}"], color="yellow")

            if not scans:
                print(f"\n{ui.COLORS['yellow']}[!] No scan history recorded yet in state/network.db.{ui.RESET}\n")
            else:
                header = f"{'ID'.ljust(5)} | {'Timestamp'.ljust(20)} | {'Subnet'.ljust(20)} | Hosts Found"
                print(f"{ui.BOLD}{header}{ui.RESET}")
                print("─" * len(header))
                for s in scans:
                    print(f"{str(s['id']).ljust(5)} | {s['timestamp'].ljust(20)} | {s['subnet'].ljust(20)} | {s['hosts_found']} hosts")
                print()

            # Show last few lines of activity.log
            if os.path.exists(scan_network.ACTIVITY_LOG_PATH):
                print(f"{ui.BOLD}Recent Event Logs (logs/activity.log):{ui.RESET}")
                try:
                    with open(scan_network.ACTIVITY_LOG_PATH, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                        for line in lines[-6:]:
                            print(f"  {ui.DIM}{line.strip()}{ui.RESET}")
                except Exception:
                    pass
                print()
            wait_for_key()

        elif choice == 1:
            clear_screen()
            alerts = storage.get_all_alerts(limit=15)
            ui.print_banner("SECURITY & DIFF ALERTS", [f"Total Recorded Alerts: {len(alerts)}"], color="yellow")

            if not alerts:
                ui.print_result_box("Alert Status", [
                    ("Status", f"{ui.COLORS['green']}All clear - No alerts{ui.RESET}"),
                    ("Unknown Devices", "0"),
                    ("Database", "state/network.db (up-to-date)"),
                ], color="green")
            else:
                header = f"{'Timestamp'.ljust(20)} | {'Type'.ljust(13)} | {'Target IP'.ljust(16)} | Alert Message"
                print(f"{ui.BOLD}{header}{ui.RESET}")
                print("─" * 80)
                for a in alerts:
                    type_color = ui.COLORS['red'] if a['alert_type'] == 'NEW_DEVICE' else ui.COLORS['yellow']
                    type_tag = f"{type_color}{a['alert_type'].ljust(13)}{ui.RESET}"
                    print(f"{a['timestamp'].ljust(20)} | {type_tag} | {a['ip'].ljust(16)} | {a['message']}")
                print()
            wait_for_key()

        elif choice == 2:
            run_background_monitor(subnet)


def screen_device_list(network_name: str, ip_addr: str):
    """Sub-menu for known devices list and renaming."""
    device_choices = [
        ("View Registered Devices", "List all devices stored in SQLite registry"),
        ("Rename a Device", "Assign a custom alias to a recognized MAC or IP"),
        ("Back to Main Menu", "Return to previous screen"),
    ]

    banner_lines = [
        "Device Registry & Identification",
        "Manage known network clients and assign friendly aliases in SQLite.",
    ]

    while True:
        choice = prompt_menu_choice(
            "Device Management Menu",
            device_choices,
            header_banner_title="DEVICE REGISTRY",
            header_banner_lines=banner_lines,
            color="blue"
        )

        if choice in (-1, 2):
            break
        elif choice == 0:
            clear_screen()
            devices = storage.get_all_devices()
            ui.print_banner("REGISTERED DEVICES (SQLite)", [f"Total Devices in Registry: {len(devices)}"], color="blue")

            if not devices:
                print(f"\n{ui.COLORS['yellow']}[!] No devices stored in database yet. Run a network scan first!{ui.RESET}\n")
            else:
                header = f"{'Alias / Name'.ljust(22)} | {'IP Address'.ljust(16)} | {'MAC Address'.ljust(18)} | {'Vendor'.ljust(28)} | Status"
                print(f"{ui.BOLD}{header}{ui.RESET}")
                print("─" * 100)
                for d in devices:
                    name = d["custom_name"] or d["hostname"] or "Unknown"
                    if d["custom_name"]:
                        status_disp = f"{ui.COLORS['green']}Known (Alias){ui.RESET}"
                    elif d["status"] == "known":
                        status_disp = f"{ui.COLORS['green']}Known{ui.RESET}"
                    else:
                        status_disp = f"{ui.COLORS['yellow']}Unknown (New){ui.RESET}"
                    vendor_disp = (d["vendor"] or "Unknown")[:27]
                    print(f"{name[:21].ljust(22)} | {d['ip'].ljust(16)} | {d['mac'].ljust(18)} | {vendor_disp.ljust(28)} | {status_disp}")
                print()
            wait_for_key()

        elif choice == 1:
            # Interactive device selection list
            devices = storage.get_all_devices()
            if not devices:
                clear_screen()
                ui.print_banner("RENAME DEVICE", ["No devices found in registry. Please run a network scan first!"], color="blue")
                wait_for_key()
                continue

            rename_choices = []
            for d in devices:
                display_label = d["custom_name"] if d["custom_name"] else d["hostname"]
                vendor_short = d["vendor"][:24]
                desc = f"{d['ip']} • {d['mac']} • {vendor_short}"
                rename_choices.append((display_label, desc))
            rename_choices.append(("Back to Device Menu", "Cancel and return"))

            dev_idx = prompt_menu_choice(
                "Select Device to Rename",
                rename_choices,
                header_banner_title="RENAME DEVICE / ASSIGN ALIAS",
                header_banner_lines=[
                    "Use ↑ / ↓ arrow keys to select the device you wish to edit.",
                    "Press [ENTER] to choose, or [ESC] to cancel."
                ],
                color="blue"
            )

            if dev_idx in (-1, len(devices)):  # User pressed ESC or chosen 'Back'
                continue

            selected_device = devices[dev_idx]
            clear_screen()
            show_cursor()
            ui.print_banner(
                "EDIT DEVICE ALIAS",
                [
                    f"Target IP  : {selected_device['ip']}",
                    f"MAC Address: {selected_device['mac']}",
                    f"Vendor     : {selected_device['vendor']}",
                    f"Hostname   : {selected_device['hostname']}",
                    f"Current    : {selected_device['custom_name'] or '(No alias set)'}"
                ],
                color="blue"
            )
            print()
            try:
                new_alias = input(f"{ui.BOLD}Enter new alias name (e.g. 'Living Room TV', 'Huawei Gateway'):{ui.RESET} ").strip()
                if new_alias:
                    storage.rename_device(selected_device["mac"], new_alias)
                    print(f"\n{ui.COLORS['green']}✔ Successfully updated alias to '{new_alias}'! Status marked as Known.{ui.RESET}\n")
                else:
                    print(f"\n{ui.COLORS['yellow']}[!] Rename cancelled (empty alias entered).{ui.RESET}\n")
            except (KeyboardInterrupt, EOFError):
                pass
            hide_cursor()
            wait_for_key()


# ─────────────────────────────────────────────────────────────────────────────
# Main Application Loop
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Main application loop for Home Network Mapper."""
    try:
        net_info = network_info.get_network_info()
        network_name = net_info["ssid"]
        ip_addr = net_info["ip"]
        gateway = net_info["gateway"]

        main_choices = [
            ("Scan Networks", "Run nmap scan & parse results to table view"),
            ("Logs & Alerts", "Automated scan logs & unknown device alerts"),
            ("List of Devices", "Device table (name, IP, MAC) & rename devices"),
            ("Exit", "Exit Home Network Mapper"),
        ]

        while True:
            is_running, daemon_pid = scan_network.is_daemon_running()
            daemon_label = f"{ui.COLORS['green']}Active (PID {daemon_pid}) [Scanning every 30s]{ui.RESET}" if is_running else "Inactive"

            banner_lines = [
                "Scans your network for devices and logs any unknown devices.",
                "",
                f"Network : {network_name} ({net_info['net_type']})",
                f"Your IP : {ip_addr}",
                f"Gateway : {gateway}",
                f"Daemon  : {daemon_label}",
            ]

            choice = prompt_menu_choice(
                "Main Menu",
                main_choices,
                header_banner_title="HOME NETWORK MAPPER",
                header_banner_lines=banner_lines,
                color="cyan"
            )

            if choice in (-1, 3):  # ESC or Exit
                is_running, daemon_pid = scan_network.is_daemon_running()
                exit_choices = [
                    ("Full Exit", "Shut down application completely"),
                ]
                if is_running:
                    exit_choices.append(("Stop Daemon & Exit", f"Terminate background monitor (PID: {daemon_pid})"))
                    exit_choices.append(("Leave Daemon Running & Exit", f"Keep monitor running in background (PID: {daemon_pid})"))
                else:
                    exit_choices.append(("Run in Background & Exit", "Detach background scanner (~15MB RAM) with desktop alerts"))
                exit_choices.append(("Cancel", "Return to Main Menu"))

                exit_choice = prompt_menu_choice(
                    "Exit Application",
                    exit_choices,
                    header_banner_title="EXIT / BACKGROUND DAEMON",
                    header_banner_lines=[
                        "Choose how you want to exit:",
                        f"Daemon status: {'Active [PID ' + str(daemon_pid) + ']' if is_running else 'Inactive'}"
                    ],
                    color="cyan"
                )

                if exit_choice in (-1, len(exit_choices) - 1):  # Cancel / ESC
                    continue
                elif exit_choice == 0:  # Full Exit
                    if is_running:
                        scan_network.stop_background_daemon()
                    clear_screen()
                    ui.print_banner(
                        "HOME NETWORK MAPPER",
                        ["Application closed. Thank you for using Home Network Mapper!"],
                        color="cyan",
                        align="center"
                    )
                    break
                elif exit_choice == 1 and not is_running:  # Start Daemon & Exit
                    clear_screen()
                    subnet = scan_network.derive_subnet(ip_addr)
                    ok, pid, msg = scan_network.start_background_daemon(subnet, interval_seconds=30)
                    if ok:
                        ui.print_banner(
                            "BACKGROUND MONITOR ACTIVATED",
                            [
                                f"Monitoring Subnet : {subnet}",
                                f"Process ID (PID)  : {pid}",
                                "RAM Footprint     : ~15 MB (ultra-lightweight)",
                                "Desktop Popups    : Active via notify-send",
                                "",
                                f"To stop daemon: Re-open app or run 'kill {pid}'"
                            ],
                            color="green"
                        )
                    else:
                        print(f"\n{ui.COLORS['red']}[!] {msg}{ui.RESET}\n")
                    break
                elif exit_choice == 1 and is_running:  # Stop Daemon & Exit
                    scan_network.stop_background_daemon()
                    clear_screen()
                    ui.print_banner("HOME NETWORK MAPPER", ["Daemon stopped. Application closed."], color="cyan", align="center")
                    break
                elif exit_choice == 2 and is_running:  # Leave Daemon Running & Exit
                    clear_screen()
                    ui.print_banner("HOME NETWORK MAPPER", [f"Daemon left active (PID: {daemon_pid}). Application closed."], color="cyan", align="center")
                    break
            elif choice == 0:
                screen_scan_networks(network_name, ip_addr)
            elif choice == 1:
                screen_logs(network_name, ip_addr)
            elif choice == 2:
                screen_device_list(network_name, ip_addr)

    except KeyboardInterrupt:
        clear_screen()
        print(f"\n{ui.COLORS['yellow']}Exiting Home Network Mapper... Goodbye!{ui.RESET}\n")
    finally:
        show_cursor()


if __name__ == "__main__":
    main()

