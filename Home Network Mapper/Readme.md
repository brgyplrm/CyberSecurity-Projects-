# [ HNM ] Home Network Mapper

> **An interactive, terminal-driven Network Mapping, Device Registry, and Intrusion Detection Tool** built in Python 3, Nmap, and SQLite.

```
  _  _                     _  _      _                      _     __  __                                  
 | || | ___  _ __   ___   | \| | ___| |_ __ __ __ ___  _ _ | |__ |  \/  | __ _  _ __  _ __  ___  _ _ 
 | __ |/ _ \| '  \ / -_)  | .` |/ -_)|  _|\ V  V // _ \| '_|| / / | |\/| |/ _` || '_ \| '_ \/ -_)| '_|
 |_||_|\___/|_|_|_|\___|  |_|\_|\___| \__| \_/\_/ \___/|_|  |_\_\ |_|  |_|\__,_|| .__/| .__/\___||_|  
                                                                                 |_|   |_|              
```

---

## [01] About The Project

**Home Network Mapper** is a modular, CLI-based cybersecurity tool designed to map local network topologies, discover active clients, identify hardware vendors, detect unknown devices, and alert users of unauthorized connections in real-time.

### [>] The Development Journey & AI Collaboration

This project was built through a **human-in-the-loop, AI-assisted development workflow**—leveraging AI collaboration for algorithmic structuring, regex refinement, and terminal UI design, while driving the implementation with a **deep, hands-on understanding of every syntax, logic block, and low-level protocol**:

* `[+]` **AI-Supported Design & Architecture**: Collaborated with AI as a pair programmer to brainstorm algorithms, design resilient state-machine schemas, optimize regex patterns for Nmap output parsing, and design clean Unicode terminal interfaces.
* `[*]` **Deep Syntax & Logic Mastery**: Thoroughly dissected and mastered the underlying code—understanding why `os.read(fd, 1)` in `cbreak` mode is required over buffered `sys.stdin.read()`, how Layer-2 ARP packet broadcasting works across switches, and how OS signals manage detached daemon lifecycles.
* `[>]` **Systems-Level Linux Programming**: Direct low-level terminal manipulation (`termios`, `tty`, `select`) without relying on heavy third-party UI frameworks.
* `[~]` **Network Discovery Engineering**: Combining unprivileged `nmap -sn` sweeps with Linux kernel ARP table queries (`/proc/net/arp` and `/sys/class/net/`) for complete host visibility.
* `[#]` **Persistent State & Anomaly Detection**: Implementing SQLite database schemas to track device lifecycles, detect IP reallocations, and maintain a known device registry.
* `[!]` **Decoupled Daemonization**: Designing an ultra-lightweight background monitor (~14.6 MB RAM footprint) with native OS desktop alerts (`notify-send`).

---

## [02] Key Features

* `[+]` **Interactive Arrow-Key UI**: Smooth keyboard navigation (`^`/`v`, `[ENTER]`, `[ESC]`), unbuffered escape sequence parsing, and Unicode box-drawing styling.
* `[*]` **Animated Braille Spinner**: Multi-threaded, non-blocking loading spinner providing live visual feedback during network sweeps.
* `[>]` **Smart Interface & Connection Detection**: Automatically distinguishes between **Wired Ethernet** (`enp34s0`) and **Wi-Fi SSID** connections, finding local IP, gateway, and subnet mask.
* `[~]` **Dual-Layer MAC Address Resolution**: Resolves hardware MAC addresses even during unprivileged scans by cross-referencing the Linux kernel ARP cache.
* `[#]` **Hardware Vendor & Private MAC Identification**: Offline IEEE OUI database matching (`oui.txt`, `nmap-mac-prefixes`) and bitwise detection for randomized mobile MACs (iOS/Android).
* `[=]` **SQLite Registry & Interactive Renaming**: Permanent database storage (`state/network.db`) with an interactive device picker to assign friendly aliases (e.g., *"Living Room TV"*).
* `[!]` **Automated Diff Engine & Desktop Alerts**: Compares live scans against database baselines, detecting rogue devices and firing instant native desktop popups via `notify-send`.
* `[$]` **Background Daemon Mode**: Detach the scanner upon exit into a background daemon that continuously protects your network with near-zero resource consumption.

---

## [03] System Architecture & File Structure

```
Home Network Mapper/
|-- user_interaction.py   # Main CLI interface & arrow-key menu controller
|-- ui.py                 # ANSI colors, Unicode box layouts, and animated Spinner
|-- network_info.py       # Gateway, subnet, and interface/SSID discovery
|-- scan_network.py       # Nmap engine, audit logging, & daemon lifecycle management
|-- parser.py             # Regex scan parser, kernel ARP cache, & OUI vendor resolver
|-- storage.py            # SQLite database manager (CRUD, registry, alerts)
|-- differ.py             # State anomaly detector & notify-send alert dispatcher
|-- state/
|   |-- network.db        # SQLite database (devices, scan_history, alerts)
|   `-- daemon.pid        # PID file for active background daemon
`-- logs/
    |-- activity.log      # Timestamped audit log of all scans and events
    `-- last_scan.txt     # Raw output from the most recent Nmap sweep
```

### Module Responsibilities

| Module | Purpose & Core Logic |
| :--- | :--- |
| **[`user_interaction.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/user_interaction.py)** | Handles interactive menu loops, key listening (`get_key`), screen transitions, and user prompts. |
| **[`ui.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/ui.py)** | Renders Unicode box borders, headers, tables, colored status tags, and thread-safe loading spinners. |
| **[`network_info.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/network_info.py)** | Inspects default routing tables (`ip route`) and NetworkManager (`nmcli`) to detect IP, SSID, Gateway, and Subnet. |
| **[`scan_network.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/scan_network.py)** | Spawns `nmap -sn` subprocesses, manages background daemon sessions (`start_new_session=True`), and tracks PIDs. |
| **[`parser.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/parser.py)** | Parses Nmap stdout with regex, enriches missing MACs from `/proc/net/arp`, and resolves OUI vendors. |
| **[`storage.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/storage.py)** | SQLite database layer managing `devices`, `scan_history`, and `alerts` tables with atomic transactions. |
| **[`differ.py`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/differ.py)** | Evaluates current scan against historical DB records to flag `NEW_DEVICE` or `IP_CHANGE` anomalies. |

---

## [04] Database Schema (`state/network.db`)

```sql
-- Registered network devices
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    custom_name TEXT,
    hostname TEXT,
    vendor TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    status TEXT DEFAULT 'unknown'
);

-- Audit history of all scans
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    subnet TEXT,
    hosts_found INTEGER,
    raw_output TEXT
);

-- Security and state anomaly alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    mac TEXT,
    ip TEXT,
    alert_type TEXT,
    message TEXT
);
```

---

## [05] Getting Started

### 1. Prerequisites
* **Operating System**: Linux (Ubuntu, Debian, Arch, Fedora, etc.) or macOS
* **Python**: Python 3.10+
* **Nmap**: Network exploration tool (`sudo apt install nmap`)
* **Notify-Send** *(Optional, for desktop popups)*: `sudo apt install libnotify-bin`

### 2. Running the Application

Make the launcher executable and run:
```bash
chmod +x ./Home\ Network\ Mapper/user_interaction.py
./Home\ Network\ Mapper/user_interaction.py
```

---

## [06] User Interface & Navigation

### 1. Main Menu
Displays current network interface, local IP, gateway, and live background daemon status:
```
+------------------------------------------------------------------+
|                       HOME NETWORK MAPPER                        |
+------------------------------------------------------------------+
|  Scans your network for devices and logs any unknown devices.    |
|                                                                  |
|  Network : Wired (enp34s0) (Ethernet)                            |
|  Your IP : 192.168.254.108                                       |
|  Gateway : 192.168.254.254                                       |
|  Daemon  : Active (PID 91986) [Scanning every 30s]               |
+------------------------------------------------------------------+

+-- Main Menu -----------------------------------------------------------+
|                                                                        |
|  > [1] Scan Networks    Run nmap scan & parse results to table view    |
|    [2] Logs & Alerts    Automated scan logs & unknown device alerts    |
|    [3] List of Devices  Device table (name, IP, MAC) & rename devices  |
|    [4] Exit             Exit Home Network Mapper                       |
|                                                                        |
+------------------------------------------------------------------------+
  [^/v] Navigate  *  [ENTER] Select  *  [ESC/q] Back/Exit
```

### 2. Device Registry & Interactive Renaming
View all recognized clients and interactively assign aliases without having to remember or copy IP/MAC addresses:
```
Alias / Name           | IP Address       | MAC Address        | Vendor                       | Status
----------------------------------------------------------------------------------------------------
My MSI Desktop PC      | 192.168.254.108  | 34:5A:60:B6:38:6A  | Micro-Star INTL CO., LTD.    | Known (Alias)
globebroadband.net     | 192.168.254.254  | 6C:A4:D1:E5:9B:40  | Fiberhome Telecommunication  | Known (Alias)
Borgy Phone            | 192.168.254.107  | EA:7B:67:F3:08:93  | Private MAC (Phone/Mobile)   | Known (Alias)
```

### 3. Exit with Background Daemonization
When exiting, choose to leave the scanner running as a detached background service:
```
+-- Exit Application ------------------------------------------------------------------------+
|                                                                                             |
|  > [1] Full Exit                 Shut down application completely                           |
|    [2] Run in Background & Exit  Detach background scanner (~15MB RAM) with desktop alerts  |
|    [3] Cancel                    Return to Main Menu                                        |
|                                                                                             |
+--------------------------------------------------------------------------------------------+
```

---

## [07] Technical Deep-Dive & Concepts Mastered

### 1. Unbuffered Raw Terminal Input
Standard `sys.stdin.read()` buffers keystrokes until the user hits Enter. To capture arrow keys (`\x1b[A`, `\x1b[B`) instantly:
```python
# Switch terminal to cbreak raw mode
fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)
tty.setcbreak(fd)

# Read raw bytes directly from OS file descriptor
char = os.read(fd, 1)
```

### 2. Discovering Devices Connected to Router without Admin Login
Instead of requiring admin credentials to access the router's private DHCP lease table, an unprivileged `nmap -sn` sweep triggers the router's Layer-2 switch to forward discovery frames to all clients. Their responses automatically populate the local kernel ARP table (`/proc/net/arp`), enabling full MAC extraction.

### 3. Detecting Randomized Private MACs
Mobile devices (iOS, Android) rotate MAC addresses using Locally Administered Address (LAA) formatting. We identify them mathematically by inspecting the IEEE Local/Universal bit (bit 1 of byte 0):
```python
def is_randomized_mac(mac: str) -> bool:
    first_byte = int(mac.split(":")[0], 16)
    return (first_byte & 0b00000010) != 0  # True for private smartphone MACs
```

### 4. Background Daemon Resource Benchmarking
* **RAM Footprint**: **~14.6 MB** (`VmRSS: 14612 kB`)
* **CPU Usage**: **0.0%** during idle timer intervals.
* **Process Management**: Detached with `start_new_session=True` and tracked via `state/daemon.pid`.

---

## [08] License
This project is open-source and created for educational, network security, and administrative monitoring purposes.

