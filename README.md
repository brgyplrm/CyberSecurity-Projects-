# [ CyberSecurity Projects ]

> **A curated collection of cybersecurity tools, network scanners, and defensive automation projects developed throughout my cybersecurity engineering journey.**

```
   ____      _               ____                      _ _         
  / ___|   _| |__   ___ _ __/ ___|  ___  ___ _   _ _ __(_) |_ _   _ 
 | |  | | | | '_ \ / _ \ '__\___ \ / _ \/ __| | | | '__| | __| | | |
 | |__| |_| | |_) |  __/ |   ___) |  __/ (__| |_| | |  | | |_| |_| |
  \____\__, |_.__/ \___|_|  |____/ \___|\___|\__,_|_|  |_|\__|\__, |
       |___/                                                  |___/ 
  ____            _           _       
 |  _ \ _ __ ___ (_) ___  ___| |_ ___ 
 | |_) | '__/ _ \| |/ _ \/ __| __/ __|
 |  __/| | | (_) | |  __/ (__| |_\__ \
 |_|   |_|  \___// |\___|\___|\__|___/
               |__/                   
```

---

## [01] About This Repository

Welcome to my **Cybersecurity Engineering & Tooling Portfolio**. This repository serves as the central hub for practical security tools, network scanners, anomaly detection engines, and systems-level utilities developed during my continuous cybersecurity journey.

### [>] The Development Philosophy: AI Pair-Programming with Full Conceptual Mastery

Every tool in this repository is built using an **active, human-in-the-loop, AI-assisted development workflow**:

* `[+]` **Architectural Collaboration**: Using AI as a collaborative pair programmer for rapid brainstorming, algorithm prototyping, regex refinement, and state-machine design.
* `[*]` **Deep Syntax & Protocol Mastery**: No "black-box" copy-pasting. Every single line of code, low-level system call, terminal escape sequence, protocol header, and database query is thoroughly studied, understood, and engineered by hand.
* `[>]` **Practical Systems Engineering**: Moving beyond basic scripts to build production-grade, modular CLI applications with unbuffered terminal I/O, SQLite persistence, and decoupled background daemons.

---

## [02] Projects Portfolio

```
CyberSecurity-Projects-/
|-- [01] Home Network Mapper/      # Interactive network scanner, device registry, & daemon
|-- [02] Future Projects...        # Upcoming tools in development
`-- README.md                      # Main repository index & roadmap
```

### 1. Home Network Mapper (HNM)
* **Path**: [`Home Network Mapper/`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper)
* **Documentation**: [`Home Network Mapper/Readme.md`](file:///home/achyllisss/Documents/Projects/CyberSecurity-Projects-/Home%20Network%20Mapper/Readme.md)
* **Tech Stack**: `Python 3` | `Nmap` | `SQLite` | `Linux Kernel (/proc/net/arp)` | `Termios / ANSI`
* **Core Highlights**:
  * `[+]` **Interactive Arrow-Key Menu**: Pure Python terminal UI with unbuffered keyboard navigation (`^`/`v`, `[ENTER]`, `[ESC]`) and Unicode box drawing.
  * `[*]` **Dual-Layer Host & MAC Resolution**: Combines unprivileged `nmap -sn` sweeps with kernel ARP cache inspection (`/proc/net/arp`) for full Layer-2 & Layer-3 host visibility.
  * `[~]` **Hardware OUI & Mobile MAC Resolver**: Matches IEEE OUI vendor databases (`oui.txt`, `nmap-mac-prefixes`) and detects randomized private MACs on smartphones.
  * `[=]` **SQLite Device Registry**: Database persistence (`state/network.db`) with an interactive alias management workflow.
  * `[!]` **Live Monitor & Background Daemon**: Detached background scanning service (~14.6 MB RAM footprint) with native desktop popup alerts (`notify-send`) when unauthorized devices connect.
* **Quick Run**:
  * `[Linux]` : `chmod +x ./Home\ Network\ Mapper/user_interaction.py && ./Home\ Network\ Mapper/user_interaction.py`
  * `[macOS]` : `python3 "Home Network Mapper/user_interaction.py"`
  * `[Windows]`: `python "Home Network Mapper\user_interaction.py"` (PowerShell / Windows Terminal)

---

## [03] Core Competencies & Learning Focus Areas

* `[>]` **Network Security & Host Discovery**: Understanding ARP packet dynamics across switches, subnet CIDR calculation, ICMP/TCP ping sweeps, and interface binding.
* `[*]` **Low-Level Linux & Terminal Programming**: Managing terminal states via `termios`/`tty` `cbreak` modes, unbuffered `os.read()` descriptors, ANSI color codes, and non-blocking I/O with `select`.
* `[#]` **Data Persistence & Anomaly Diffing**: Designing relational SQLite schemas for device lifecycles, audit logging, and detecting state changes (IP reallocations, unknown MACs).
* `[$]` **Daemonization & Process Management**: Forking independent sessions (`start_new_session=True`), PID tracking, signal handling (`SIGTERM`), and inter-process communication.

---

## [04] Roadmap & Upcoming Projects

* `[ ]` **Multi-Threaded TCP/UDP Port Scanner**: Custom raw socket port scanner with banner grabbing and service version fingerprinting.
* `[ ]` **Packet Sniffer & Protocol Analyzer**: Low-level packet capture tool parsing Ethernet, IP, TCP, and UDP headers.
* `[ ]` **Log & Intrusion Detection Analyzer**: Automated parser for web server and authentication logs (`/var/log/auth.log`) to detect brute-force and traversal attacks.
* `[ ]` **Cryptography & Hash Cracking Lab**: Practical implementations of hashing, symmetric encryption, and dictionary attack engines.

---

## [05] License
This repository is open-source and created for educational, ethical cybersecurity research, and network administrative purposes.