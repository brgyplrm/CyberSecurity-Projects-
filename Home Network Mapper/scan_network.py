"""
scan_network.py - Network Scanning Engine
Executes Nmap discovery scans (ping/host scan), manages raw scan logs, and records scan events.
"""

import os
import shutil
import subprocess
import datetime


def get_nmap_bin() -> str | None:
    """
    Finds the nmap executable path across Linux, macOS, and Windows.
    Checks system PATH and standard Windows installation directories.
    """
    # 1. Standard PATH lookup (handles Linux/macOS 'nmap' and Windows 'nmap.exe')
    for name in ["nmap", "nmap.exe"]:
        path = shutil.which(name)
        if path:
            return path

    # 2. Common Windows paths (if user forgot to add to Environment Variables)
    if os.name == "nt" or "WINDIR" in os.environ:
        windows_candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%ProgramFiles(x86)%\Nmap\nmap.exe"),
            os.path.expandvars(r"%ProgramFiles%\Nmap\nmap.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
        ]
        for win_path in windows_candidates:
            if os.path.exists(win_path):
                return win_path

    return None


def is_nmap_installed() -> bool:
    """
    Checks if the 'nmap' binary is installed and available.
    """
    return get_nmap_bin() is not None


def get_nmap_install_instructions() -> list[str]:
    """
    Returns platform-specific instructions for installing Nmap.
    """
    return [
        "'nmap' was not found on your system PATH or default directories.",
        "Nmap is required to perform network discovery scans.",
        "",
        "How to install Nmap:",
        " • Ubuntu / Debian : sudo apt update && sudo apt install -y nmap",
        " • Arch Linux      : sudo pacman -S nmap",
        " • Fedora / RHEL   : sudo dnf install nmap",
        " • macOS (Homebrew): brew install nmap",
        " • Windows         : winget install Insecure.Nmap",
        "                     or download installer from https://nmap.org",
        "",
        "Once installed, restart the scan to discover devices!"
    ]

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
STATE_DIR = os.path.join(BASE_DIR, "state")
LAST_SCAN_RAW_PATH = os.path.join(LOGS_DIR, "last_scan.txt")
ACTIVITY_LOG_PATH = os.path.join(LOGS_DIR, "activity.log")
DAEMON_PID_PATH = os.path.join(STATE_DIR, "daemon.pid")


def ensure_logs_directory():
    """Ensures the logs and state directories exist."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)


def log_activity(event_message: str):
    """Appends a timestamped event entry to logs/activity.log."""
    ensure_logs_directory()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {event_message}\n"
    try:
        with open(ACTIVITY_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception:
        pass


def derive_subnet(ip_addr: str) -> str:
    """
    Derives standard /24 subnet from an IP address.
    Example: '192.168.1.45' -> '192.168.1.0/24'
    """
    if not ip_addr or ip_addr == "127.0.0.1":
        return "127.0.0.1"
    parts = ip_addr.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return f"{ip_addr}/24"


def run_nmap_scan(target_subnet: str, timeout_seconds: int = 60) -> tuple[bool, str]:
    """
    Executes a ping/host discovery scan using `nmap -sn <target_subnet>`.
    Includes automatic fallback to `--unprivileged` mode on Windows / restricted environments.
    """
    ensure_logs_directory()
    log_activity(f"Scan started on target: {target_subnet}")

    nmap_bin = get_nmap_bin()
    if not nmap_bin:
        err_msg = "Error: 'nmap' is not installed or not found in system PATH."
        log_activity(f"Scan error: {err_msg}")
        return False, err_msg

    cmd = [nmap_bin, "-sn", target_subnet]
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )

        if process.returncode == 0:
            raw_output = process.stdout
            # Save raw scan text
            with open(LAST_SCAN_RAW_PATH, "w", encoding="utf-8") as f:
                f.write(raw_output)
            log_activity(f"Scan completed successfully for {target_subnet}")
            return True, raw_output

        # If Nmap failed (e.g. Windows unprivileged / Npcap driver permission restriction),
        # automatically retry with --unprivileged flag
        err_output = process.stderr.strip() or process.stdout.strip()
        if os.name == "nt" or "dnet" in err_output.lower() or "permission" in err_output.lower() or "device" in err_output.lower():
            log_activity(f"Retrying scan with --unprivileged flag on {target_subnet}...")
            unpriv_cmd = [nmap_bin, "-sn", "--unprivileged", target_subnet]
            process2 = subprocess.run(
                unpriv_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False
            )
            if process2.returncode == 0:
                raw_output = process2.stdout
                with open(LAST_SCAN_RAW_PATH, "w", encoding="utf-8") as f:
                    f.write(raw_output)
                log_activity(f"Scan completed successfully with --unprivileged for {target_subnet}")
                return True, raw_output

        err_msg = process.stderr.strip() or process.stdout.strip() or f"Process exited with code {process.returncode}"
        log_activity(f"Scan failed on {target_subnet}: {err_msg}")
        return False, f"Nmap Error: {err_msg}"

    except FileNotFoundError:
        err_msg = "Error: 'nmap' is not installed or not found in system PATH."
        log_activity(f"Scan error: {err_msg}")
        return False, err_msg
    except subprocess.TimeoutExpired:
        err_msg = f"Scan timed out after {timeout_seconds} seconds."
        log_activity(f"Scan timeout: {err_msg}")
        return False, err_msg
    except Exception as e:
        err_msg = f"Unexpected error during scan: {str(e)}"
        log_activity(err_msg)
        return False, err_msg


def read_last_scan_raw() -> str:
    """
    Reads the last raw scan output saved in `logs/last_scan.txt`.
    Returns placeholder message if no scan file exists yet.
    """
    if os.path.exists(LAST_SCAN_RAW_PATH):
        try:
            with open(LAST_SCAN_RAW_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass
    return "No previous scan found. Please run an Nmap scan first."


# ─────────────────────────────────────────────────────────────────────────────
# Background Daemon Management
# ─────────────────────────────────────────────────────────────────────────────

def is_daemon_running() -> tuple[bool, int | None]:
    """
    Checks if a background scanning daemon is currently alive.
    Returns (is_running: bool, pid: int | None).
    """
    if os.path.exists(DAEMON_PID_PATH):
        try:
            with open(DAEMON_PID_PATH, "r") as f:
                pid_str = f.read().strip()
                if pid_str.isdigit():
                    pid = int(pid_str)
                    # Check if process is alive (signal 0 doesn't kill)
                    os.kill(pid, 0)
                    return True, pid
        except (OSError, ValueError):
            # Process dead or invalid PID file, cleanup
            try:
                os.remove(DAEMON_PID_PATH)
            except Exception:
                pass
    return False, None


def start_background_daemon(subnet: str, interval_seconds: int = 30) -> tuple[bool, int | None, str]:
    """
    Spawns an independent background process to continuously monitor the network.
    Returns (success: bool, pid: int | None, message: str).
    """
    ensure_logs_directory()
    running, pid = is_daemon_running()
    if running:
        return False, pid, f"Background daemon is already running (PID: {pid})."

    script_path = os.path.abspath(__file__)
    cmd = [
        os.sys.executable,
        script_path,
        "--daemon",
        subnet,
        str(interval_seconds)
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True  # Detach completely from parent terminal session
        )

        with open(DAEMON_PID_PATH, "w") as f:
            f.write(str(proc.pid))

        log_activity(f"Background monitoring daemon started with PID {proc.pid} (Subnet: {subnet}, Interval: {interval_seconds}s)")
        return True, proc.pid, f"Daemon started successfully with PID {proc.pid}"
    except Exception as e:
        return False, None, f"Failed to start daemon: {str(e)}"


def stop_background_daemon() -> tuple[bool, str]:
    """
    Terminates the running background monitoring daemon.
    """
    running, pid = is_daemon_running()
    if not running or not pid:
        return False, "No background daemon is currently active."

    try:
        import signal
        os.kill(pid, signal.SIGTERM)
        if os.path.exists(DAEMON_PID_PATH):
            os.remove(DAEMON_PID_PATH)
        log_activity(f"Background monitoring daemon (PID {pid}) stopped by user.")
        return True, f"Background daemon (PID {pid}) has been stopped."
    except Exception as e:
        return False, f"Failed to stop daemon PID {pid}: {str(e)}"


def run_daemon_loop(subnet: str, interval_seconds: int = 30):
    """
    Continuous background daemon execution loop.
    Runs scans, updates SQLite, and fires desktop alerts when unknown devices join.
    """
    import time
    import parser
    import differ
    import storage

    log_activity(f"Background daemon loop running for {subnet}")
    while True:
        try:
            success, output = run_nmap_scan(subnet)
            if success:
                hosts = parser.parse_nmap_output(output)
                diff_res = differ.analyze_and_update_state(hosts)
                storage.record_scan(subnet, len(hosts), output)
        except Exception as e:
            log_activity(f"Daemon scan iteration error: {str(e)}")

        time.sleep(max(10, interval_seconds))


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 4 and sys.argv[1] == "--daemon":
        target_sub = sys.argv[2]
        interval = int(sys.argv[3]) if sys.argv[3].isdigit() else 30
        run_daemon_loop(target_sub, interval)

