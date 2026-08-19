"""
storage.py - SQLite Database Storage Engine
Handles persistent storage for network devices, scan audit history, and security alerts.
"""

import os
import sqlite3
import datetime

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(BASE_DIR, "state")
DB_PATH = os.path.join(STATE_DIR, "network.db")


def get_db_connection() -> sqlite3.Connection:
    """Creates and returns a SQLite database connection with row factory enabled."""
    os.makedirs(STATE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema if tables do not exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Devices Registry Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                custom_name TEXT DEFAULT '',
                hostname TEXT DEFAULT 'Unknown',
                vendor TEXT DEFAULT 'Unknown',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'unknown' -- 'known', 'unknown', 'trusted', 'blocked'
            );
        """)

        # 2. Scan History Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                subnet TEXT NOT NULL,
                hosts_found INTEGER NOT NULL,
                raw_output TEXT DEFAULT ''
            );
        """)

        # 3. Security Alerts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                alert_type TEXT NOT NULL, -- 'NEW_DEVICE', 'IP_CHANGE', 'STATUS_CHANGE'
                message TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0
            );
        """)

        conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Device CRUD Operations
# ─────────────────────────────────────────────────────────────────────────────

def get_all_devices() -> list[dict]:
    """Retrieves all registered devices sorted by last seen date."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC;")
        return [dict(row) for row in cursor.fetchall()]


def get_device_by_mac(mac: str) -> dict | None:
    """Retrieves a single device by MAC address."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE UPPER(mac) = UPPER(?);", (mac.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_device_by_ip(ip: str) -> dict | None:
    """Retrieves a single device by IP address."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE ip = ?;", (ip.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def upsert_device(
    mac: str,
    ip: str,
    hostname: str = "Unknown",
    vendor: str = "Unknown",
    custom_name: str = "",
    status: str = "unknown"
) -> tuple[bool, str]:
    """
    Inserts a new device or updates an existing device record.
    Returns (is_new_device: bool, message: str).
    """
    init_db()
    normalized_mac = mac.strip().upper()
    existing = get_device_by_mac(normalized_mac)

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if existing:
            # Update last_seen and network details
            cursor.execute("""
                UPDATE devices
                SET ip = ?, hostname = ?, vendor = ?, last_seen = ?
                WHERE UPPER(mac) = UPPER(?);
            """, (ip, hostname, vendor, now_str, normalized_mac))
            conn.commit()
            return False, f"Updated existing device [{normalized_mac}]"
        else:
            # Insert brand new device
            cursor.execute("""
                INSERT INTO devices (mac, ip, custom_name, hostname, vendor, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (normalized_mac, ip, custom_name, hostname, vendor, now_str, now_str, status))
            conn.commit()
            return True, f"New device registered: [{normalized_mac}] ({ip})"


def rename_device(identifier: str, new_name: str) -> bool:
    """
    Renames a device by either its MAC address or IP address.
    Returns True if updated successfully, False if not found.
    """
    init_db()
    identifier = identifier.strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE devices
            SET custom_name = ?, status = 'known'
            WHERE UPPER(mac) = UPPER(?) OR ip = ?;
        """, (new_name.strip(), identifier, identifier))
        conn.commit()
        return cursor.rowcount > 0


# ─────────────────────────────────────────────────────────────────────────────
# Scan History & Audit Operations
# ─────────────────────────────────────────────────────────────────────────────

def record_scan(subnet: str, hosts_found: int, raw_output: str = ""):
    """Records an executed scan into scan_history table."""
    init_db()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (timestamp, subnet, hosts_found, raw_output)
            VALUES (?, ?, ?, ?);
        """, (now_str, subnet, hosts_found, raw_output))
        conn.commit()


def get_recent_scans(limit: int = 10) -> list[dict]:
    """Returns the most recent scan records."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?;", (limit,))
        return [dict(row) for row in cursor.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# Alerts & Change Tracking Operations
# ─────────────────────────────────────────────────────────────────────────────

def record_alert(mac: str, ip: str, alert_type: str, message: str):
    """Inserts a security / network change alert."""
    init_db()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, mac, ip, alert_type, message, acknowledged)
            VALUES (?, ?, ?, ?, ?, 0);
        """, (now_str, mac.strip().upper(), ip.strip(), alert_type, message))
        conn.commit()


def get_all_alerts(limit: int = 25) -> list[dict]:
    """Retrieves recent alerts."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?;", (limit,))
        return [dict(row) for row in cursor.fetchall()]


# Initialize database automatically upon import
init_db()
