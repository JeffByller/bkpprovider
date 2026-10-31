import datetime
import glob
import os
import re
import sqlite3

from app.config import BACKUPS_DIR, DB_FILE, DEFAULT_SETTINGS
from app.crypto import encrypt_secret

_ROS_HEADER_RE = re.compile(r"by RouterOS\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)


def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _migrate_column(cursor, table, column, ddl):
    """Adds a column if it doesn't exist yet. Safe to call on every startup."""
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
    except sqlite3.OperationalError:
        pass


def _detect_ros_from_backup_files(ip: str) -> tuple[str, str]:
    """Scans existing backup files for a device IP to identify RouterOS v6 vs v7."""
    if not os.path.exists(BACKUPS_DIR):
        return "auto", ""
    pattern = os.path.join(BACKUPS_DIR, f"*_{ip}_*.txt")
    files = sorted(glob.glob(pattern), reverse=True)
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                head = f.read(512)
            m = _ROS_HEADER_RE.search(head)
            if m:
                ver_detail = m.group(1)
                major = "v7" if ver_detail.startswith("7.") else ("v6" if ver_detail.startswith("6.") else "auto")
                return major, ver_detail
        except Exception:
            continue
    return "auto", ""


def _table_exists(cursor, table_name: str) -> bool:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None


def _migrate_legacy_devices(conn):
    """
    One-time migration that merges legacy `mikrotik_devices` and `ping_targets`
    into the unified `devices` table, preserving credentials, Telegram destinations,
    detecting RouterOS v6/v7 from existing backups, and indexing existing backup files.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM devices")
    if cursor.fetchone()["cnt"] > 0:
        # Clean up legacy tables if they still exist
        cursor.execute("DROP TABLE IF EXISTS ping_targets")
        cursor.execute("DROP TABLE IF EXISTS mikrotik_devices")
        conn.commit()
        return

    has_mk = _table_exists(cursor, "mikrotik_devices")
    has_pt = _table_exists(cursor, "ping_targets")

    mk_rows = []
    if has_mk:
        cursor.execute("SELECT * FROM mikrotik_devices ORDER BY id ASC")
        mk_rows = [dict(r) for r in cursor.fetchall()]

    pt_by_ip = {}
    pt_rows = []
    if has_pt:
        cursor.execute("SELECT * FROM ping_targets ORDER BY id ASC")
        pt_rows = [dict(r) for r in cursor.fetchall()]
        for r in pt_rows:
            ip = (r.get("ip") or "").strip()
            if ip and ip not in pt_by_ip:
                pt_by_ip[ip] = r

    migrated_ips = set()

    # 1. Migrate all MikroTik devices with SSH credentials + matched ICMP settings
    for mk in mk_rows:
        ip = (mk.get("ip") or "").strip()
        if not ip:
            continue
        migrated_ips.add(ip)
        pt = pt_by_ip.get(ip, {})

        ros_major, ros_detail = _detect_ros_from_backup_files(ip)
        enc_pass = encrypt_secret(mk.get("password") or "")
        dest_id = pt.get("telegram_destination_id")
        active = pt.get("active", 1)
        if active is None:
            active = 1
        status = pt.get("status") or "UP"
        latency_ms = pt.get("latency_ms")
        avg_latency_ms = pt.get("avg_latency_ms")
        last_check = pt.get("last_check")

        cursor.execute(
            """
            INSERT INTO devices (
                name, ip, device_type, ros_version, ros_version_detail,
                ssh_port, ssh_username, ssh_password,
                icmp_enabled, backup_enabled, ssh_enabled, snmp_enabled,
                snmp_community, snmp_port, snmp_version,
                active, telegram_destination_id,
                status, latency_ms, avg_latency_ms, last_check,
                last_backup, last_backup_status
            ) VALUES (?, ?, 'mikrotik', ?, ?, ?, ?, ?, 1, 1, 1, 0, 'public', 161, '2c', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mk.get("name") or ip,
                ip,
                ros_major,
                ros_detail,
                int(mk.get("port") or 22),
                mk.get("username") or "admin",
                enc_pass,
                int(active),
                dest_id,
                status,
                latency_ms,
                avg_latency_ms,
                last_check,
                mk.get("last_backup"),
                mk.get("last_status") or "PENDING",
            ),
        )
        dev_id = cursor.lastrowid

        # Index existing backup files on disk into backup_history
        if os.path.exists(BACKUPS_DIR):
            files = sorted(glob.glob(os.path.join(BACKUPS_DIR, f"*_{ip}_*.txt")))
            for fpath in files:
                fname = os.path.basename(fpath)
                try:
                    st = os.stat(fpath)
                    fsize = st.st_size
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    fsize = 0
                    mtime = mk.get("last_backup") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(
                    """
                    INSERT INTO backup_history (
                        device_id, device_name, device_ip, ros_version,
                        filename, size_bytes, status, trigger_type, duration_ms, message, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS', 'AUTO', 0, 'Backup importado na unificação', ?)
                    """,
                    (dev_id, mk.get("name") or ip, ip, ros_detail or ros_major, fname, fsize, mtime),
                )

    # 2. Migrate remaining ping_targets (links without SSH credentials yet) as ICMP-only devices
    for pt in pt_rows:
        ip = (pt.get("ip") or "").strip()
        if not ip or ip in migrated_ips:
            continue
        migrated_ips.add(ip)
        active = pt.get("active", 1)
        if active is None:
            active = 1
        cursor.execute(
            """
            INSERT INTO devices (
                name, ip, device_type, ros_version, ros_version_detail,
                ssh_port, ssh_username, ssh_password,
                icmp_enabled, backup_enabled, ssh_enabled, snmp_enabled,
                snmp_community, snmp_port, snmp_version,
                active, telegram_destination_id,
                status, latency_ms, avg_latency_ms, last_check,
                last_backup_status
            ) VALUES (?, ?, 'mikrotik', 'auto', '', 22, '', '', 1, 0, 0, 0, 'public', 161, '2c', ?, ?, ?, ?, ?, ?, 'DISABLED')
            """,
            (
                pt.get("name") or ip,
                ip,
                int(active),
                pt.get("telegram_destination_id"),
                pt.get("status") or "UP",
                pt.get("latency_ms"),
                pt.get("avg_latency_ms"),
                pt.get("last_check"),
            ),
        )

    # 3. Remove obsolete tables and obsolete packet_loss settings
    cursor.execute("DROP TABLE IF EXISTS ping_targets")
    cursor.execute("DROP TABLE IF EXISTS mikrotik_devices")
    cursor.execute("DELETE FROM settings WHERE key IN ('packet_loss_window', 'packet_loss_threshold_pct')")
    # Adjust fail_threshold if it was set to an extreme value like 30 minutes
    cursor.execute("SELECT value FROM settings WHERE key='fail_threshold'")
    row = cursor.fetchone()
    if row and str(row["value"]).isdigit() and int(row["value"]) > 10:
        cursor.execute("UPDATE settings SET value='3' WHERE key='fail_threshold'")
    conn.commit()


def init_db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telegram_destinations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token TEXT NOT NULL,
            chat_id TEXT NOT NULL
        )
    """)

    # Unified Central Devices Inventory
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            device_type TEXT DEFAULT 'mikrotik',
            ros_version TEXT DEFAULT 'auto',
            ros_version_detail TEXT DEFAULT '',
            board_name TEXT DEFAULT '',
            architecture TEXT DEFAULT '',
            ssh_port INTEGER DEFAULT 22,
            ssh_username TEXT DEFAULT '',
            ssh_password TEXT DEFAULT '',
            ssh_host_key TEXT DEFAULT '',
            icmp_enabled INTEGER DEFAULT 1,
            backup_enabled INTEGER DEFAULT 0,
            ssh_enabled INTEGER DEFAULT 0,
            snmp_enabled INTEGER DEFAULT 0,
            snmp_auto_poll INTEGER DEFAULT 0,
            snmp_auto_until TIMESTAMP,
            snmp_version TEXT DEFAULT '2c',
            snmp_port INTEGER DEFAULT 161,
            snmp_community TEXT DEFAULT 'public',
            snmp_status TEXT DEFAULT 'UNCONFIGURED',
            snmp_last_error TEXT DEFAULT '',
            snmp_last_check TIMESTAMP,
            active INTEGER DEFAULT 1,
            telegram_destination_id INTEGER,
            notes TEXT DEFAULT '',
            status TEXT DEFAULT 'UP',
            consecutive_failures INTEGER DEFAULT 0,
            latency_ms REAL,
            avg_latency_ms REAL,
            last_check TIMESTAMP,
            last_seen_up TIMESTAMP,
            alert_sent INTEGER DEFAULT 0,
            last_backup TIMESTAMP,
            last_backup_status TEXT DEFAULT 'PENDING',
            last_backup_message TEXT DEFAULT '',
            cpu_load INTEGER,
            memory_used_pct REAL,
            memory_total_mb REAL,
            memory_used_mb REAL,
            uptime_str TEXT DEFAULT '',
            rx_bps INTEGER DEFAULT 0,
            tx_bps INTEGER DEFAULT 0,
            interfaces_json TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backup_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            device_name TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            ros_version TEXT DEFAULT '',
            filename TEXT NOT NULL,
            size_bytes INTEGER DEFAULT 0,
            status TEXT NOT NULL,
            trigger_type TEXT DEFAULT 'AUTO',
            duration_ms INTEGER DEFAULT 0,
            message TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            device_name TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            action_key TEXT NOT NULL,
            command_executed TEXT NOT NULL,
            status TEXT NOT NULL,
            output_preview TEXT DEFAULT '',
            duration_ms INTEGER DEFAULT 0,
            client_ip TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            latency_ms REAL,
            cpu_load INTEGER,
            memory_used_pct REAL,
            rx_bps INTEGER DEFAULT 0,
            tx_bps INTEGER DEFAULT 0
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_backup_history_dev ON backup_history(device_id, id DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_command_logs_dev ON command_logs(device_id, id DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_metrics_dev_ts ON device_metrics(device_id, timestamp DESC)")

    _migrate_column(cursor, "devices", "snmp_auto_poll", "INTEGER DEFAULT 0")
    _migrate_column(cursor, "devices", "snmp_auto_until", "TIMESTAMP")

    # License management tables (preserved 100% original)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT NOT NULL,
            license_key TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            allowed_domain TEXT DEFAULT '',
            expires_at TIMESTAMP,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_check_at TIMESTAMP,
            last_ip TEXT,
            last_hostname TEXT,
            last_version TEXT,
            total_checks INTEGER DEFAULT 0
        )
    """)
    cursor.execute("DROP TABLE IF EXISTS license_logs")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)")

    _migrate_column(cursor, "licenses", "allowed_domain", "TEXT DEFAULT ''")
    _migrate_column(cursor, "licenses", "notes", "TEXT DEFAULT ''")
    _migrate_column(cursor, "licenses", "last_check_at", "TIMESTAMP")
    _migrate_column(cursor, "licenses", "last_ip", "TEXT")
    _migrate_column(cursor, "licenses", "last_hostname", "TEXT")
    _migrate_column(cursor, "licenses", "last_version", "TEXT")
    _migrate_column(cursor, "licenses", "total_checks", "INTEGER DEFAULT 0")

    conn.commit()
    _migrate_legacy_devices(conn)
    prune_command_logs(conn.cursor(), 200)
    conn.commit()
    conn.close()


def prune_command_logs(cursor, max_rows: int = 200):
    """Keeps only the most recent `max_rows` records in command_logs."""
    cursor.execute(
        """
        DELETE FROM command_logs
        WHERE id NOT IN (
            SELECT id FROM command_logs ORDER BY id DESC LIMIT ?
        )
        """,
        (max_rows,),
    )


def get_setting(key, default=None):
    if default is None:
        default = DEFAULT_SETTINGS.get(key, "")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = c.fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=?",
            (key, value, value),
        )
        conn.commit()
    finally:
        conn.close()


def get_all_settings():
    """Returns every known setting merged with its default, all as strings."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        stored = {row["key"]: row["value"] for row in c.fetchall()}
    finally:
        conn.close()
    merged = dict(DEFAULT_SETTINGS)
    merged.update({k: v for k, v in stored.items() if v is not None and k in DEFAULT_SETTINGS})
    return merged


def get_settings_typed():
    """Same as get_all_settings but with numeric fields cast to int/float."""
    raw = get_all_settings()
    out = dict(raw)
    int_fields = [
        "ping_interval_seconds",
        "fail_threshold",
        "snmp_interval_seconds",
        "metrics_retention_days",
        "backup_hour",
        "backup_minute",
        "backup_retention",
    ]
    for field in int_fields:
        try:
            out[field] = int(float(raw.get(field, DEFAULT_SETTINGS[field])))
        except (ValueError, TypeError):
            out[field] = int(DEFAULT_SETTINGS[field])
    return out

