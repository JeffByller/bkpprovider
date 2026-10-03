import os
import sqlite3

from app.config import DB_FILE, DEFAULT_SETTINGS


def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _migrate_column(cursor, table, column, ddl):
    """Adds a column if it doesn't exist yet. Safe to call on every startup."""
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
    except sqlite3.OperationalError:
        pass  # Column already exists


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
        CREATE TABLE IF NOT EXISTS ping_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            consecutive_failures INTEGER DEFAULT 0,
            status TEXT DEFAULT 'UP',
            last_check TIMESTAMP,
            alert_sent INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mikrotik_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            last_backup TIMESTAMP,
            last_status TEXT DEFAULT 'PENDING'
        )
    """)

    # Migrations for existing databases (columns added over time)
    _migrate_column(cursor, "ping_targets", "active", "INTEGER DEFAULT 1")
    _migrate_column(cursor, "ping_targets", "latency_ms", "REAL")
    _migrate_column(cursor, "ping_targets", "avg_latency_ms", "REAL")
    _migrate_column(cursor, "ping_targets", "packet_loss_pct", "REAL DEFAULT 0")
    _migrate_column(cursor, "ping_targets", "loss_alert_sent", "INTEGER DEFAULT 0")

    # License management tables
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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS license_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER DEFAULT 0,
            license_key TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            hostname TEXT,
            app_version TEXT,
            status_returned TEXT NOT NULL,
            message TEXT,
            details TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_license_logs_license_id ON license_logs(license_id, id DESC)")

    _migrate_column(cursor, "licenses", "allowed_domain", "TEXT DEFAULT ''")
    _migrate_column(cursor, "licenses", "notes", "TEXT DEFAULT ''")
    _migrate_column(cursor, "licenses", "last_check_at", "TIMESTAMP")
    _migrate_column(cursor, "licenses", "last_ip", "TEXT")
    _migrate_column(cursor, "licenses", "last_hostname", "TEXT")
    _migrate_column(cursor, "licenses", "last_version", "TEXT")
    _migrate_column(cursor, "licenses", "total_checks", "INTEGER DEFAULT 0")

    conn.commit()
    conn.close()


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
    merged.update({k: v for k, v in stored.items() if v is not None})
    return merged


def get_settings_typed():
    """Same as get_all_settings but with numeric fields cast to int/float."""
    raw = get_all_settings()
    out = dict(raw)
    int_fields = [
        "ping_interval_seconds", "fail_threshold", "packet_loss_window",
        "packet_loss_threshold_pct", "backup_hour", "backup_minute", "backup_retention",
    ]
    for field in int_fields:
        try:
            out[field] = int(float(raw.get(field, DEFAULT_SETTINGS[field])))
        except (ValueError, TypeError):
            out[field] = int(DEFAULT_SETTINGS[field])
    return out
