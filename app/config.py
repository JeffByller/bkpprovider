import os

DATA_DIR = "/app/data" if os.path.exists("/app") else os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DB_FILE = os.path.join(DATA_DIR, "monitor.db")
BACKUPS_DIR = "/app/backups" if os.path.exists("/app") else os.path.join(os.path.dirname(os.path.dirname(__file__)), "backups")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "DtMzN51NkYuDe4")
SECRET_KEY_ENV = os.getenv("SECRET_KEY", "")

# Login brute-force protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

# Default values for settings stored in the DB (key/value table).
# Kept as strings since the settings table stores everything as TEXT.
DEFAULT_SETTINGS = {
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "ping_interval_seconds": "60",
    "fail_threshold": "3",
    "snmp_interval_seconds": "60",
    "snmp_default_community": "@BKP2712",
    "snmp_allowed_ip": "38.225.221.159",
    "metrics_retention_days": "7",
    "backup_hour": "12",
    "backup_minute": "0",
    "backup_retention": "7",
}
