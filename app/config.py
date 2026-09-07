import os

DB_FILE = "/app/data/monitor.db"
BACKUPS_DIR = "/app/backups"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "DtMzN51NkYuDe4")

# Login brute-force protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

# Default values for settings stored in the DB (key/value table).
# Kept as strings since the settings table stores everything as TEXT.
DEFAULT_SETTINGS = {
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "ping_interval_seconds": "15",
    "fail_threshold": "4",
    "packet_loss_window": "20",
    "packet_loss_threshold_pct": "20",
    "backup_hour": "17",
    "backup_minute": "0",
    "backup_retention": "7",
}
