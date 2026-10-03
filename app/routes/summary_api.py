import datetime

from fastapi import APIRouter, Depends

from app.auth import require_auth
from app.db import get_db

router = APIRouter(prefix="/api/summary", dependencies=[Depends(require_auth)])


@router.get("")
async def summary():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT status, active, latency_ms FROM ping_targets")
        targets = c.fetchall()

        c.execute("SELECT last_status, last_backup FROM mikrotik_devices")
        devices = c.fetchall()

        c.execute("SELECT status, expires_at FROM licenses")
        licenses = c.fetchall()

        today_start = datetime.datetime.now().strftime("%Y-%m-%d 00:00:00")
        c.execute("SELECT COUNT(*) as count FROM license_logs WHERE timestamp >= ?", (today_start,))
        checks_row = c.fetchone()
        license_checks_today = checks_row["count"] if checks_row else 0
    finally:
        conn.close()

    active_targets = [t for t in targets if t["active"]]
    up = sum(1 for t in active_targets if t["status"] == "UP")
    down = sum(1 for t in active_targets if t["status"] == "DOWN")
    latencies = [t["latency_ms"] for t in active_targets if t["latency_ms"] is not None]
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    backups_today = [d for d in devices if d["last_backup"] and d["last_backup"].startswith(today)]
    backups_ok_today = sum(1 for d in backups_today if d["last_status"] == "SUCCESS")
    backups_failed_today = sum(1 for d in backups_today if d["last_status"] and d["last_status"].startswith("FAILED"))

    licenses_total = len(licenses)
    licenses_active = sum(1 for l in licenses if l["status"] == "ACTIVE")
    licenses_blocked = sum(1 for l in licenses if l["status"] == "BLOCKED")

    return {
        "targets_total": len(targets),
        "targets_active": len(active_targets),
        "targets_up": up,
        "targets_down": down,
        "avg_latency_ms": avg_latency,
        "devices_total": len(devices),
        "backups_ok_today": backups_ok_today,
        "backups_failed_today": backups_failed_today,
        "licenses_total": licenses_total,
        "licenses_active": licenses_active,
        "licenses_blocked": licenses_blocked,
        "license_checks_today": license_checks_today,
    }
