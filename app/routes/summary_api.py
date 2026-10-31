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
        c.execute(
            """
            SELECT active, icmp_enabled, backup_enabled, ssh_enabled, snmp_enabled,
                   status, latency_ms, ros_version, last_backup, last_backup_status, snmp_status
            FROM devices
            """
        )
        devices = c.fetchall()

        c.execute("SELECT status, expires_at FROM licenses")
        licenses = c.fetchall()
    finally:
        conn.close()

    active_devices = [d for d in devices if d["active"]]
    icmp_devices = [d for d in active_devices if d["icmp_enabled"]]
    up = sum(1 for d in icmp_devices if d["status"] == "UP")
    down = sum(1 for d in icmp_devices if d["status"] == "DOWN")
    latencies = [d["latency_ms"] for d in icmp_devices if d["latency_ms"] is not None]
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None

    bkp_devices = [d for d in active_devices if d["backup_enabled"]]
    ssh_devices = [d for d in active_devices if d["ssh_enabled"]]
    snmp_devices = [d for d in active_devices if d["snmp_enabled"]]
    snmp_ok = sum(1 for d in snmp_devices if d["snmp_status"] == "OK")

    ros_v6 = sum(1 for d in devices if d["ros_version"] == "v6")
    ros_v7 = sum(1 for d in devices if d["ros_version"] == "v7")

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    backups_today = [d for d in bkp_devices if d["last_backup"] and str(d["last_backup"]).startswith(today)]
    backups_ok_today = sum(1 for d in backups_today if d["last_backup_status"] == "SUCCESS")
    backups_failed_today = sum(
        1 for d in bkp_devices if d["last_backup_status"] and str(d["last_backup_status"]).startswith("FAILED")
    )

    licenses_total = len(licenses)
    licenses_active = sum(1 for l in licenses if l["status"] == "ACTIVE")
    licenses_blocked = sum(1 for l in licenses if l["status"] == "BLOCKED")

    return {
        "devices_total": len(devices),
        "devices_active": len(active_devices),
        "targets_total": len(icmp_devices),
        "targets_active": len(icmp_devices),
        "targets_up": up,
        "targets_down": down,
        "avg_latency_ms": avg_latency,
        "backup_devices_total": len(bkp_devices),
        "ssh_devices_total": len(ssh_devices),
        "snmp_devices_total": len(snmp_devices),
        "snmp_ok": snmp_ok,
        "ros_v6": ros_v6,
        "ros_v7": ros_v7,
        "backups_ok_today": backups_ok_today,
        "backups_failed_today": backups_failed_today,
        "licenses_total": licenses_total,
        "licenses_active": licenses_active,
        "licenses_blocked": licenses_blocked,
    }
