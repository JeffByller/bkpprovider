import asyncio
import datetime
import re
from collections import deque

from app.db import get_db, get_settings_typed
from app.telegram import send_telegram

_HISTORY_MAXLEN = 40
HISTORY: dict[int, deque] = {}

_PING_TIME_RE = re.compile(rb"time[=<]\s*([\d.]+)")


def _history_for(device_id: int) -> deque:
    hist = HISTORY.get(device_id)
    if hist is None:
        hist = deque(maxlen=_HISTORY_MAXLEN)
        HISTORY[device_id] = hist
    return hist


async def _single_ping(ip: str, count: int = 1, timeout: int = 2) -> tuple[bool, float | None]:
    cmd = ["ping", "-c", str(count), "-W", str(timeout)]
    if count > 1:
        cmd.extend(["-i", "0.2"])
    cmd.append(ip)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    ok = proc.returncode == 0
    latency = None
    if ok:
        matches = _PING_TIME_RE.findall(stdout)
        if matches:
            try:
                vals = [float(x) for x in matches]
                latency = round(sum(vals) / len(vals), 2)
            except ValueError:
                latency = None
    return ok, latency


async def ping_ip(ip: str) -> tuple[bool, float | None]:
    """
    Availability-focused ICMP probe:
    Sends 1 packet first. If it fails (e.g., transient cloud jitter), immediately
    performs a quick 2-packet confirmation burst before declaring the probe failed.
    """
    ok, latency = await _single_ping(ip, count=1, timeout=2)
    if ok:
        return True, latency
    return await _single_ping(ip, count=2, timeout=2)


def _avg_latency(device_id: int) -> float | None:
    hist = _history_for(device_id)
    ok_latencies = [lat for ok, lat in hist if ok and lat is not None]
    if not ok_latencies:
        return None
    return round(sum(ok_latencies) / len(ok_latencies), 2)


async def _probe_device(dev, settings, now: str) -> dict:
    dev_id = dev["id"]
    name = dev["name"]
    ip = dev["ip"]
    failures = dev["consecutive_failures"] or 0
    status = dev["status"] or "UP"
    alert_sent = dev["alert_sent"] or 0
    last_seen_up = dev["last_seen_up"]
    interval = settings["ping_interval_seconds"]
    fail_threshold = max(settings["fail_threshold"], 1)

    is_up, latency = await ping_ip(ip)
    _history_for(dev_id).append((is_up, latency))
    avg_lat = _avg_latency(dev_id)

    new_status = status if status in ("UP", "DOWN") else "UP"
    new_failures = failures
    new_alert_sent = alert_sent
    new_last_seen_up = last_seen_up
    telegram_messages = []

    if is_up:
        new_failures = 0
        new_alert_sent = 0
        new_last_seen_up = now
        if status == "DOWN":
            new_status = "UP"
            telegram_messages.append(
                f"🟢 <b>[ONLINE]</b> Dispositivo <b>{name}</b> (<code>{ip}</code>) voltou a responder ICMP! "
                f"(Latência: {latency:.1f} ms)" if latency is not None else
                f"🟢 <b>[ONLINE]</b> Dispositivo <b>{name}</b> (<code>{ip}</code>) voltou a responder ICMP!"
            )
        else:
            new_status = "UP"
    else:
        new_failures = failures + 1
        if new_failures >= fail_threshold:
            new_status = "DOWN"
            if alert_sent == 0:
                approx_secs = fail_threshold * interval
                telegram_messages.append(
                    f"🚨 <b>[INDISPONÍVEL - DOWN]</b> Dispositivo <b>{name}</b> (<code>{ip}</code>) "
                    f"sem resposta ICMP após {new_failures} verificações consecutivas (~{approx_secs}s)!"
                )
                new_alert_sent = 1

    return {
        "id": dev_id,
        "status": new_status,
        "consecutive_failures": new_failures,
        "last_check": now,
        "last_seen_up": new_last_seen_up,
        "alert_sent": new_alert_sent,
        "latency_ms": latency,
        "avg_latency_ms": avg_lat,
        "snmp_enabled": bool(dev["snmp_enabled"]),
        "telegram_destination_id": dev["telegram_destination_id"],
        "telegram_messages": telegram_messages,
    }


async def run_icmp_cycle():
    settings = get_settings_typed()
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE active=1 AND icmp_enabled=1")
        devices = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    if not devices:
        return

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = await asyncio.gather(
        *(_probe_device(d, settings, now) for d in devices),
        return_exceptions=True,
    )

    valid_results = [r for r in results if isinstance(r, dict)]
    if not valid_results:
        return

    # Single batch transaction for all ICMP updates -> reduces disk I/O by >90%
    conn = get_db()
    try:
        c = conn.cursor()
        c.executemany(
            """
            UPDATE devices
            SET consecutive_failures=?, status=?, last_check=?, last_seen_up=?,
                alert_sent=?, latency_ms=?, avg_latency_ms=?
            WHERE id=?
            """,
            [
                (
                    r["consecutive_failures"],
                    r["status"],
                    r["last_check"],
                    r["last_seen_up"],
                    r["alert_sent"],
                    r["latency_ms"],
                    r["avg_latency_ms"],
                    r["id"],
                )
                for r in valid_results
            ],
        )
        # For devices without SNMP enabled, record latency in device_metrics so latency trend is persisted
        icmp_only_metrics = [
            (r["id"], now, r["latency_ms"])
            for r in valid_results
            if not r["snmp_enabled"] and r["latency_ms"] is not None
        ]
        if icmp_only_metrics:
            c.executemany(
                "INSERT INTO device_metrics (device_id, timestamp, latency_ms) VALUES (?, ?, ?)",
                icmp_only_metrics,
            )
        conn.commit()
    finally:
        conn.close()

    # Dispatch Telegram notifications outside the DB transaction
    for r in valid_results:
        for msg in r["telegram_messages"]:
            await send_telegram(msg, r["telegram_destination_id"])


async def icmp_worker():
    while True:
        settings = get_settings_typed()
        interval = max(settings["ping_interval_seconds"], 5)
        try:
            await run_icmp_cycle()
        except Exception as e:
            print(f"[ICMP Worker Error] {e}")
        await asyncio.sleep(interval)


def get_history_for_device(device_id: int) -> list[dict]:
    hist = list(_history_for(device_id))[-30:]
    return [{"ok": bool(ok), "latency": lat} for ok, lat in hist]
