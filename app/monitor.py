import asyncio
import datetime
import re
from collections import deque

from app.db import get_db, get_settings_typed
from app.telegram import send_telegram

# In-memory rolling history per target: deque of (ok: bool, latency_ms: float|None).
# Capped generously (100 samples); the effective window used for packet-loss/avg
# calculations comes from the "packet_loss_window" setting, so changing that
# setting takes effect immediately without needing to recreate the deques.
_HISTORY_MAXLEN = 100
HISTORY: dict[int, deque] = {}

_PING_TIME_RE = re.compile(rb"time[=<]\s*([\d.]+)")


def _history_for(target_id: int) -> deque:
    hist = HISTORY.get(target_id)
    if hist is None:
        hist = deque(maxlen=_HISTORY_MAXLEN)
        HISTORY[target_id] = hist
    return hist


async def ping_ip(ip: str):
    """Sends 1 ICMP packet (2s timeout). Returns (ok, latency_ms|None)."""
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", "2", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    ok = proc.returncode == 0
    latency = None
    if ok:
        match = _PING_TIME_RE.search(stdout)
        if match:
            try:
                latency = float(match.group(1))
            except ValueError:
                latency = None
    return ok, latency


def _window_stats(target_id: int, window: int):
    hist = _history_for(target_id)
    recent = list(hist)[-window:] if window > 0 else list(hist)
    if not recent:
        return None, 0.0
    ok_latencies = [lat for ok, lat in recent if ok and lat is not None]
    avg_latency = sum(ok_latencies) / len(ok_latencies) if ok_latencies else None
    failures = sum(1 for ok, _ in recent if not ok)
    loss_pct = round((failures / len(recent)) * 100, 1)
    return avg_latency, loss_pct


async def _check_target(target, settings, now):
    target_id = target["id"]
    name = target["name"]
    ip = target["ip"]
    failures = target["consecutive_failures"]
    status = target["status"]
    alert_sent = target["alert_sent"]
    loss_alert_sent = target["loss_alert_sent"] or 0

    is_up, latency = await ping_ip(ip)
    _history_for(target_id).append((is_up, latency))

    window = settings["packet_loss_window"]
    fail_threshold = settings["fail_threshold"]
    loss_threshold = settings["packet_loss_threshold_pct"]
    avg_latency, loss_pct = _window_stats(target_id, window)

    new_status = status
    new_failures = failures
    new_alert_sent = alert_sent
    new_loss_alert_sent = loss_alert_sent
    telegram_messages = []

    if is_up:
        new_failures = 0
        new_alert_sent = 0
        if status == "DOWN":
            new_status = "UP"
            telegram_messages.append(
                f"🟢 <b>[RECOVERED]</b> Host <b>{name}</b> ({ip}) está online novamente!"
            )
    else:
        new_failures = failures + 1
        if new_failures >= fail_threshold:
            new_status = "DOWN"
            if alert_sent == 0:
                telegram_messages.append(
                    f"🚨 <b>[ALERT - DOWN]</b> Host <b>{name}</b> ({ip}) sem resposta ICMP "
                    f"há {fail_threshold * 15}s aprox!"
                )
                new_alert_sent = 1

    # Packet-loss alert is independent from the full-DOWN alert above.
    if new_status != "DOWN" and loss_threshold > 0:
        if loss_pct >= loss_threshold:
            if loss_alert_sent == 0:
                telegram_messages.append(
                    f"⚠️ <b>[ALERTA - PERDA DE PACOTES]</b> Host <b>{name}</b> ({ip}) com "
                    f"<b>{loss_pct}%</b> de perda nos últimos {min(len(_history_for(target_id)), window)} pings!"
                )
                new_loss_alert_sent = 1
        else:
            # Hysteresis: only send recovery alert if loss drops below half of loss_threshold (e.g. <= 10% when threshold is 20%)
            recovery_threshold = max(0.0, loss_threshold / 2)
            if loss_alert_sent == 1 and loss_pct <= recovery_threshold:
                telegram_messages.append(
                    f"🟢 <b>[NORMALIZADO - PERDA DE PACOTES]</b> Host <b>{name}</b> ({ip}) "
                    f"normalizou a perda de pacotes (atual: <b>{loss_pct}%</b>)!"
                )
                new_loss_alert_sent = 0
            elif loss_alert_sent == 1:
                # Retain loss_alert_sent = 1 while loss is between recovery_threshold and loss_threshold to avoid flapping
                new_loss_alert_sent = 1
    else:
        new_loss_alert_sent = 0

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """UPDATE ping_targets
               SET consecutive_failures=?, status=?, last_check=?, alert_sent=?,
                   latency_ms=?, avg_latency_ms=?, packet_loss_pct=?, loss_alert_sent=?
               WHERE id=?""",
            (new_failures, new_status, now, new_alert_sent,
             latency, avg_latency, loss_pct, new_loss_alert_sent, target_id),
        )
        conn.commit()
    finally:
        conn.close()

    for msg in telegram_messages:
        await send_telegram(msg)


async def icmp_worker():
    while True:
        settings = get_settings_typed()
        interval = settings["ping_interval_seconds"]
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM ping_targets WHERE active=1")
            targets = c.fetchall()
            conn.close()

            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Ping every active target concurrently so the cycle stays close to
            # `interval` regardless of how many hosts are being monitored.
            await asyncio.gather(
                *(_check_target(t, settings, now) for t in targets),
                return_exceptions=True,
            )
        except Exception as e:
            print(f"[ICMP Worker Error] {e}")

        await asyncio.sleep(interval)


def snapshot_for_target(target_row) -> dict:
    """Merges a DB row with in-memory history into a JSON-friendly dict for the API."""
    target_id = target_row["id"]
    hist = list(_history_for(target_id))[-30:]
    is_active = bool(target_row["active"]) if "active" in target_row.keys() else True
    return {
        "id": target_id,
        "name": target_row["name"],
        "ip": target_row["ip"],
        "active": is_active,
        "status": target_row["status"] if is_active else "INACTIVE",
        "consecutive_failures": target_row["consecutive_failures"],
        "last_check": target_row["last_check"],
        "latency_ms": target_row["latency_ms"],
        "avg_latency_ms": target_row["avg_latency_ms"],
        "packet_loss_pct": target_row["packet_loss_pct"] or 0,
        "history": [{"ok": bool(ok), "latency": lat} for ok, lat in hist],
    }
