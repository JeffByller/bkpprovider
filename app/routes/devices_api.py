import glob
import json
import os

from fastapi import APIRouter, Body, Cookie, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response

from app.auth import check_password, is_authenticated, require_auth
from app.config import BACKUPS_DIR
from app.crypto import encrypt_secret
from app.db import get_db, prune_command_logs
from app.license import extract_client_ip
from app.mikrotik import (
    QUICK_ACTIONS,
    analyze_device_failover,
    clean_device_name,
    configure_device_failover,
    execute_device_command,
    handle_failover_webhook_event,
    probe_device_ssh,
    run_all_backups,
    run_backup_for_device,
    toggle_device_failover_netwatch,
)
from app.monitor import get_history_for_device
from app.snmp import collect_device_metrics, provision_device_snmp
from app.telegram import send_telegram

router = APIRouter(prefix="/api/devices", dependencies=[Depends(require_auth)])
download_router = APIRouter()


def _device_files(clean_name: str, ip: str, limit: int = 10) -> list[dict]:
    if not os.path.exists(BACKUPS_DIR):
        return []
    # Match both exact clean_name_ip_*.txt and any *_{ip}_*.txt from legacy names
    exact = glob.glob(os.path.join(BACKUPS_DIR, f"{clean_name}_{ip}_*.txt"))
    by_ip = glob.glob(os.path.join(BACKUPS_DIR, f"*_{ip}_*.txt"))
    merged = sorted(set(exact + by_ip), reverse=True)[:limit]
    out = []
    for fpath in merged:
        fname = os.path.basename(fpath)
        try:
            st = os.stat(fpath)
            size_kb = round(st.st_size / 1024.0, 1)
        except Exception:
            size_kb = 0.0
        out.append({"filename": fname, "size_kb": size_kb})
    return out


def _device_snapshot(dev) -> dict:
    clean_name = clean_device_name(dev["name"])
    is_active = bool(dev["active"])
    icmp_on = bool(dev["icmp_enabled"])
    files_info = _device_files(clean_name, dev["ip"])
    try:
        interfaces = json.loads(dev["interfaces_json"] or "[]")
    except Exception:
        interfaces = []

    if not is_active:
        effective_status = "INACTIVE"
    elif not icmp_on:
        effective_status = "UNMONITORED"
    else:
        effective_status = dev["status"] or "UP"

    return {
        "id": dev["id"],
        "name": dev["name"],
        "ip": dev["ip"],
        "device_type": dev["device_type"] or "mikrotik",
        "ros_version": dev["ros_version"] or "auto",
        "ros_version_detail": dev["ros_version_detail"] or "",
        "board_name": dev["board_name"] or "",
        "architecture": dev["architecture"] or "",
        "ssh_port": dev["ssh_port"] or 22,
        "ssh_username": dev["ssh_username"] or "",
        "has_password": bool(dev["ssh_password"]),
        "ssh_host_key": dev["ssh_host_key"] or "",
        "active": is_active,
        "icmp_enabled": icmp_on,
        "backup_enabled": bool(dev["backup_enabled"]),
        "ssh_enabled": bool(dev["ssh_enabled"]),
        "snmp_enabled": bool(dev["snmp_enabled"]),
        "snmp_auto_poll": bool(dev["snmp_auto_poll"]) if "snmp_auto_poll" in dev.keys() else False,
        "snmp_auto_until": (dev["snmp_auto_until"] or "") if "snmp_auto_until" in dev.keys() else "",
        "snmp_version": dev["snmp_version"] or "2c",
        "snmp_port": dev["snmp_port"] or 161,
        "snmp_community": dev["snmp_community"] or "public",
        "snmp_status": dev["snmp_status"] or "UNCONFIGURED",
        "snmp_last_error": dev["snmp_last_error"] or "",
        "snmp_last_check": dev["snmp_last_check"] or "",
        "telegram_destination_id": dev["telegram_destination_id"],
        "notes": dev["notes"] or "",
        "status": effective_status,
        "consecutive_failures": dev["consecutive_failures"] or 0,
        "latency_ms": dev["latency_ms"],
        "avg_latency_ms": dev["avg_latency_ms"],
        "last_check": dev["last_check"] or "",
        "last_seen_up": dev["last_seen_up"] or "",
        "history": get_history_for_device(dev["id"]),
        "last_backup": dev["last_backup"] or "",
        "last_backup_status": dev["last_backup_status"] or "PENDING",
        "last_backup_message": dev["last_backup_message"] or "",
        "files": [f["filename"] for f in files_info],
        "files_detail": files_info,
        "cpu_load": dev["cpu_load"],
        "memory_used_pct": dev["memory_used_pct"],
        "memory_total_mb": dev["memory_total_mb"],
        "memory_used_mb": dev["memory_used_mb"],
        "uptime_str": dev["uptime_str"] or "",
        "rx_bps": dev["rx_bps"] or 0,
        "tx_bps": dev["tx_bps"] or 0,
        "interfaces": interfaces,
    }


@router.get("")
@download_router.get("/api/targets", dependencies=[Depends(require_auth)])
async def list_devices():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices ORDER BY name COLLATE NOCASE")
        rows = c.fetchall()
    finally:
        conn.close()
    return [_device_snapshot(d) for d in rows]


@router.get("/ssh/actions")
async def list_ssh_quick_actions():
    return [
        {
            "key": k,
            "label": v["label"],
            "description": v["description"],
            "requires_param": bool(v.get("requires_param")),
            "param_label": v.get("param_label", ""),
        }
        for k, v in QUICK_ACTIONS.items()
    ]


@router.get("/backups/history")
async def get_backup_history(
    device_id: int = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
):
    conn = get_db()
    try:
        c = conn.cursor()
        if device_id:
            c.execute("SELECT COUNT(*) AS cnt FROM backup_history WHERE device_id=?", (device_id,))
            total = int(c.fetchone()["cnt"] or 0)
        else:
            c.execute("SELECT COUNT(*) AS cnt FROM backup_history")
            total = int(c.fetchone()["cnt"] or 0)

        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * page_size

        if device_id:
            c.execute(
                "SELECT * FROM backup_history WHERE device_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
                (device_id, page_size, offset),
            )
        else:
            c.execute(
                "SELECT * FROM backup_history ORDER BY id DESC LIMIT ? OFFSET ?",
                (page_size, offset),
            )
        rows = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()
    return {
        "items": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.get("/backups/view")
async def view_backup_file(
    filename: str = Query(...),
    password: str = Query(None),
):
    if not password or not check_password(password):
        raise HTTPException(status_code=403, detail="Senha incorreta")
    safe_filename = os.path.basename(filename)
    if ".." in safe_filename or "/" in safe_filename or not safe_filename.endswith(".txt"):
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido")
    file_path = os.path.join(BACKUPS_DIR, safe_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Arquivo de backup não encontrado")
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(500_000)
        size_bytes = os.path.getsize(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao ler arquivo: {e}")
    return {"filename": safe_filename, "size_bytes": size_bytes, "content": content}


@router.get("/ssh/logs")
async def get_command_audit_logs(
    device_id: int = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
):
    conn = get_db()
    try:
        c = conn.cursor()
        prune_command_logs(c, 200)
        if c.rowcount and c.rowcount > 0:
            conn.commit()

        if device_id:
            c.execute("SELECT COUNT(*) AS cnt FROM command_logs WHERE device_id=?", (device_id,))
            total = int(c.fetchone()["cnt"] or 0)
        else:
            c.execute("SELECT COUNT(*) AS cnt FROM command_logs")
            total = int(c.fetchone()["cnt"] or 0)

        total_pages = max(1, (total + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * page_size

        if device_id:
            c.execute(
                "SELECT * FROM command_logs WHERE device_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
                (device_id, page_size, offset),
            )
        else:
            c.execute(
                "SELECT * FROM command_logs ORDER BY id DESC LIMIT ? OFFSET ?",
                (page_size, offset),
            )
        rows = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    return {
        "items": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.post("")
async def create_device(payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    ip = (payload.get("ip") or "").strip()
    if not name or not ip:
        raise HTTPException(status_code=400, detail="Nome e IP/Hostname são obrigatórios.")

    device_type = (payload.get("device_type") or "mikrotik").strip()
    ros_version = (payload.get("ros_version") or "auto").strip()
    ssh_port = int(payload.get("ssh_port") or payload.get("port") or 2250)
    ssh_username = (payload.get("ssh_username") or payload.get("username") or "gerabackup").strip()
    raw_password = (payload.get("ssh_password") or payload.get("password") or "gerabackup").strip()

    icmp_enabled = 1 if payload.get("icmp_enabled", True) else 0
    backup_enabled = 1 if payload.get("backup_enabled", False) else 0
    ssh_enabled = 1 if payload.get("ssh_enabled", False) else 0
    snmp_enabled = 1 if payload.get("snmp_enabled", False) else 0
    active = 1 if payload.get("active", True) else 0

    if (backup_enabled or ssh_enabled) and (not ssh_username or not raw_password):
        raise HTTPException(
            status_code=400,
            detail="Para habilitar Backup ou Acesso SSH, informe o Usuário e a Senha SSH do equipamento.",
        )

    snmp_community = (payload.get("snmp_community") or "@BKP2712").strip()
    snmp_port = int(payload.get("snmp_port") or 161)
    snmp_version = (payload.get("snmp_version") or "2c").strip()
    dest_id = payload.get("telegram_destination_id")
    if dest_id == "":
        dest_id = None
    notes = (payload.get("notes") or "").strip()

    enc_password = encrypt_secret(raw_password) if raw_password else ""

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO devices (
                name, ip, device_type, ros_version, ssh_port, ssh_username, ssh_password,
                icmp_enabled, backup_enabled, ssh_enabled, snmp_enabled,
                snmp_community, snmp_port, snmp_version,
                active, telegram_destination_id, notes,
                last_backup_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                ip,
                device_type,
                ros_version,
                ssh_port,
                ssh_username,
                enc_password,
                icmp_enabled,
                backup_enabled,
                ssh_enabled,
                snmp_enabled,
                snmp_community,
                snmp_port,
                snmp_version,
                active,
                dest_id,
                notes,
                "PENDING" if backup_enabled else "DISABLED",
            ),
        )
        conn.commit()
        new_id = c.lastrowid
        c.execute("SELECT * FROM devices WHERE id=?", (new_id,))
        dev_row = dict(c.fetchone())
    finally:
        conn.close()

    # If SSH credentials were provided and version is auto, trigger background discovery
    if (ssh_enabled or backup_enabled) and ssh_username and raw_password:
        try:
            await probe_device_ssh(dev_row)
        except Exception:
            pass

    return {"ok": True, "id": new_id}


@router.put("/{device_id}")
async def update_device(device_id: int, payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    ip = (payload.get("ip") or "").strip()
    if not name or not ip:
        raise HTTPException(status_code=400, detail="Nome e IP/Hostname são obrigatórios.")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        existing = c.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

        device_type = (payload.get("device_type") or existing["device_type"] or "mikrotik").strip()
        ros_version = (payload.get("ros_version") or existing["ros_version"] or "auto").strip()
        ssh_port = int(payload.get("ssh_port") or payload.get("port") or existing["ssh_port"] or 22)
        ssh_username = (payload.get("ssh_username") if "ssh_username" in payload else payload.get("username", existing["ssh_username"]) or "").strip()
        raw_password = (payload.get("ssh_password") if "ssh_password" in payload else payload.get("password") or "").strip()

        enc_password = encrypt_secret(raw_password) if raw_password else existing["ssh_password"]

        icmp_enabled = 1 if payload.get("icmp_enabled", bool(existing["icmp_enabled"])) else 0
        backup_enabled = 1 if payload.get("backup_enabled", bool(existing["backup_enabled"])) else 0
        ssh_enabled = 1 if payload.get("ssh_enabled", bool(existing["ssh_enabled"])) else 0
        snmp_enabled = 1 if payload.get("snmp_enabled", bool(existing["snmp_enabled"])) else 0
        active = 1 if payload.get("active", bool(existing["active"])) else 0

        if (backup_enabled or ssh_enabled) and (not ssh_username or not enc_password):
            raise HTTPException(
                status_code=400,
                detail="Para habilitar Backup ou Acesso SSH, informe o Usuário e a Senha SSH do equipamento.",
            )

        snmp_community = (payload.get("snmp_community") or existing["snmp_community"] or "public").strip()
        snmp_port = int(payload.get("snmp_port") or existing["snmp_port"] or 161)
        snmp_version = (payload.get("snmp_version") or existing["snmp_version"] or "2c").strip()
        dest_id = payload.get("telegram_destination_id") if "telegram_destination_id" in payload else existing["telegram_destination_id"]
        if dest_id == "":
            dest_id = None
        notes = (payload.get("notes") if "notes" in payload else existing["notes"] or "").strip()

        c.execute(
            """
            UPDATE devices
            SET name=?, ip=?, device_type=?, ros_version=?,
                ssh_port=?, ssh_username=?, ssh_password=?,
                icmp_enabled=?, backup_enabled=?, ssh_enabled=?, snmp_enabled=?,
                snmp_community=?, snmp_port=?, snmp_version=?,
                active=?, telegram_destination_id=?, notes=?
            WHERE id=?
            """,
            (
                name,
                ip,
                device_type,
                ros_version,
                ssh_port,
                ssh_username,
                enc_password,
                icmp_enabled,
                backup_enabled,
                ssh_enabled,
                snmp_enabled,
                snmp_community,
                snmp_port,
                snmp_version,
                active,
                dest_id,
                notes,
                device_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {"ok": True}


@router.delete("/{device_id}")
async def delete_device(device_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM device_metrics WHERE device_id=?", (device_id,))
        c.execute("DELETE FROM devices WHERE id=?", (device_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post("/{device_id}/toggle")
async def toggle_device(device_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT active FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
        new_active = 0 if row["active"] else 1
        c.execute(
            "UPDATE devices SET active=?, consecutive_failures=0, alert_sent=0 WHERE id=?",
            (new_active, device_id),
        )
        if not new_active:
            c.execute("UPDATE devices SET status='UP' WHERE id=?", (device_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "active": bool(new_active)}


@router.post("/{device_id}/probe-ssh")
async def probe_ssh_endpoint(device_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    ok, info, msg = await probe_device_ssh(dict(row))
    return {"ok": ok, "info": info, "message": msg}


@router.post("/{device_id}/backup-now")
async def backup_now(device_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        dev = c.fetchone()
    finally:
        conn.close()

    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    success, msg = await run_backup_for_device(dict(dev), manual=True)
    return {"ok": success, "message": msg}


@router.post("/backup-all")
async def trigger_all_backups():
    await run_all_backups()
    return {"ok": True, "message": "Rotina de backup em lote executada para todos os dispositivos habilitados."}


@router.post("/{device_id}/ssh/execute")
async def execute_ssh_action(device_id: int, request: Request, payload: dict = Body(...)):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    action_key = (payload.get("action_key") or "").strip()
    target_param = (payload.get("target_param") or "").strip()
    custom_cmd = (payload.get("custom_cmd") or "").strip()
    client_ip = extract_client_ip(request)

    result = await execute_device_command(
        dict(row),
        action_key=action_key,
        target_param=target_param,
        custom_cmd=custom_cmd,
        client_ip=client_ip,
    )
    return result


@router.post("/{device_id}/failover/analyze")
async def analyze_failover_endpoint(device_id: int, request: Request):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    client_ip = extract_client_ip(request)
    return await analyze_device_failover(dict(row), client_ip=client_ip)


@router.post("/{device_id}/failover/configure")
async def configure_failover_endpoint(device_id: int, request: Request, payload: dict = Body(...)):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    client_ip = extract_client_ip(request)
    return await configure_device_failover(dict(row), payload=payload, client_ip=client_ip)


@router.post("/{device_id}/failover/toggle-netwatch")
async def toggle_failover_netwatch_endpoint(device_id: int, request: Request, payload: dict = Body(...)):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    enable = bool(payload.get("enable", True))
    client_ip = extract_client_ip(request)
    return await toggle_device_failover_netwatch(dict(row), enable=enable, client_ip=client_ip)


@router.post("/{device_id}/failover/test-telegram")
async def test_failover_telegram_endpoint(device_id: int):
    import datetime as dt

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    dev = dict(row)
    now_str = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"🔔 <b>[TESTE DE ALERTA DE FAILOVER]</b>\n"
        f"Equipamento: <b>{dev['name']}</b> (<code>{dev['ip']}</code>)\n"
        f"Status: Notificação de troca de link (Netwatch ➔ Telegram) configurada e operacional!\n"
        f"Horário: <code>{now_str}</code>"
    )
    await send_telegram(msg, dev.get("telegram_destination_id"))
    return {"ok": True, "message": "Mensagem de teste enviada para o Telegram configurado neste equipamento!"}


@download_router.get("/api/devices/failover-event/{device_id}/{link_role}/{state}/{token}")
async def device_failover_webhook_get(
    device_id: int,
    link_role: str,
    state: str,
    token: str,
    request: Request,
):
    client_ip = extract_client_ip(request)
    return await handle_failover_webhook_event(device_id, link_role, state, token, client_ip=client_ip)


@router.post("/{device_id}/snmp/provision")
async def provision_snmp_endpoint(device_id: int, request: Request, payload: dict = Body(...)):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    from app.db import get_setting
    default_allowed_ip = get_setting("snmp_allowed_ip", "38.225.221.159") or "38.225.221.159"
    community = (payload.get("snmp_community") or row["snmp_community"] or "public").strip()
    snmp_port = int(payload.get("snmp_port") or row["snmp_port"] or 161)
    allowed_ip = (payload.get("allowed_ip") or default_allowed_ip).strip()
    allow_firewall = bool(payload.get("allow_firewall", True))
    client_ip = extract_client_ip(request)

    res = await provision_device_snmp(
        dict(row),
        community=community,
        snmp_port=snmp_port,
        allowed_ip=allowed_ip,
        allow_firewall=allow_firewall,
        client_ip=client_ip,
    )
    return res


@router.post("/{device_id}/snmp/poll-now")
async def poll_snmp_now_endpoint(device_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    dev = dict(row)
    ok, data, msg = await collect_device_metrics(dev)
    if ok:
        import datetime as dt
        now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute(
                """
                UPDATE devices
                SET snmp_status='OK', snmp_last_error='', snmp_last_check=?,
                    uptime_str=?, cpu_load=?, memory_total_mb=?, memory_used_mb=?,
                    memory_used_pct=?, rx_bps=?, tx_bps=?, interfaces_json=?
                WHERE id=?
                """,
                (
                    now,
                    data.get("uptime_str") or dev.get("uptime_str") or "",
                    data.get("cpu_load"),
                    data.get("memory_total_mb"),
                    data.get("memory_used_mb"),
                    data.get("memory_used_pct"),
                    data.get("rx_bps", 0),
                    data.get("tx_bps", 0),
                    json.dumps(data.get("interfaces", []), ensure_ascii=False),
                    device_id,
                ),
            )
            c.execute(
                """
                INSERT INTO device_metrics (device_id, timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    now,
                    dev.get("latency_ms"),
                    data.get("cpu_load"),
                    data.get("memory_used_pct"),
                    data.get("rx_bps", 0),
                    data.get("tx_bps", 0),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    return {"ok": ok, "metrics": data, "message": msg}


@router.post("/{device_id}/snmp/auto-poll")
async def set_device_snmp_auto_poll(device_id: int, payload: dict = Body(...)):
    import datetime as dt

    enabled = bool(payload.get("enabled", False))
    duration_hours = float(payload.get("duration_hours") or 0)

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

        auto_until = None
        if enabled:
            if duration_hours > 0:
                auto_until = (dt.datetime.now() + dt.timedelta(hours=duration_hours)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "UPDATE devices SET snmp_enabled=1, snmp_auto_poll=1, snmp_auto_until=? WHERE id=?",
                (auto_until, device_id),
            )
        else:
            c.execute(
                "UPDATE devices SET snmp_auto_poll=0, snmp_auto_until=NULL WHERE id=?",
                (device_id,),
            )
        conn.commit()
    finally:
        conn.close()

    if enabled:
        # Trigger an immediate collection sample so the analysis starts with fresh data right away
        await poll_snmp_now_endpoint(device_id)

    return {
        "ok": True,
        "snmp_auto_poll": enabled,
        "snmp_auto_until": auto_until or "",
        "message": (
            f"Coleta automática ativada{' até ' + auto_until if auto_until else ' (contínua até desativar)'}."
            if enabled
            else "Coleta automática desativada (apenas coleta manual sob demanda)."
        ),
    }


def _compute_metrics_summary(points: list[dict]) -> dict:
    if not points:
        return {
            "samples_count": 0,
            "period_start": "",
            "period_end": "",
            "cpu_avg": None,
            "cpu_max": None,
            "cpu_peak_at": "",
            "mem_avg": None,
            "mem_max": None,
            "mem_peak_at": "",
            "lat_avg": None,
            "lat_max": None,
            "lat_peak_at": "",
            "rx_avg_bps": 0,
            "rx_max_bps": 0,
            "rx_peak_at": "",
            "tx_avg_bps": 0,
            "tx_max_bps": 0,
            "tx_peak_at": "",
        }

    cpus = [(p["cpu_load"], p["timestamp"]) for p in points if p.get("cpu_load") is not None]
    mems = [(p["memory_used_pct"], p["timestamp"]) for p in points if p.get("memory_used_pct") is not None]
    lats = [(p["latency_ms"], p["timestamp"]) for p in points if p.get("latency_ms") is not None]
    rxs = [(int(p.get("rx_bps") or 0), p["timestamp"]) for p in points]
    txs = [(int(p.get("tx_bps") or 0), p["timestamp"]) for p in points]

    cpu_peak = max(cpus, key=lambda x: x[0]) if cpus else (None, "")
    mem_peak = max(mems, key=lambda x: x[0]) if mems else (None, "")
    lat_peak = max(lats, key=lambda x: x[0]) if lats else (None, "")
    rx_peak = max(rxs, key=lambda x: x[0]) if rxs else (0, "")
    tx_peak = max(txs, key=lambda x: x[0]) if txs else (0, "")

    return {
        "samples_count": len(points),
        "period_start": points[0].get("timestamp") or "",
        "period_end": points[-1].get("timestamp") or "",
        "cpu_avg": round(sum(x[0] for x in cpus) / len(cpus), 1) if cpus else None,
        "cpu_max": cpu_peak[0],
        "cpu_peak_at": cpu_peak[1],
        "mem_avg": round(sum(x[0] for x in mems) / len(mems), 1) if mems else None,
        "mem_max": round(mem_peak[0], 1) if mem_peak[0] is not None else None,
        "mem_peak_at": mem_peak[1],
        "lat_avg": round(sum(x[0] for x in lats) / len(lats), 1) if lats else None,
        "lat_max": round(lat_peak[0], 1) if lat_peak[0] is not None else None,
        "lat_peak_at": lat_peak[1],
        "rx_avg_bps": int(sum(x[0] for x in rxs) / len(rxs)) if rxs else 0,
        "rx_max_bps": rx_peak[0],
        "rx_peak_at": rx_peak[1],
        "tx_avg_bps": int(sum(x[0] for x in txs) / len(txs)) if txs else 0,
        "tx_max_bps": tx_peak[0],
        "tx_peak_at": tx_peak[1],
    }


@router.get("/{device_id}/metrics")
async def get_device_metrics_history(
    device_id: int,
    hours: float = Query(24),
    limit: int = Query(500),
):
    import datetime as dt

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        dev = c.fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

        safe_limit = min(max(limit, 10), 2000)
        if hours and hours > 0:
            cutoff = (dt.datetime.now() - dt.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                """
                SELECT timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps
                FROM device_metrics
                WHERE device_id=? AND timestamp >= ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, cutoff, safe_limit),
            )
        else:
            c.execute(
                """
                SELECT timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps
                FROM device_metrics
                WHERE device_id=?
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, safe_limit),
            )
        points = [dict(r) for r in reversed(c.fetchall())]
    finally:
        conn.close()

    return {
        "device": _device_snapshot(dev),
        "series": points,
        "summary": _compute_metrics_summary(points),
    }


@router.delete("/{device_id}/metrics")
async def clear_device_metrics_history(device_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM device_metrics WHERE device_id=?", (device_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "message": "Histórico de métricas do dispositivo limpo."}


@router.get("/{device_id}/metrics/export")
async def export_device_metrics_csv(device_id: int, hours: float = Query(24)):
    import datetime as dt

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        dev = c.fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

        if hours and hours > 0:
            cutoff = (dt.datetime.now() - dt.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                """
                SELECT timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps
                FROM device_metrics
                WHERE device_id=? AND timestamp >= ?
                ORDER BY id ASC
                """,
                (device_id, cutoff),
            )
        else:
            c.execute(
                """
                SELECT timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps
                FROM device_metrics
                WHERE device_id=?
                ORDER BY id ASC
                """,
                (device_id,),
            )
        points = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    summary = _compute_metrics_summary(points)
    clean_name = clean_device_name(dev["name"])
    now_str = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"relatorio_snmp_{clean_name}_{now_str}.csv"

    lines = [
        f"# Relatorio de Analise SNMP - {dev['name']} ({dev['ip']})",
        f"# RouterOS: {dev['ros_version_detail'] or dev['ros_version']} | Modelo: {dev['board_name'] or '-'}",
        f"# Amostras: {summary['samples_count']} | Inicio: {summary['period_start'] or '-'} | Fim: {summary['period_end'] or '-'}",
        f"# CPU Media: {summary['cpu_avg'] if summary['cpu_avg'] is not None else '-'}% | CPU Pico: {summary['cpu_max'] if summary['cpu_max'] is not None else '-'}% ({summary['cpu_peak_at'] or '-'})",
        f"# Memoria Media: {summary['mem_avg'] if summary['mem_avg'] is not None else '-'}% | Memoria Pico: {summary['mem_max'] if summary['mem_max'] is not None else '-'}%",
        f"# Download RX Medio: {round(summary['rx_avg_bps'] / 1_000_000, 2)} Mbps | Pico RX: {round(summary['rx_max_bps'] / 1_000_000, 2)} Mbps ({summary['rx_peak_at'] or '-'})",
        f"# Upload TX Medio: {round(summary['tx_avg_bps'] / 1_000_000, 2)} Mbps | Pico TX: {round(summary['tx_max_bps'] / 1_000_000, 2)} Mbps ({summary['tx_peak_at'] or '-'})",
        "Data_Hora,Latencia_ms,CPU_pct,Memoria_pct,Download_RX_bps,Download_RX_Mbps,Upload_TX_bps,Upload_TX_Mbps",
    ]
    for p in points:
        rx_b = int(p.get("rx_bps") or 0)
        tx_b = int(p.get("tx_bps") or 0)
        lines.append(
            f"{p.get('timestamp') or ''},"
            f"{p.get('latency_ms') if p.get('latency_ms') is not None else ''},"
            f"{p.get('cpu_load') if p.get('cpu_load') is not None else ''},"
            f"{p.get('memory_used_pct') if p.get('memory_used_pct') is not None else ''},"
            f"{rx_b},{round(rx_b / 1_000_000, 3)},"
            f"{tx_b},{round(tx_b / 1_000_000, 3)}"
        )

    csv_bytes = ("\n".join(lines) + "\n").encode("utf-8-sig")
    return Response(
        content=csv_bytes,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@download_router.get("/mikrotik/download")
async def download_backup(
    filename: str = Query(...),
    password: str = Query(None),
    session_token: str = Cookie(None),
):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    if not password or not check_password(password):
        raise HTTPException(status_code=403, detail="Senha incorreta")

    safe_filename = os.path.basename(filename)
    if ".." in safe_filename or "/" in safe_filename:
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido")
    file_path = os.path.join(BACKUPS_DIR, safe_filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Arquivo de backup não encontrado")

    return FileResponse(file_path, filename=safe_filename, media_type="application/octet-stream")
