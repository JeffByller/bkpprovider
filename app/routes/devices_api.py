import glob
import os

from fastapi import APIRouter, Body, Cookie, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from app.auth import check_password, is_authenticated, require_auth
from app.config import BACKUPS_DIR
from app.db import get_db
from app.mikrotik import clean_device_name, run_backup_for_device

router = APIRouter(prefix="/api/devices", dependencies=[Depends(require_auth)])

# Kept outside /api (plain GET navigation, not fetch) since it triggers a file download.
download_router = APIRouter()


def _device_files(clean_name: str, ip: str, limit: int = 7):
    if not os.path.exists(BACKUPS_DIR):
        return []
    prefix = f"{clean_name}_{ip}_"
    files = sorted(glob.glob(f"{BACKUPS_DIR}/{prefix}*.txt"), reverse=True)[:limit]
    return [os.path.basename(f) for f in files]


def _device_snapshot(dev) -> dict:
    clean_name = clean_device_name(dev["name"])
    return {
        "id": dev["id"],
        "name": dev["name"],
        "ip": dev["ip"],
        "port": dev["port"],
        "username": dev["username"],
        "last_backup": dev["last_backup"],
        "last_status": dev["last_status"],
        "files": _device_files(clean_name, dev["ip"]),
    }


@router.get("")
async def list_devices():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM mikrotik_devices ORDER BY name COLLATE NOCASE")
        rows = c.fetchall()
    finally:
        conn.close()
    return [_device_snapshot(d) for d in rows]


@router.post("")
async def create_device(payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    ip = (payload.get("ip") or "").strip()
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    port = int(payload.get("port") or 22)
    if not name or not ip or not username or not password:
        raise HTTPException(status_code=400, detail="Nome, IP, usuário e senha são obrigatórios")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO mikrotik_devices (name, ip, port, username, password) VALUES (?, ?, ?, ?, ?)",
            (name, ip, port, username, password),
        )
        conn.commit()
        new_id = c.lastrowid
    finally:
        conn.close()
    return {"ok": True, "id": new_id}


@router.put("/{device_id}")
async def update_device(device_id: int, payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    ip = (payload.get("ip") or "").strip()
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    port = int(payload.get("port") or 22)
    if not name or not ip or not username:
        raise HTTPException(status_code=400, detail="Nome, IP e usuário são obrigatórios")
    conn = get_db()
    try:
        c = conn.cursor()
        if password:
            c.execute(
                "UPDATE mikrotik_devices SET name=?, ip=?, port=?, username=?, password=? WHERE id=?",
                (name, ip, port, username, password, device_id),
            )
        else:
            c.execute(
                "UPDATE mikrotik_devices SET name=?, ip=?, port=?, username=? WHERE id=?",
                (name, ip, port, username, device_id),
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
        c.execute("DELETE FROM mikrotik_devices WHERE id=?", (device_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post("/{device_id}/backup-now")
async def backup_now(device_id: int):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM mikrotik_devices WHERE id=?", (device_id,))
    dev = c.fetchone()
    conn.close()

    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")

    success, msg = await run_backup_for_device(dev, manual=True)
    return {"ok": success, "message": msg}


@download_router.get("/mikrotik/download")
async def download_backup(filename: str = Query(...), password: str = Query(...), session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    if not check_password(password):
        raise HTTPException(status_code=403, detail="Senha incorreta")

    safe_filename = os.path.basename(filename)
    if ".." in safe_filename or "/" in safe_filename:
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido")
    file_path = os.path.join(BACKUPS_DIR, safe_filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Arquivo de backup não encontrado")

    return FileResponse(file_path, filename=safe_filename, media_type="application/octet-stream")
