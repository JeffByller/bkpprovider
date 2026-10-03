import datetime
from fastapi import APIRouter, Body, Depends, HTTPException

from app.auth import require_auth
from app.db import get_db
from app.license import (
    format_relative_time,
    generate_license_key,
    is_license_expired,
    stream_manager,
)

router = APIRouter(prefix="/api/licenses", dependencies=[Depends(require_auth)])


def _license_snapshot(row) -> dict:
    expired = is_license_expired(row["expires_at"])
    raw_status = row["status"] or "ACTIVE"
    if raw_status == "BLOCKED":
        effective_status = "BLOCKED"
    elif expired:
        effective_status = "EXPIRED"
    else:
        effective_status = "ACTIVE"

    is_online = stream_manager.is_online(row["license_key"])

    return {
        "id": row["id"],
        "client_name": row["client_name"],
        "license_key": row["license_key"],
        "status": raw_status,
        "effective_status": effective_status,
        "is_expired": expired,
        "is_online": is_online,
        "allowed_domain": row["allowed_domain"] or "",
        "expires_at": row["expires_at"] or "",
        "notes": row["notes"] or "",
        "created_at": row["created_at"],
        "last_check_at": row["last_check_at"] or "",
        "last_check_relative": format_relative_time(row["last_check_at"]),
        "last_ip": row["last_ip"] or "",
        "last_hostname": row["last_hostname"] or "",
        "last_version": row["last_version"] or "",
        "total_checks": row["total_checks"] or 0,
    }


@router.get("")
async def list_licenses():
    """Lists all software licenses."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM licenses ORDER BY id DESC")
        rows = c.fetchall()
        return [_license_snapshot(r) for r in rows]
    finally:
        conn.close()


@router.get("/generate-key")
async def get_random_key():
    """Utility endpoint to generate a fresh license key string."""
    return {"license_key": generate_license_key()}


@router.post("")
async def create_license(payload: dict = Body(...)):
    """Creates a new software license."""
    client_name = (payload.get("client_name") or "").strip()
    license_key = (payload.get("license_key") or "").strip().upper()
    status = (payload.get("status") or "ACTIVE").strip().upper()
    allowed_domain = (payload.get("allowed_domain") or "").strip().lower()
    expires_at = (payload.get("expires_at") or "").strip() or None
    notes = (payload.get("notes") or "").strip()

    if not client_name:
        raise HTTPException(status_code=400, detail="O nome do cliente/aplicação é obrigatório.")

    if not license_key:
        license_key = generate_license_key()

    if status not in ("ACTIVE", "BLOCKED"):
        status = "ACTIVE"

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM licenses WHERE UPPER(license_key) = ?", (license_key,))
        if c.fetchone():
            raise HTTPException(status_code=400, detail=f"A chave '{license_key}' já está em uso.")

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            """
            INSERT INTO licenses (client_name, license_key, status, allowed_domain, expires_at, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (client_name, license_key, status, allowed_domain, expires_at, notes, now_str),
        )
        conn.commit()
        new_id = c.lastrowid
        return {"ok": True, "id": new_id, "license_key": license_key}
    finally:
        conn.close()


@router.get("/{license_id}")
async def get_license(license_id: int):
    """Gets details for a single license."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM licenses WHERE id = ?", (license_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Licença não encontrada.")
        return _license_snapshot(row)
    finally:
        conn.close()


@router.put("/{license_id}")
async def update_license(license_id: int, payload: dict = Body(...)):
    """Updates an existing license."""
    client_name = (payload.get("client_name") or "").strip()
    license_key = (payload.get("license_key") or "").strip().upper()
    status = (payload.get("status") or "ACTIVE").strip().upper()
    allowed_domain = (payload.get("allowed_domain") or "").strip().lower()
    expires_at = (payload.get("expires_at") or "").strip() or None
    notes = (payload.get("notes") or "").strip()

    if not client_name:
        raise HTTPException(status_code=400, detail="O nome do cliente/aplicação é obrigatório.")

    if not license_key:
        raise HTTPException(status_code=400, detail="A chave de licença não pode ser vazia.")

    if status not in ("ACTIVE", "BLOCKED"):
        status = "ACTIVE"

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM licenses WHERE UPPER(license_key) = ? AND id != ?", (license_key, license_id))
        if c.fetchone():
            raise HTTPException(status_code=400, detail=f"A chave '{license_key}' já está em uso por outra licença.")

        c.execute(
            """
            UPDATE licenses 
            SET client_name = ?, license_key = ?, status = ?, allowed_domain = ?, expires_at = ?, notes = ?
            WHERE id = ?
            """,
            (client_name, license_key, status, allowed_domain, expires_at, notes, license_id),
        )
        conn.commit()

        # Instant real-time push to connected clients
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        await stream_manager.broadcast(
            license_key,
            {
                "event": status,
                "status": status,
                "valid": status == "ACTIVE",
                "client_name": client_name,
                "message": f"Status atualizado para {status}.",
                "server_time": now_str,
            },
        )
        return {"ok": True}
    finally:
        conn.close()


@router.post("/{license_id}/toggle")
async def toggle_license_status(license_id: int):
    """Toggles license status between ACTIVE and BLOCKED."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, status, client_name, license_key FROM licenses WHERE id = ?", (license_id,))
        lic = c.fetchone()
        if not lic:
            raise HTTPException(status_code=404, detail="Licença não encontrada.")

        current_status = lic["status"] or "ACTIVE"
        new_status = "BLOCKED" if current_status == "ACTIVE" else "ACTIVE"

        c.execute("UPDATE licenses SET status = ? WHERE id = ?", (new_status, license_id))
        
        # Log the admin status change
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        action_msg = "Licença BLOQUEADA pelo administrador." if new_status == "BLOCKED" else "Licença DESBLOQUEADA pelo administrador."
        c.execute(
            """
            INSERT INTO license_logs 
            (license_id, license_key, timestamp, ip, hostname, app_version, status_returned, message, details)
            VALUES (?, ?, ?, 'painel', 'admin', 'painel', ?, ?, 'Alteração manual no painel')
            """,
            (license_id, lic["license_key"], now_str, new_status, action_msg),
        )
        conn.commit()

        # Instant real-time push to connected clients!
        await stream_manager.broadcast(
            lic["license_key"],
            {
                "event": new_status,
                "status": new_status,
                "valid": new_status == "ACTIVE",
                "client_name": lic["client_name"],
                "message": action_msg,
                "server_time": now_str,
            },
        )

        return {"ok": True, "new_status": new_status, "client_name": lic["client_name"]}
    finally:
        conn.close()


@router.post("/{license_id}/regenerate-key")
async def regenerate_license_key_endpoint(license_id: int):
    """Generates a new key for this license."""
    new_key = generate_license_key()
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, client_name, license_key FROM licenses WHERE id = ?", (license_id,))
        lic = c.fetchone()
        if not lic:
            raise HTTPException(status_code=404, detail="Licença não encontrada.")

        old_key = lic["license_key"]
        c.execute("UPDATE licenses SET license_key = ? WHERE id = ?", (new_key, license_id))
        
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            """
            INSERT INTO license_logs 
            (license_id, license_key, timestamp, ip, hostname, app_version, status_returned, message, details)
            VALUES (?, ?, ?, 'painel', 'admin', 'painel', 'KEY_ROTATED', 'Chave rotacionada no painel', ?)
            """,
            (license_id, new_key, now_str, f"Antiga chave: {old_key}"),
        )
        conn.commit()
        return {"ok": True, "new_key": new_key}
    finally:
        conn.close()


@router.delete("/{license_id}")
async def delete_license(license_id: int):
    """Deletes a license and its logs."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM license_logs WHERE license_id = ?", (license_id,))
        c.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@router.get("/{license_id}/logs")
async def get_license_logs(license_id: int, limit: int = 100):
    """Retrieves recent communication logs for a specific license."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM licenses WHERE id = ?", (license_id,))
        lic = c.fetchone()
        if not lic:
            raise HTTPException(status_code=404, detail="Licença não encontrada.")

        c.execute(
            """
            SELECT * FROM license_logs 
            WHERE license_id = ? 
            ORDER BY id DESC 
            LIMIT ?
            """,
            (license_id, min(limit, 300)),
        )
        logs = c.fetchall()
        return {
            "license": _license_snapshot(lic),
            "logs": [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "relative_time": format_relative_time(row["timestamp"]),
                    "ip": row["ip"] or "-",
                    "hostname": row["hostname"] or "-",
                    "app_version": row["app_version"] or "-",
                    "status_returned": row["status_returned"],
                    "message": row["message"] or "",
                    "details": row["details"] or "",
                }
                for row in logs
            ],
        }
    finally:
        conn.close()


@router.delete("/{license_id}/logs")
async def clear_license_logs(license_id: int):
    """Clears communication history for this license."""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM license_logs WHERE license_id = ?", (license_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()
