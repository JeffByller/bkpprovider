from fastapi import APIRouter, Body, Depends, HTTPException

from app.auth import require_auth
from app.db import get_db
from app.monitor import snapshot_for_target

router = APIRouter(prefix="/api/targets", dependencies=[Depends(require_auth)])


@router.get("")
async def list_targets():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM ping_targets ORDER BY name COLLATE NOCASE")
        rows = c.fetchall()
    finally:
        conn.close()
    return [snapshot_for_target(r) for r in rows]


@router.post("")
async def create_target(payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    ip = (payload.get("ip") or "").strip()
    if not name or not ip:
        raise HTTPException(status_code=400, detail="Nome e IP são obrigatórios")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO ping_targets (name, ip) VALUES (?, ?)", (name, ip))
        conn.commit()
        new_id = c.lastrowid
    finally:
        conn.close()
    return {"ok": True, "id": new_id}


@router.put("/{target_id}")
async def update_target(target_id: int, payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    ip = (payload.get("ip") or "").strip()
    if not name or not ip:
        raise HTTPException(status_code=400, detail="Nome e IP são obrigatórios")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE ping_targets SET name=?, ip=? WHERE id=?", (name, ip, target_id))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.delete("/{target_id}")
async def delete_target(target_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM ping_targets WHERE id=?", (target_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post("/{target_id}/toggle")
async def toggle_target(target_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT active FROM ping_targets WHERE id=?", (target_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alvo não encontrado")
        new_active = 0 if row["active"] else 1
        c.execute(
            "UPDATE ping_targets SET active=?, consecutive_failures=0, alert_sent=0, loss_alert_sent=0 WHERE id=?",
            (new_active, target_id),
        )
        if not new_active:
            c.execute("UPDATE ping_targets SET status='UP' WHERE id=?", (target_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "active": bool(new_active)}
