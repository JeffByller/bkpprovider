from fastapi import APIRouter, Body, Depends, HTTPException

from app.auth import require_auth
from app.db import get_db

router = APIRouter(prefix="/api/telegram_destinations", dependencies=[Depends(require_auth)])

@router.get("")
async def list_destinations():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, name, token, chat_id FROM telegram_destinations ORDER BY name COLLATE NOCASE")
        rows = c.fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]

@router.post("")
async def create_destination(payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    token = (payload.get("token") or "").strip()
    chat_id = (payload.get("chat_id") or "").strip()
    if not name or not token or not chat_id:
        raise HTTPException(status_code=400, detail="Nome, token e chat_id são obrigatórios")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO telegram_destinations (name, token, chat_id) VALUES (?, ?, ?)", (name, token, chat_id))
        conn.commit()
        new_id = c.lastrowid
    finally:
        conn.close()
    return {"ok": True, "id": new_id}

@router.put("/{dest_id}")
async def update_destination(dest_id: int, payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    token = (payload.get("token") or "").strip()
    chat_id = (payload.get("chat_id") or "").strip()
    if not name or not token or not chat_id:
        raise HTTPException(status_code=400, detail="Nome, token e chat_id são obrigatórios")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE telegram_destinations SET name=?, token=?, chat_id=? WHERE id=?", (name, token, chat_id, dest_id))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}

@router.delete("/{dest_id}")
async def delete_destination(dest_id: int):
    conn = get_db()
    try:
        c = conn.cursor()
        # Nullify any targets using this destination
        c.execute("UPDATE ping_targets SET telegram_destination_id=NULL WHERE telegram_destination_id=?", (dest_id,))
        c.execute("DELETE FROM telegram_destinations WHERE id=?", (dest_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}
