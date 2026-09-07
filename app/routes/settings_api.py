from fastapi import APIRouter, Body, Depends, HTTPException

from app.auth import require_auth
from app.config import DEFAULT_SETTINGS
from app.db import get_all_settings, set_setting

router = APIRouter(prefix="/api/settings", dependencies=[Depends(require_auth)])

INT_FIELDS = [
    "ping_interval_seconds", "fail_threshold", "packet_loss_window",
    "packet_loss_threshold_pct", "backup_hour", "backup_minute", "backup_retention",
]


@router.get("")
async def read_settings():
    return get_all_settings()


@router.post("")
async def save_settings(payload: dict = Body(...)):
    for key in DEFAULT_SETTINGS:
        if key not in payload:
            continue
        value = payload[key]
        if key in INT_FIELDS:
            try:
                value = str(int(value))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"Valor inválido para {key}")
        else:
            value = str(value).strip()
        set_setting(key, value)
    return {"ok": True}
