import asyncio
import datetime
import json
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.db import get_db
from app.license import (
    extract_client_ip,
    is_license_expired,
    stream_manager,
    validate_license_origin,
)
from app.mikrotik import handle_failover_webhook_event

router = APIRouter(prefix="/api/license")

# Throttle DB writes for last_seen updates: license_id -> (last_write_monotonic, last_ip)
_LAST_SEEN_WRITE_CACHE: dict[int, tuple[float, str]] = {}
_WRITE_THROTTLE_SECONDS = 60.0


def _update_license_last_seen_throttled(conn, license_id: int, ip: str, hostname: str, app_version: str):
    """Updates last_check_at in SQLite at most once every 60s per license (or when IP changes) to avoid disk I/O."""
    now_mono = time.monotonic()
    prev = _LAST_SEEN_WRITE_CACHE.get(license_id)
    if prev is not None:
        last_ts, last_ip = prev
        if (now_mono - last_ts) < _WRITE_THROTTLE_SECONDS and last_ip == ip:
            return

    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE licenses
            SET last_check_at = ?,
                last_ip = ?,
                last_hostname = COALESCE(NULLIF(?, ''), last_hostname),
                last_version = COALESCE(NULLIF(?, ''), last_version),
                total_checks = total_checks + 1
            WHERE id = ?
            """,
            (now_str, ip, hostname, app_version, license_id),
        )
        conn.commit()
        _LAST_SEEN_WRITE_CACHE[license_id] = (now_mono, ip)
    except Exception:
        pass


@router.get("/ping")
async def license_ping():
    """Healthcheck endpoint for the license server."""
    return {
        "status": "ok",
        "service": "bkpprovider-license-server",
        "server_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/failover-event/{device_id}/{link_role}/{state}/{token}")
async def failover_webhook_event(
    device_id: int,
    link_role: str,
    state: str,
    token: str,
    request: Request,
):
    """Public webhook triggered by MikroTik /tool netwatch when a WAN link goes DOWN or UP."""
    client_ip = extract_client_ip(request)
    return await handle_failover_webhook_event(device_id, link_role, state, token, client_ip=client_ip)


async def _handle_verify(request: Request, raw_key: Optional[str] = None, payload: dict = None):
    payload = payload or {}
    client_ip = extract_client_ip(request)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    key = raw_key
    if not key:
        key = request.headers.get("x-license-key")
    if not key:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            key = auth_header[7:].strip()
    if not key:
        key = payload.get("license_key") or payload.get("key")

    key = str(key).strip().upper() if key else ""
    if not key:
        return {
            "valid": False,
            "status": "INVALID_KEY",
            "message": "Chave de licença não fornecida.",
            "server_time": now_str,
        }

    app_version = str(payload.get("app_version") or request.query_params.get("app_version") or "").strip()
    hostname = str(payload.get("hostname") or request.query_params.get("hostname") or "").strip()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE UPPER(license_key) = ?", (key,))
        lic = cursor.fetchone()

        if not lic:
            return {
                "valid": False,
                "status": "INVALID_KEY",
                "license_key": key,
                "message": "Chave de licença inexistente ou incorreta.",
                "server_time": now_str,
            }

        license_id = lic["id"]
        client_name = lic["client_name"]
        db_key = lic["license_key"]
        status = lic["status"]
        expires_at = lic["expires_at"]
        allowed_domain = lic["allowed_domain"]

        _update_license_last_seen_throttled(conn, license_id, client_ip, hostname, app_version)

        if status == "BLOCKED":
            return {
                "valid": False,
                "status": "BLOCKED",
                "client_name": client_name,
                "license_key": db_key,
                "message": "Esta licença foi bloqueada pelo administrador. Acesso negado.",
                "server_time": now_str,
            }

        if is_license_expired(expires_at):
            return {
                "valid": False,
                "status": "EXPIRED",
                "client_name": client_name,
                "license_key": db_key,
                "expires_at": expires_at,
                "message": f"Esta licença expirou em {expires_at}.",
                "server_time": now_str,
            }

        is_origin_valid, origin_status, origin_reason = validate_license_origin(allowed_domain, hostname, client_ip)
        if not is_origin_valid:
            return {
                "valid": False,
                "status": origin_status,
                "client_name": client_name,
                "license_key": db_key,
                "message": origin_reason,
                "server_time": now_str,
            }

        return {
            "valid": True,
            "status": "ACTIVE",
            "client_name": client_name,
            "license_key": db_key,
            "expires_at": expires_at,
            "message": "Licença ativa e autorizada.",
            "server_time": now_str,
        }
    finally:
        conn.close()


@router.post("/verify")
async def license_verify_post(request: Request):
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        pass
    return await _handle_verify(request, payload=payload)


@router.get("/verify")
async def license_verify_get(request: Request, key: Optional[str] = Query(None)):
    return await _handle_verify(request, raw_key=key)


@router.post("/heartbeat")
async def license_heartbeat(request: Request):
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        pass
    return await _handle_verify(request, payload=payload)


@router.get("/stream")
async def license_stream(request: Request, key: Optional[str] = Query(None)):
    """Lightweight SSE stream for instant license status push."""
    raw_key = key or request.headers.get("x-license-key")
    if not raw_key:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            raw_key = auth_header[7:].strip()

    if not raw_key:
        raise HTTPException(status_code=400, detail="Chave de licença não fornecida.")

    norm_key = str(raw_key).strip().upper()
    client_ip = extract_client_ip(request)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE UPPER(license_key) = ?", (norm_key,))
        lic = cursor.fetchone()
        if not lic:
            raise HTTPException(status_code=404, detail="Licença inexistente.")

        is_origin_valid, _, origin_reason = validate_license_origin(
            lic["allowed_domain"], request.query_params.get("hostname"), client_ip
        )
        if not is_origin_valid:
            raise HTTPException(status_code=403, detail=origin_reason)

        current_status = lic["status"] or "ACTIVE"
        client_name = lic["client_name"]
    finally:
        conn.close()

    queue = stream_manager.subscribe(norm_key)

    async def event_generator():
        try:
            initial_event = {
                "event": current_status,
                "status": current_status,
                "valid": current_status == "ACTIVE",
                "client_name": client_name,
                "message": "Conectado ao servidor de licenças.",
                "server_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            yield f"data: {json.dumps(initial_event)}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield f"data: {json.dumps(message)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            stream_manager.unsubscribe(norm_key, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
