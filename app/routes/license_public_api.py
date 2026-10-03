import datetime
import json
from typing import Optional

from fastapi import APIRouter, Header, Query, Request

from app.db import get_db
from app.license import (
    check_domain_allowed,
    extract_client_ip,
    is_license_expired,
)

router = APIRouter(prefix="/api/license")


def _record_log(
    conn,
    license_id: int,
    license_key: str,
    ip: str,
    hostname: str,
    app_version: str,
    status_returned: str,
    message: str,
    details: str = "",
):
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO license_logs 
            (license_id, license_key, timestamp, ip, hostname, app_version, status_returned, message, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (license_id, license_key, now_str, ip, hostname, app_version, status_returned, message, details),
        )

        # Keep last 200 logs for this license to avoid database bloat
        if license_id > 0:
            cursor.execute(
                """
                DELETE FROM license_logs 
                WHERE id NOT IN (
                    SELECT id FROM license_logs 
                    WHERE license_id = ? 
                    ORDER BY id DESC LIMIT 200
                ) AND license_id = ?
                """,
                (license_id, license_id),
            )
        conn.commit()
    except Exception:
        pass


def _update_license_last_seen(conn, license_id: int, ip: str, hostname: str, app_version: str):
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


async def _handle_verify(request: Request, raw_key: Optional[str] = None, payload: dict = None):
    payload = payload or {}
    client_ip = extract_client_ip(request)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract key from param, headers, or body
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

    app_name = str(payload.get("app_name") or request.query_params.get("app_name") or "").strip()
    app_version = str(payload.get("app_version") or request.query_params.get("app_version") or "").strip()
    hostname = str(payload.get("hostname") or request.query_params.get("hostname") or "").strip()
    machine_id = str(payload.get("machine_id") or request.query_params.get("machine_id") or "").strip()
    
    details_dict = {
        "app_name": app_name,
        "machine_id": machine_id,
        "raw_extra": payload.get("details") or payload.get("extra"),
    }
    details_json = json.dumps({k: v for k, v in details_dict.items() if v}, ensure_ascii=False)

    conn = get_db()
    try:
        if not key:
            _record_log(
                conn, 0, "<nenhuma>", client_ip, hostname, app_version,
                "INVALID_KEY", "Chave de licença não fornecida.", details_json
            )
            return {
                "valid": False,
                "status": "INVALID_KEY",
                "message": "Chave de licença não fornecida.",
                "server_time": now_str,
            }

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE UPPER(license_key) = ?", (key,))
        lic = cursor.fetchone()

        if not lic:
            _record_log(
                conn, 0, key, client_ip, hostname, app_version,
                "INVALID_KEY", "Chave de licença inexistente ou incorreta.", details_json
            )
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

        # 1. Check if blocked
        if status == "BLOCKED":
            _update_license_last_seen(conn, license_id, client_ip, hostname, app_version)
            _record_log(
                conn, license_id, db_key, client_ip, hostname, app_version,
                "BLOCKED", "Licença bloqueada pelo administrador.", details_json
            )
            return {
                "valid": False,
                "status": "BLOCKED",
                "client_name": client_name,
                "license_key": db_key,
                "message": "Esta licença foi bloqueada pelo administrador. Acesso negado.",
                "server_time": now_str,
            }

        # 2. Check if expired
        if is_license_expired(expires_at):
            _update_license_last_seen(conn, license_id, client_ip, hostname, app_version)
            _record_log(
                conn, license_id, db_key, client_ip, hostname, app_version,
                "EXPIRED", f"Licença expirou em {expires_at}.", details_json
            )
            return {
                "valid": False,
                "status": "EXPIRED",
                "client_name": client_name,
                "license_key": db_key,
                "expires_at": expires_at,
                "message": f"Esta licença expirou em {expires_at}.",
                "server_time": now_str,
            }

        # 3. Check allowed domain
        if allowed_domain and not check_domain_allowed(allowed_domain, hostname):
            _update_license_last_seen(conn, license_id, client_ip, hostname, app_version)
            _record_log(
                conn, license_id, db_key, client_ip, hostname, app_version,
                "DOMAIN_MISMATCH", f"Domínio '{hostname}' não autorizado.", details_json
            )
            return {
                "valid": False,
                "status": "DOMAIN_MISMATCH",
                "client_name": client_name,
                "license_key": db_key,
                "message": f"Domínio '{hostname or 'desconhecido'}' não autorizado para esta licença.",
                "server_time": now_str,
            }

        # 4. Valid and active!
        _update_license_last_seen(conn, license_id, client_ip, hostname, app_version)
        _record_log(
            conn, license_id, db_key, client_ip, hostname, app_version,
            "ACTIVE", "Licença ativa e autorizada.", details_json
        )
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
    """Primary endpoint for client application to verify license via POST."""
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        pass
    return await _handle_verify(request, payload=payload)


@router.get("/verify")
async def license_verify_get(request: Request, key: Optional[str] = Query(None)):
    """Allows checking license via GET query parameter or header."""
    return await _handle_verify(request, raw_key=key)


@router.post("/heartbeat")
async def license_heartbeat(request: Request):
    """Periodic heartbeat endpoint for client application."""
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        pass
    return await _handle_verify(request, payload=payload)
