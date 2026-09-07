import secrets
import time

from fastapi import Cookie, HTTPException

from app.config import ADMIN_PASSWORD, LOCKOUT_SECONDS, MAX_LOGIN_ATTEMPTS

# Session storage for web authentication (in-memory)
ACTIVE_SESSIONS = set()

# Login brute-force protection: ip -> {'count': int, 'locked_until': float}
LOGIN_ATTEMPTS = {}


def is_authenticated(session_token: str) -> bool:
    return session_token in ACTIVE_SESSIONS if session_token else False


def require_auth(session_token: str = Cookie(None)) -> str:
    """FastAPI dependency for API routes: raises 401 (JSON) if not logged in."""
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    return session_token


def create_session() -> str:
    token = secrets.token_hex(32)
    ACTIVE_SESSIONS.add(token)
    return token


def destroy_session(session_token: str):
    ACTIVE_SESSIONS.discard(session_token)


def is_locked_out(client_ip: str):
    info = LOGIN_ATTEMPTS.get(client_ip)
    if not info:
        return False, 0
    if info["count"] >= MAX_LOGIN_ATTEMPTS and time.time() < info["locked_until"]:
        return True, int(info["locked_until"] - time.time())
    if time.time() >= info.get("locked_until", 0):
        LOGIN_ATTEMPTS[client_ip] = {"count": 0, "locked_until": 0}
    return False, 0


def register_failed_attempt(client_ip: str):
    info = LOGIN_ATTEMPTS.setdefault(client_ip, {"count": 0, "locked_until": 0})
    info["count"] += 1
    if info["count"] >= MAX_LOGIN_ATTEMPTS:
        info["locked_until"] = time.time() + LOCKOUT_SECONDS


def clear_attempts(client_ip: str):
    LOGIN_ATTEMPTS.pop(client_ip, None)


def check_password(password: str) -> bool:
    import hmac
    return hmac.compare_digest(password, ADMIN_PASSWORD)
