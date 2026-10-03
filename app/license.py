import datetime
import json
import secrets
import string
from fastapi import Request


def generate_license_key() -> str:
    """Generates an unambiguous, readable license key: BKP-XXXX-XXXX-XXXX-XXXX"""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Omits 0, O, 1, I
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
    return f"BKP-{'-'.join(parts)}"


def extract_client_ip(request: Request) -> str:
    """Extracts client IP behind reverse proxies (Nginx, Traefik, Cloudflare)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def is_license_expired(expires_at: str | None) -> bool:
    """Checks if a license expiration date has passed."""
    if not expires_at:
        return False
    expires_at = str(expires_at).strip()
    if not expires_at:
        return False
    try:
        now = datetime.datetime.now()
        if len(expires_at) == 10:  # YYYY-MM-DD
            exp_date = datetime.datetime.strptime(expires_at, "%Y-%m-%d")
            exp_date = exp_date.replace(hour=23, minute=59, second=59)
        elif "T" in expires_at:
            exp_date = datetime.datetime.fromisoformat(expires_at)
        else:
            exp_date = datetime.datetime.strptime(expires_at[:19], "%Y-%m-%d %H:%M:%S")
        return now > exp_date
    except Exception:
        return False


def check_domain_allowed(allowed_domain: str | None, client_hostname: str | None) -> bool:
    """Verifies if the client hostname/domain is authorized."""
    if not allowed_domain or not allowed_domain.strip():
        return True
    if not client_hostname or not client_hostname.strip():
        return False

    client_host = client_hostname.strip().lower()
    if "://" in client_host:
        client_host = client_host.split("://", 1)[1]
    client_host = client_host.split("/")[0].split(":")[0]

    allowed_list = [d.strip().lower() for d in allowed_domain.replace(";", ",").split(",") if d.strip()]
    for allowed in allowed_list:
        if "://" in allowed:
            allowed = allowed.split("://", 1)[1]
        allowed = allowed.split("/")[0].split(":")[0]
        if client_host == allowed or client_host.endswith("." + allowed):
            return True
    return False


def format_relative_time(timestamp_str: str | None) -> str:
    """Formats timestamp into friendly relative time in Portuguese."""
    if not timestamp_str:
        return "Nunca"
    try:
        ts_clean = str(timestamp_str).replace("T", " ")
        if len(ts_clean) > 19:
            ts_clean = ts_clean[:19]
        dt = datetime.datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
        diff = datetime.datetime.now() - dt
        seconds = int(diff.total_seconds())
        if seconds < 0:
            return "Agora"
        if seconds < 60:
            return f"há {seconds}s"
        minutes = seconds // 60
        if minutes < 60:
            return f"há {minutes} min"
        hours = minutes // 60
        if hours < 24:
            return f"há {hours}h"
        days = hours // 24
        if days == 1:
            return "ontem"
        if days < 30:
            return f"há {days} dias"
        months = days // 30
        if months < 12:
            return f"há {months} meses"
        return dt.strftime("%d/%m/%Y")
    except Exception:
        return str(timestamp_str)
