import datetime
import ipaddress
import json
import re
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


def parse_client_ip(raw_ip: str | None):
    """Parses and normalizes client IP string into IPv4/IPv6 address object."""
    if not raw_ip:
        return None
    raw = str(raw_ip).strip()
    # Strip port if passed as IP:port (e.g. 192.168.1.1:8080)
    if ":" in raw and "." in raw and raw.count(":") == 1:
        raw = raw.split(":")[0]
    try:
        ip = ipaddress.ip_address(raw)
        if getattr(ip, "ipv4_mapped", None):
            return ip.ipv4_mapped
        return ip
    except ValueError:
        return None


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


def validate_license_origin(
    allowed_restriction: str | None,
    client_hostname: str | None,
    client_ip_str: str | None,
) -> tuple[bool, str, str]:
    """
    Validates client origin against configured domains, hostnames, or IP networks (CIDR / ASN blocks).
    Supports multiple entries separated by comma, semicolon, space or newline.
    Returns: (is_allowed, status_code, failure_reason)
    """
    if not allowed_restriction or not str(allowed_restriction).strip():
        return True, "ACTIVE", ""

    # Split tokens by comma, semicolon, newline, spaces
    tokens = [t.strip() for t in re.split(r"[,;\n\r]+", str(allowed_restriction)) if t.strip()]
    if not tokens:
        return True, "ACTIVE", ""

    ip_networks = []
    domain_rules = []

    for token in tokens:
        try:
            # Check if token is an IP network or single IP (e.g. 45.160.0.0/22, 177.100.0.1, 2804:...::/32)
            net = ipaddress.ip_network(token, strict=False)
            ip_networks.append(net)
        except ValueError:
            # Token is a domain or host pattern (e.g. app.provedor.com.br)
            clean_dom = token.lower()
            if "://" in clean_dom:
                clean_dom = clean_dom.split("://", 1)[1]
            clean_dom = clean_dom.split("/")[0].split(":")[0]
            if clean_dom:
                domain_rules.append(clean_dom)

    client_ip_obj = parse_client_ip(client_ip_str)

    # 1. Check IP networks / ASN blocks
    ip_matched = False
    if ip_networks and client_ip_obj:
        for net in ip_networks:
            try:
                if client_ip_obj in net:
                    ip_matched = True
                    break
            except TypeError:
                pass  # E.g. IPv4 checked against IPv6 network

    # 2. Check Domain rules
    domain_matched = False
    if domain_rules and client_hostname:
        clean_host = client_hostname.strip().lower()
        if "://" in clean_host:
            clean_host = clean_host.split("://", 1)[1]
        clean_host = clean_host.split("/")[0].split(":")[0]

        for dom in domain_rules:
            if clean_host == dom or clean_host.endswith("." + dom):
                domain_matched = True
                break

    # Determine authorization outcome:
    # A. Only IP networks (ASN blocks) configured
    if ip_networks and not domain_rules:
        if ip_matched:
            return True, "ACTIVE", ""
        return (
            False,
            "IP_NOT_ALLOWED",
            f"IP de origem '{client_ip_str or 'desconhecido'}' não pertence à rede/bloco ASN autorizado para esta licença.",
        )

    # B. Only domains configured
    if domain_rules and not ip_networks:
        if domain_matched:
            return True, "ACTIVE", ""
        return (
            False,
            "DOMAIN_MISMATCH",
            f"Domínio '{client_hostname or 'não informado'}' não autorizado para esta licença.",
        )

    # C. Both IP networks and domains configured
    if ip_matched or domain_matched:
        return True, "ACTIVE", ""

    return (
        False,
        "ORIGIN_MISMATCH",
        f"Acesso negado: IP '{client_ip_str or 'desconhecido'}' e domínio '{client_hostname or 'não informado'}' não autorizados.",
    )


def check_domain_allowed(allowed_domain: str | None, client_hostname: str | None) -> bool:
    """Backward-compatible wrapper for domain checks."""
    allowed, _, _ = validate_license_origin(allowed_domain, client_hostname, None)
    return allowed


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
