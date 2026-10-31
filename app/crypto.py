import base64
import hashlib
import hmac
import os
from cryptography.fernet import Fernet, InvalidToken

from app.config import DATA_DIR, SECRET_KEY_ENV

_FERNET_INSTANCE = None
_ENC_PREFIX = "enc:"


def _get_fernet() -> Fernet:
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is not None:
        return _FERNET_INSTANCE

    os.makedirs(DATA_DIR, exist_ok=True)
    key_file = os.path.join(DATA_DIR, ".secret.key")

    if SECRET_KEY_ENV:
        raw = hashlib.sha256(SECRET_KEY_ENV.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(raw)
    elif os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass

    _FERNET_INSTANCE = Fernet(key)
    return _FERNET_INSTANCE


def encrypt_secret(plain_text: str | None) -> str:
    """Encrypts a plaintext credential into an 'enc:...' token."""
    if not plain_text:
        return ""
    text = str(plain_text)
    if text.startswith(_ENC_PREFIX):
        return text
    token = _get_fernet().encrypt(text.encode("utf-8")).decode("ascii")
    return f"{_ENC_PREFIX}{token}"


def decrypt_secret(stored_value: str | None) -> str:
    """Decrypts an 'enc:...' token back into plaintext (or returns legacy plaintext)."""
    if not stored_value:
        return ""
    text = str(stored_value)
    if not text.startswith(_ENC_PREFIX):
        return text
    token = text[len(_ENC_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        return ""


def generate_device_webhook_token(device_id: int) -> str:
    """Generates a deterministic 12-char alphanumeric HMAC token for a device's failover webhook."""
    _get_fernet()
    key_file = os.path.join(DATA_DIR, ".secret.key")
    if SECRET_KEY_ENV:
        seed = SECRET_KEY_ENV.encode("utf-8")
    elif os.path.exists(key_file):
        with open(key_file, "rb") as f:
            seed = f.read().strip()
    else:
        seed = b"bkpprovider-default-seed"
    digest = hashlib.sha256(seed + f":failover-webhook:{int(device_id)}".encode("utf-8")).hexdigest()
    return digest[:12]


def verify_device_webhook_token(device_id: int, token: str) -> bool:
    if not token:
        return False
    expected = generate_device_webhook_token(device_id)
    return hmac.compare_digest(str(token).strip().lower(), expected.lower())

