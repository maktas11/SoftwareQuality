import hashlib
import hmac
import os
from typing import Optional

from cryptography.fernet import Fernet

from core.config import KEY_PATH


def load_or_create_key() -> bytes:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as handle:
            return handle.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as handle:
        handle.write(key)
    return key


def _get_fernet() -> Fernet:
    key = load_or_create_key()
    return Fernet(key)


def encrypt_text(value: str) -> bytes:
    if value is None:
        return b""
    token = _get_fernet().encrypt(value.encode("utf-8"))
    return token


def decrypt_text(value: Optional[bytes]) -> str:
    if not value:
        return ""
    plain = _get_fernet().decrypt(value)
    return plain.decode("utf-8")


def deterministic_hash(value: str) -> str:
    key = load_or_create_key()
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return salt + pwd_hash


def verify_password(stored: bytes, password: str) -> bool:
    if stored and len(stored) >= 17 and hmac.compare_digest(
        stored[16:],
        hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), stored[:16], 200000),
    ):
        return True
    return False
