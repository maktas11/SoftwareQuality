import hashlib
import hmac
import os
from typing import Optional

from cryptography.fernet import Fernet

from core.config import KEY_PATH

# --- Encryption key management ---
# We use Fernet (AES-128-CBC with HMAC-SHA256) from the cryptography library.
# Fernet is a symmetric encryption scheme: same key encrypts and decrypts.
# The key is generated once and stored on disk so encrypted data stays readable
# across application restarts. Without this key, nothing in the DB can be decrypted.


def load_or_create_key() -> bytes:
    # If the key file already exists, just load it.
    # Otherwise generate a fresh 256-bit Fernet key and persist it.
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
    # Encrypts a plaintext string into a Fernet token (bytes).
    # Each call produces a different ciphertext because Fernet uses a random IV,
    # so identical inputs won't produce identical outputs — prevents pattern analysis.
    if value is None:
        return b""
    token = _get_fernet().encrypt(value.encode("utf-8"))
    return token


def decrypt_text(value: Optional[bytes]) -> str:
    # Decrypts a Fernet token back to plaintext.
    # Fernet also verifies the HMAC, so tampered data will raise an exception
    # rather than silently return garbage — this gives us integrity checking for free.
    if not value:
        return ""
    plain = _get_fernet().decrypt(value)
    return plain.decode("utf-8")


def deterministic_hash(value: str) -> str:
    # HMAC-SHA256 keyed hash for lookup fields (username_hash, role_hash, etc.).
    # Unlike Fernet encryption, this always gives the same output for the same input,
    # which lets us do WHERE username_hash = ? queries without decrypting every row.
    # We use HMAC instead of plain SHA256 so the hash is keyed — an attacker can't
    # just hash common usernames to find matches without the key.
    key = load_or_create_key()
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest


def hash_password(password: str) -> bytes:
    # Passwords are never stored encrypted — we store a one-way hash instead.
    # PBKDF2 with 200 000 iterations of HMAC-SHA256 makes brute-forcing expensive.
    # A random 16-byte salt is generated per password so two users with the same
    # password end up with different hashes (prevents rainbow table attacks).
    # The salt is prepended to the hash so we can extract it during verification.
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return salt + pwd_hash


def verify_password(stored: bytes, password: str) -> bool:
    # Extract the salt (first 16 bytes), re-derive the hash and compare.
    # hmac.compare_digest is used instead of == to prevent timing attacks —
    # a normal string comparison leaks info about how many bytes matched,
    # which could help an attacker guess the hash one byte at a time.
    if stored and len(stored) >= 17 and hmac.compare_digest(
        stored[16:],
        hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), stored[:16], 200000),
    ):
        return True
    return False
