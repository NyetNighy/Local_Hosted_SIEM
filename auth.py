import hashlib
import hmac
import os
import secrets
from typing import Tuple


def _iter_count() -> int:
    return int(os.getenv("SIEM_PBKDF2_ITERATIONS", "600000"))


def hash_password(password: str, salt: bytes | None = None) -> Tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _iter_count())
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    supplied = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _iter_count())
    return hmac.compare_digest(expected, supplied)


def get_admin_credentials() -> Tuple[str, str, str]:
    username = os.getenv("SIEM_ADMIN_USERNAME", "admin")
    salt_hex = os.getenv("SIEM_ADMIN_SALT", "")
    digest_hex = os.getenv("SIEM_ADMIN_PASSWORD_HASH", "")
    return username, salt_hex, digest_hex
