import hashlib
import hmac
import os
from typing import Mapping, Optional

ENV_REF_PLACEHOLDER = "__env_ref_required__"


def _hash_secret(secret: str, salt_hex: str = "") -> str:
    """Hash a secret using SHA-256 for storage at rest."""
    salt = bytes.fromhex(salt_hex) if salt_hex else hashlib.sha256(os.urandom(16)).digest()
    digest = hashlib.sha256(salt + secret.encode("utf-8")).digest()
    return (salt_hex and (salt_hex + digest.hex())) or digest.hex()


def _verify_secret(secret: str, stored: str) -> bool:
    """Verify a stored secret against the provided secret."""
    stored_bytes = bytes.fromhex(stored)
    stored_salt = stored_bytes[:-32]
    stored_digest = stored_bytes[-32:]
    new_digest = hashlib.sha256(stored_salt + secret.encode("utf-8")).digest()
    return hmac.compare_digest(stored_digest, new_digest)


def resolve_client_secret(tenant_row: Mapping[str, str]) -> Optional[str]:
    ref = (tenant_row.get("client_secret_ref") or "").strip()
    if ref:
        return os.getenv(ref, "").strip() or None

    raw = (tenant_row.get("client_secret") or "").strip()
    if raw and raw != ENV_REF_PLACEHOLDER:
        # Check if it's a hashed secret (stored format: hex salt + hex digest)
        if len(raw) > 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
            # It's a hashed secret - verify and return None (secret can't be recovered)
            # For token exchange, we need to request it again from the user
            return None
        return raw
    return None