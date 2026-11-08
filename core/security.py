"""
SecureVault - Core Security Module
Provides Argon2id password hashing, HKDF cryptographic key derivation,
and cryptographic utility functions.
"""

import os
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Argon2id password hasher with recommended RFC 9106 parameters
_ph = PasswordHasher(
    time_cost=3,          # 3 iterations
    memory_cost=65536,    # 64 MB RAM
    parallelism=4,        # 4 threads
    hash_len=32,          # 256-bit hash
    salt_len=16           # 128-bit salt
)

def hash_password(plain_password: str) -> str:
    """Hash plaintext password using Argon2id."""
    return _ph.hash(plain_password)

def verify_password(stored_hash: str, plain_password: str) -> bool:
    """Verify password against stored Argon2id hash."""
    try:
        return _ph.verify(stored_hash, plain_password)
    except (VerifyMismatchError, VerificationError):
        return False
    except Exception:
        return False

def generate_salt(length: int = 16) -> str:
    """Generate cryptographically secure random salt in hex string."""
    return os.urandom(length).hex()

def derive_key(secret: str | bytes, salt: str | bytes, length: int = 32, info: bytes = b"securevault-key-derivation") -> bytes:
    """
    Derive a high-entropy key of specified length using HKDF-SHA256.
    Default produces a 256-bit (32-byte) key.
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(secret)

def b64_encode(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("utf-8")

def b64_decode(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data.encode("utf-8"))
