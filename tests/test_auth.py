"""
Unit tests for SecureVault Authentication & Key Management:
- Argon2id password hashing and verification
- HKDF key derivation
"""

import pytest
from core.security import hash_password, verify_password, derive_key

def test_argon2id_hashing():
    pwd = "SuperSecretPassword2026!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, pwd) is True
    assert verify_password(hashed, "WrongPassword") is False

def test_hkdf_derivation():
    secret = "user_master_seed"
    salt = "random_salt_123"
    k1 = derive_key(secret, salt, length=32)
    k2 = derive_key(secret, salt, length=32)
    assert k1 == k2
    assert len(k1) == 32
    
    k3 = derive_key(secret, "different_salt", length=32)
    assert k1 != k3
