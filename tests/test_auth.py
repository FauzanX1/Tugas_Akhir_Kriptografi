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

def test_face_recognition_engine():
    import numpy as np
    from hardware.biometric import FaceRecognitionEngine

    # Create dummy face ROI (100x100)
    dummy_face = np.random.randint(50, 200, (100, 100, 3), dtype=np.uint8)
    feat1 = FaceRecognitionEngine.extract_features(dummy_face)
    feat2 = FaceRecognitionEngine.extract_features(dummy_face)
    
    # Self-match should be ~1.0
    sim_self = FaceRecognitionEngine.compare(feat1, feat2)
    assert sim_self > 0.95

    # Serialize & deserialize roundtrip
    s = FaceRecognitionEngine.serialize_features(feat1)
    deser = FaceRecognitionEngine.deserialize_features(s)
    assert deser is not None
    assert np.allclose(feat1, deser, atol=1e-5)
