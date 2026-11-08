"""
Unit tests for SecureVault Cryptography Modules:
- Vigenère Cipher
- AES-256-GCM
- ChaCha20-Poly1305
- SHA-256 Hashing
"""

import os
import pytest
from crypto.vigenere import VigenereCipher
from crypto.aes import AES256GCMCipher
from crypto.chacha20 import ChaCha20Poly1305Cipher
from crypto.hashing import HashManager

def test_vigenere_roundtrip():
    plaintext = "KRIPTOGRAFI ITB - Tugas Akhir SecureVault 2026!"
    key = "RAHASIA"
    encrypted = VigenereCipher.encrypt(plaintext, key)
    assert encrypted != plaintext
    decrypted = VigenereCipher.decrypt(encrypted, key)
    assert decrypted == plaintext

def test_vigenere_invalid_key():
    with pytest.raises(ValueError):
        VigenereCipher.encrypt("Hello", "12345!@#")

def test_aes_gcm_roundtrip():
    key = os.urandom(32)
    plaintext = "Sensitive Nuclear Launch Code: 4892-XYZ-990"
    enc = AES256GCMCipher.encrypt(plaintext, key)
    assert "bundle" in enc
    assert "nonce" in enc
    assert "tag" in enc
    
    decrypted = AES256GCMCipher.decrypt(enc["bundle"], key)
    assert decrypted.decode("utf-8") == plaintext

def test_aes_gcm_tamper_detection():
    key = os.urandom(32)
    plaintext = "Secure message"
    enc = AES256GCMCipher.encrypt(plaintext, key)
    
    # Modify one byte in ciphertext
    import base64
    raw = bytearray(base64.b64decode(enc["bundle"]))
    raw[-1] ^= 0xFF  # flip bits of last byte
    tampered_bundle = base64.b64encode(raw).decode("utf-8")

    with pytest.raises(ValueError, match="Tag autentikasi tidak valid"):
        AES256GCMCipher.decrypt(tampered_bundle, key)

def test_chacha20_file_roundtrip(tmp_path):
    key = os.urandom(32)
    original_file = tmp_path / "sample.bin"
    encrypted_file = tmp_path / "sample.bin.svf"
    decrypted_file = tmp_path / "sample_decrypted.bin"

    # Create 250 KB random test file (crosses several 64KB chunks)
    data = os.urandom(250 * 1024)
    original_file.write_bytes(data)

    # Encrypt
    enc_info = ChaCha20Poly1305Cipher.encrypt_file(original_file, encrypted_file, key)
    assert enc_info["total_chunks"] > 1
    assert encrypted_file.exists()

    # Decrypt
    dec_info = ChaCha20Poly1305Cipher.decrypt_file(encrypted_file, decrypted_file, key)
    assert decrypted_file.exists()
    assert decrypted_file.read_bytes() == data

    # Verify SHA-256 matches bit for bit
    orig_hash = HashManager.sha256_file(original_file)
    dec_hash = HashManager.sha256_file(decrypted_file)
    assert orig_hash == dec_hash

def test_chacha20_tamper_detection(tmp_path):
    key = os.urandom(32)
    original_file = tmp_path / "test.txt"
    encrypted_file = tmp_path / "test.txt.svf"
    decrypted_file = tmp_path / "test_out.txt"

    original_file.write_text("Hello Secure Data")
    ChaCha20Poly1305Cipher.encrypt_file(original_file, encrypted_file, key)

    # Tamper with file
    content = bytearray(encrypted_file.read_bytes())
    content[-5] ^= 0xAA
    encrypted_file.write_bytes(content)

    with pytest.raises(ValueError, match="Verifikasi integritas gagal|Magic header mismatch"):
        ChaCha20Poly1305Cipher.decrypt_file(encrypted_file, decrypted_file, key)
