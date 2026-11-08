"""
Unit tests for SecureVault File Cryptography:
- ChaCha20-Poly1305 file encryption
- ChaCha20-Poly1305 file decryption
- File integrity verification
"""

import os
import pytest
from pathlib import Path
from crypto.chacha20 import ChaCha20Poly1305Cipher
from crypto.hashing import HashManager

def test_file_encryption_decryption(tmp_path):
    key = os.urandom(32)
    sample_path = tmp_path / "document.pdf"
    encrypted_path = tmp_path / "document.pdf.svf"
    decrypted_path = tmp_path / "document_restored.pdf"

    # Write dummy PDF binary content
    sample_content = b"%PDF-1.4\n" + os.urandom(80000) + b"\n%%EOF"
    sample_path.write_bytes(sample_content)

    # 1. Encrypt
    enc_info = ChaCha20Poly1305Cipher.encrypt_file(sample_path, encrypted_path, key)
    assert enc_info["encrypted_size"] > enc_info["original_size"]
    assert encrypted_path.exists()

    # 2. Decrypt
    dec_info = ChaCha20Poly1305Cipher.decrypt_file(encrypted_path, decrypted_path, key)
    assert decrypted_path.exists()
    assert dec_info["decrypted_size"] == len(sample_content)

    # 3. Check exact SHA-256 hash match
    assert HashManager.sha256_file(sample_path) == HashManager.sha256_file(decrypted_path)
