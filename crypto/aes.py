"""
SecureVault - Modern Cryptography: AES-256-GCM
Implements Authenticated Encryption with Associated Data (AEAD) using AES-256 in Galois/Counter Mode.
Guarantees confidentiality, integrity, and authenticity.
"""

import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class AES256GCMCipher:
    """
    AES-256-GCM authenticated cipher.
    Requires 256-bit (32 bytes) key.
    Generates a cryptographically secure unique 96-bit (12 bytes) nonce for every encryption.
    """

    KEY_SIZE_BYTES = 32
    NONCE_SIZE_BYTES = 12
    TAG_SIZE_BYTES = 16

    @classmethod
    def encrypt(cls, plaintext: str | bytes, key: bytes, associated_data: bytes = None) -> dict:
        """
        Encrypt plaintext using AES-256-GCM.
        Returns dictionary containing base64 encoded payload, nonce, tag, and ciphertext.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"AES-256-GCM memerlukan kunci berukuran {cls.KEY_SIZE_BYTES} byte (256-bit).")

        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = plaintext

        # Generate unique 96-bit nonce
        nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        aesgcm = AESGCM(key)

        # cryptography AESGCM.encrypt appends 16-byte authentication tag to ciphertext
        ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
        ciphertext = ct_with_tag[:-cls.TAG_SIZE_BYTES]
        tag = ct_with_tag[-cls.TAG_SIZE_BYTES:]

        # Compact bundled payload: [nonce (12)] + [tag (16)] + [ciphertext]
        bundle = nonce + tag + ciphertext
        bundle_b64 = base64.b64encode(bundle).decode("utf-8")

        return {
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "bundle": bundle_b64
        }

    @classmethod
    def decrypt(cls, bundle_b64: str, key: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypt bundled base64 payload containing nonce, tag, and ciphertext.
        Raises InvalidTag if data has been tampered with or key is incorrect.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"AES-256-GCM memerlukan kunci berukuran {cls.KEY_SIZE_BYTES} byte (256-bit).")

        bundle = base64.b64decode(bundle_b64.encode("utf-8"))
        min_len = cls.NONCE_SIZE_BYTES + cls.TAG_SIZE_BYTES
        if len(bundle) < min_len:
            raise ValueError("Data ciphertext tidak valid atau terlalu pendek.")

        nonce = bundle[:cls.NONCE_SIZE_BYTES]
        tag = bundle[cls.NONCE_SIZE_BYTES:min_len]
        ciphertext = bundle[min_len:]

        # AESGCM decrypt expects ciphertext + tag
        ct_with_tag = ciphertext + tag
        aesgcm = AESGCM(key)
        
        try:
            decrypted = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
            return decrypted
        except InvalidTag:
            raise ValueError("Dekripsi Gagal: Tag autentikasi tidak valid. Ciphertext telah dimanipulasi atau kunci salah!")

    @classmethod
    def decrypt_raw(cls, ciphertext_b64: str, nonce_b64: str, tag_b64: str, key: bytes, associated_data: bytes = None) -> bytes:
        """Decrypt using explicitly separated components."""
        ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
        nonce = base64.b64decode(nonce_b64.encode("utf-8"))
        tag = base64.b64decode(tag_b64.encode("utf-8"))
        
        ct_with_tag = ciphertext + tag
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct_with_tag, associated_data)
        except InvalidTag:
            raise ValueError("Dekripsi Gagal: Tag autentikasi tidak valid. Ciphertext telah dimanipulasi atau kunci salah!")
