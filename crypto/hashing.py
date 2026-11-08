"""
SecureVault - Cryptographic Hashing: SHA-256
Provides cryptographic hash calculation for data, assets, files, and blockchain blocks.
"""

import hashlib
from pathlib import Path

class HashManager:
    """SHA-256 Hashing utility."""

    @staticmethod
    def sha256_text(text: str) -> str:
        """Calculate SHA-256 hex digest of string."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        """Calculate SHA-256 hex digest of bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_file(file_path: str | Path, chunk_size: int = 65536) -> str:
        """Stream file through SHA-256 to calculate hex digest efficiently."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File tidak ditemukan: {path}")

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
