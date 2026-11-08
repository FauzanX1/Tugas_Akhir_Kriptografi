"""
SecureVault - Service: File Cryptography
Coordinates ChaCha20-Poly1305 authenticated chunked encryption for files,
SHA-256 integrity hashing, and records asset entries in database and blockchain.
"""

import os
import uuid
from pathlib import Path
from typing import Optional
from config.database import db
from config.settings import ENCRYPTED_FILES_DIR, DECRYPTED_FILES_DIR
from core.key_manager import key_manager
from crypto.chacha20 import ChaCha20Poly1305Cipher
from crypto.hashing import HashManager
from services.blockchain_service import BlockchainService

class FileService:
    """Manages file encryption, decryption, and integrity audit."""

    @classmethod
    def _get_file_key(cls, user_id: int) -> bytes:
        """Derive user's file encryption key."""
        return key_manager.derive_sub_key(user_id, purpose="file-vault-key")

    @classmethod
    def encrypt_and_store_file(cls, owner_id: int, original_file_path: str, progress_callback=None) -> dict:
        """
        Encrypt file with ChaCha20-Poly1305, store in encrypted storage,
        record SHA-256 in database, and anchor asset in blockchain.
        """
        src = Path(original_file_path)
        if not src.exists():
            raise FileNotFoundError(f"File tidak ditemukan: {src}")

        # 1. Compute SHA-256 checksum of original file
        sha256_original = HashManager.sha256_file(src)
        original_size = src.stat().st_size

        # 2. Derive key and prepare output path
        key = cls._get_file_key(owner_id)
        storage_filename = f"{uuid.uuid4().hex}_{src.name}.svf"
        dest_path = ENCRYPTED_FILES_DIR / storage_filename

        # 3. Encrypt file in chunks with ChaCha20-Poly1305
        enc_info = ChaCha20Poly1305Cipher.encrypt_file(
            input_path=src,
            output_path=dest_path,
            key=key,
            progress_callback=progress_callback
        )

        # 4. Insert into database
        file_id = db.insert_get_id(
            """
            INSERT INTO files (owner_id, original_name, storage_name, file_size_bytes, sha256_hash, algorithm)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (owner_id, src.name, storage_filename, original_size, sha256_original, "ChaCha20-Poly1305")
        )

        # 5. Anchor file asset hash into Blockchain
        block = BlockchainService.add_asset_block(
            asset_name=f"FILE:{src.name}",
            asset_type="ENCRYPTED_FILE",
            asset_hash=sha256_original
        )

        # 6. Log activity
        db.execute_query(
            "INSERT INTO activity_logs (user_id, action, details) VALUES (%s, %s, %s)",
            (owner_id, "FILE_ENCRYPT", f"Enkripsi file '{src.name}' ({original_size} bytes). Block #{block['block_index']}")
        )

        return {
            "file_id": file_id,
            "original_name": src.name,
            "storage_name": storage_filename,
            "original_size": original_size,
            "encrypted_size": enc_info["encrypted_size"],
            "sha256": sha256_original,
            "block_index": block["block_index"],
            "encrypted_path": str(dest_path)
        }

    @classmethod
    def decrypt_stored_file(cls, owner_id: int, file_id: int, target_dir: str | Path = None, progress_callback=None) -> dict:
        """
        Decrypt file stored in vault, verify against recorded SHA-256 hash.
        """
        record = db.fetch_one("SELECT * FROM files WHERE id = %s AND owner_id = %s", (file_id, owner_id))
        if not record:
            raise ValueError("File tidak ditemukan atau Anda tidak memiliki izin akses.")

        encrypted_path = ENCRYPTED_FILES_DIR / record["storage_name"]
        if not encrypted_path.exists():
            raise FileNotFoundError(f"File fisik terenkripsi tidak ditemukan di storage: {encrypted_path}")

        target_folder = Path(target_dir) if target_dir else DECRYPTED_FILES_DIR
        target_folder.mkdir(parents=True, exist_ok=True)
        decrypted_path = target_folder / f"decrypted_{record['original_name']}"

        key = cls._get_file_key(owner_id)

        # Decrypt chunked ChaCha20-Poly1305 file
        dec_info = ChaCha20Poly1305Cipher.decrypt_file(
            input_path=encrypted_path,
            output_path=decrypted_path,
            key=key,
            progress_callback=progress_callback
        )

        # Compute SHA-256 of decrypted file and compare with original
        sha256_decrypted = HashManager.sha256_file(decrypted_path)
        integrity_ok = (sha256_decrypted.lower() == record["sha256_hash"].lower())

        if not integrity_ok:
            raise ValueError("Integritas Gagal: Hash SHA-256 file hasil dekripsi tidak cocok dengan file asli!")

        # Log activity
        db.execute_query(
            "INSERT INTO activity_logs (user_id, action, details) VALUES (%s, %s, %s)",
            (owner_id, "FILE_DECRYPT", f"Dekripsi file '{record['original_name']}' berhasil diverifikasi.")
        )

        return {
            "original_name": record["original_name"],
            "decrypted_path": str(decrypted_path),
            "sha256": sha256_decrypted,
            "integrity_verified": True
        }

    @classmethod
    def get_user_files(cls, owner_id: int) -> list[dict]:
        """Fetch list of encrypted files owned by user."""
        return db.fetch_all(
            "SELECT * FROM files WHERE owner_id = %s ORDER BY created_at DESC",
            (owner_id,)
        )
