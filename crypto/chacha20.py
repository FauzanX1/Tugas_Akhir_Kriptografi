"""
SecureVault - Modern Cryptography: ChaCha20-Poly1305
Implements high-speed authenticated encryption for files and binary streams.
Includes chunked authenticated encryption with per-chunk nonce and sequence AAD
to handle arbitrary file sizes safely while preventing chunk reordering or truncation.
"""

import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

class ChaCha20Poly1305Cipher:
    """
    ChaCha20-Poly1305 Authenticated Cipher.
    Key size: 32 bytes (256-bit).
    Nonce size: 12 bytes (96-bit).
    """

    MAGIC_HEADER = b"SVF1"
    KEY_SIZE_BYTES = 32
    NONCE_SIZE_BYTES = 12
    TAG_SIZE_BYTES = 16
    DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB per chunk

    @classmethod
    def encrypt_bytes(cls, data: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        """Encrypt in-memory bytes and return (nonce, ciphertext_with_tag)."""
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"ChaCha20-Poly1305 memerlukan kunci 32-byte (256-bit). Diterima: {len(key)}")
        
        nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        cipher = ChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, data, associated_data)
        return nonce, ct

    @classmethod
    def decrypt_bytes(cls, nonce: bytes, ciphertext_with_tag: bytes, key: bytes, associated_data: bytes = None) -> bytes:
        """Decrypt in-memory bytes. Raises ValueError if verification fails."""
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError("ChaCha20-Poly1305 memerlukan kunci 32-byte (256-bit).")
        
        cipher = ChaCha20Poly1305(key)
        try:
            return cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise ValueError("Dekripsi ChaCha20-Poly1305 Gagal: File rusak atau kunci salah!")

    @classmethod
    def encrypt_file(cls, input_path: str | Path, output_path: str | Path, key: bytes, progress_callback=None) -> dict:
        """
        Encrypt a file in chunked streaming mode.
        Format:
        [MAGIC: 4 bytes] [SALT: 16 bytes] [CHUNK_SIZE: 4 bytes]
        Repeated for each chunk:
        [PAYLOAD_LEN: 4 bytes] [NONCE: 12 bytes] [ENCRYPTED_CHUNK + TAG]
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"File tidak ditemukan: {input_path}")
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"Kunci enkripsi harus berukuran {cls.KEY_SIZE_BYTES} bytes.")

        file_size = input_path.stat().st_size
        cipher = ChaCha20Poly1305(key)
        salt = os.urandom(16)
        chunk_size = cls.DEFAULT_CHUNK_SIZE

        bytes_processed = 0
        chunk_index = 0

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            # Write header
            fout.write(cls.MAGIC_HEADER)
            fout.write(salt)
            fout.write(struct.pack(">I", chunk_size))

            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                
                # Unique random nonce for this chunk
                nonce = os.urandom(cls.NONCE_SIZE_BYTES)
                # Associated data includes chunk index to prevent reordering/dropping
                aad = b"SVF1-CHUNK-" + struct.pack(">Q", chunk_index)
                encrypted_chunk = cipher.encrypt(nonce, chunk, aad)

                # Write payload length (4 bytes), nonce (12 bytes), and encrypted chunk
                fout.write(struct.pack(">I", len(encrypted_chunk)))
                fout.write(nonce)
                fout.write(encrypted_chunk)

                bytes_processed += len(chunk)
                chunk_index += 1
                if progress_callback and file_size > 0:
                    progress_callback(int((bytes_processed / file_size) * 100))

        return {
            "original_size": file_size,
            "encrypted_size": output_path.stat().st_size,
            "total_chunks": chunk_index,
            "salt": salt.hex()
        }

    @classmethod
    def decrypt_file(cls, input_path: str | Path, output_path: str | Path, key: bytes, progress_callback=None) -> dict:
        """
        Decrypt a chunked encrypted file.
        Verifies magic header, chunk tags, and sequence order.
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        if not input_path.exists():
            raise FileNotFoundError(f"File terenkripsi tidak ditemukan: {input_path}")
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"Kunci dekripsi harus berukuran {cls.KEY_SIZE_BYTES} bytes.")

        file_size = input_path.stat().st_size
        cipher = ChaCha20Poly1305(key)

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            # Read header
            magic = fin.read(4)
            if magic != cls.MAGIC_HEADER:
                raise ValueError("Format file tidak dikenali atau bukan file SecureVault (Magic header mismatch).")
            
            salt = fin.read(16)
            chunk_size_bytes = fin.read(4)
            if len(chunk_size_bytes) < 4:
                raise ValueError("Header file rusak atau tidak lengkap.")
            chunk_size = struct.unpack(">I", chunk_size_bytes)[0]

            bytes_read = 24
            chunk_index = 0

            while bytes_read < file_size:
                len_bytes = fin.read(4)
                if not len_bytes:
                    break
                payload_len = struct.unpack(">I", len_bytes)[0]
                nonce = fin.read(cls.NONCE_SIZE_BYTES)
                if len(nonce) < cls.NONCE_SIZE_BYTES:
                    raise ValueError("File terpotong atau rusak pada pembacaan nonce.")

                encrypted_chunk = fin.read(payload_len)
                if len(encrypted_chunk) < payload_len:
                    raise ValueError("File terpotong atau data chunk tidak lengkap.")

                # Verify and decrypt with sequence AAD
                aad = b"SVF1-CHUNK-" + struct.pack(">Q", chunk_index)
                try:
                    decrypted_chunk = cipher.decrypt(nonce, encrypted_chunk, aad)
                except InvalidTag:
                    raise ValueError(f"Verifikasi integritas gagal pada chunk #{chunk_index}. Kunci salah atau file telah dimanipulasi!")

                fout.write(decrypted_chunk)
                bytes_read += 4 + cls.NONCE_SIZE_BYTES + payload_len
                chunk_index += 1

                if progress_callback and file_size > 0:
                    progress_callback(int((bytes_read / file_size) * 100))

        return {
            "decrypted_size": output_path.stat().st_size,
            "total_chunks": chunk_index
        }
