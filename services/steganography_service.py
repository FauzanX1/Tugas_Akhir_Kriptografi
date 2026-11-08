"""
SecureVault - Service: Image Steganography (LSB)
Hides encrypted messages within lossless image pixels using Least Significant Bit (LSB) embedding.
Message is encrypted with AES-256-GCM prior to embedding.
Validates capacity, preserves pixel visual quality, and anchors assets in blockchain.
"""

import struct
from pathlib import Path
from PIL import Image
from config.database import db
from config.settings import STEGO_IMAGES_DIR
from core.key_manager import key_manager
from crypto.aes import AES256GCMCipher
from crypto.hashing import HashManager
from services.blockchain_service import BlockchainService

class SteganographyService:
    """Manages LSB steganography encoding and decoding."""

    MAGIC_HEADER = b"SVS1"  # 4 bytes identifier

    @classmethod
    def _get_stego_key(cls, user_id: int) -> bytes:
        """Derive steganography cryptographic key for user."""
        return key_manager.derive_sub_key(user_id, purpose="steganography-key")

    @classmethod
    def calculate_capacity_bytes(cls, image_path: str | Path) -> int:
        """
        Calculate maximum secret payload capacity in bytes for the given image.
        Each RGB pixel holds 3 bits (1 bit per R, G, B channel).
        """
        with Image.open(image_path) as img:
            rgb_img = img.convert("RGB")
            width, height = rgb_img.size
            total_bits = width * height * 3
            # Reserve 8 bytes for MAGIC_HEADER (4 bytes) and payload length (4 bytes)
            max_bytes = (total_bits // 8) - 8
            return max(0, max_bytes)

    @classmethod
    def encode_message_into_image(cls, owner_id: int, image_path: str | Path, secret_text: str, custom_key: str = None) -> dict:
        """
        Encrypt secret message and embed into image via LSB.
        Outputs lossless PNG.
        """
        src = Path(image_path)
        if not src.exists():
            raise FileNotFoundError(f"File gambar tidak ditemukan: {src}")

        if not secret_text.strip():
            raise ValueError("Pesan rahasia tidak boleh kosong.")

        # 1. Derive or use key to encrypt message with AES-256-GCM
        if custom_key:
            import hashlib
            key = hashlib.sha256(custom_key.encode("utf-8")).digest()
        else:
            key = cls._get_stego_key(owner_id)

        enc_result = AES256GCMCipher.encrypt(secret_text, key)
        payload_bytes = enc_result["bundle"].encode("utf-8")
        payload_len = len(payload_bytes)

        # 2. Check image capacity
        capacity = cls.calculate_capacity_bytes(src)
        if payload_len > capacity:
            raise ValueError(
                f"Kapasitas gambar tidak mencukupi! "
                f"Ukuran pesan terenkripsi ({payload_len} bytes) melebihi kapasitas maksimum gambar ({capacity} bytes). "
                f"Silakan gunakan gambar beresolusi lebih tinggi."
            )

        # 3. Construct binary data: [MAGIC (4)] + [LENGTH (4)] + [PAYLOAD]
        header = cls.MAGIC_HEADER + struct.pack(">I", payload_len)
        full_data = header + payload_bytes

        # Convert full_data to bit list
        bits = []
        for byte in full_data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        # 4. Open image and embed bits in LSB of RGB channels
        with Image.open(src) as img:
            rgb_img = img.convert("RGB")
            byte_arr = bytearray(rgb_img.tobytes())
            total_bits = len(bits)

            for i in range(total_bits):
                byte_arr[i] = (byte_arr[i] & ~1) | bits[i]

            stego_img = Image.frombytes("RGB", rgb_img.size, bytes(byte_arr))

            # Save as PNG to avoid compression loss
            output_filename = f"stego_{src.stem}.png"
            dest_path = STEGO_IMAGES_DIR / output_filename
            stego_img.save(dest_path, format="PNG")

        # 5. Record SHA-256 and anchor into Blockchain
        stego_hash = HashManager.sha256_file(dest_path)
        block = BlockchainService.add_asset_block(
            asset_name=f"STEGO:{output_filename}",
            asset_type="STEGO_IMAGE",
            asset_hash=stego_hash
        )

        # 6. Save in database
        stego_id = db.insert_get_id(
            """
            INSERT INTO steganography (owner_id, image_name, original_image_path, stego_image_path, payload_size_bytes, algorithm)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (owner_id, output_filename, str(src), str(dest_path), payload_len, "LSB + AES-256-GCM")
        )

        return {
            "id": stego_id,
            "stego_image_path": str(dest_path),
            "payload_size": payload_len,
            "capacity": capacity,
            "block_index": block["block_index"],
            "sha256": stego_hash
        }

    @classmethod
    def decode_message_from_image(cls, owner_id: int, image_path: str | Path, custom_key: str = None) -> str:
        """
        Extract LSB bitstream from image and decrypt the embedded secret message.
        """
        src = Path(image_path)
        if not src.exists():
            raise FileNotFoundError(f"File gambar stego tidak ditemukan: {src}")

        with Image.open(src) as img:
            rgb_img = img.convert("RGB")
            raw_bytes = rgb_img.tobytes()

        # Extract bits directly from bytearray
        extracted_bits = [b & 1 for b in raw_bytes]

        # Helper to convert bit slice to bytes
        def bits_to_bytes(bit_list):
            out = bytearray()
            for i in range(0, len(bit_list), 8):
                byte_chunk = bit_list[i:i+8]
                if len(byte_chunk) < 8:
                    break
                val = 0
                for bit in byte_chunk:
                    val = (val << 1) | bit
                out.append(val)
            return bytes(out)

        # Read first 8 bytes (MAGIC + LENGTH) = 64 bits
        header_bits = extracted_bits[:64]
        header_bytes = bits_to_bytes(header_bits)
        if len(header_bytes) < 8:
            raise ValueError("Gambar tidak memiliki data steganografi yang valid.")

        magic = header_bytes[:4]
        if magic != cls.MAGIC_HEADER:
            raise ValueError("Gambar ini tidak mengandung pesan steganografi SecureVault (Magic header tidak cocok).")

        payload_len = struct.unpack(">I", header_bytes[4:8])[0]
        total_payload_bits = payload_len * 8

        if len(extracted_bits) < 64 + total_payload_bits:
            raise ValueError("Data pesan dalam gambar terpotong atau korup.")

        payload_bits = extracted_bits[64 : 64 + total_payload_bits]
        payload_bytes = bits_to_bytes(payload_bits)

        # Decrypt payload with AES-256-GCM
        if custom_key:
            import hashlib
            key = hashlib.sha256(custom_key.encode("utf-8")).digest()
        else:
            key = cls._get_stego_key(owner_id)

        bundle_str = payload_bytes.decode("utf-8")
        decrypted_bytes = AES256GCMCipher.decrypt(bundle_str, key)
        return decrypted_bytes.decode("utf-8")
