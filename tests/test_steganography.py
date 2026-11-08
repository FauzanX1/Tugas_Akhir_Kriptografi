"""
Unit tests for SecureVault Steganography:
- Image capacity calculation
- LSB encode and decode roundtrip
"""

import pytest
from PIL import Image
from services.steganography_service import SteganographyService

def test_steganography_roundtrip(tmp_path):
    # Create test image: 100x100 RGB
    img_path = tmp_path / "test_input.png"
    img = Image.new("RGB", (100, 100), color=(128, 64, 200))
    img.save(img_path, format="PNG")

    # Check capacity: 100*100*3 / 8 - 8 = 3742 bytes
    capacity = SteganographyService.calculate_capacity_bytes(img_path)
    assert capacity > 500

    secret_message = "Kriptografi Rahasia Tugas Akhir 2026 - LSB Embedding!"
    custom_key = "MyStegoSecretKey123"

    # Encode
    result = SteganographyService.encode_message_into_image(
        owner_id=1,
        image_path=img_path,
        secret_text=secret_message,
        custom_key=custom_key
    )
    stego_path = result["stego_image_path"]

    # Decode
    extracted = SteganographyService.decode_message_from_image(
        owner_id=1,
        image_path=stego_path,
        custom_key=custom_key
    )
    assert extracted == secret_message
