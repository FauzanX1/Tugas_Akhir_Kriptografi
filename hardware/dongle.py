"""
SecureVault - Hardware Security: USB Dongle Module
Detects physical USB drives, generates cryptographically signed hardware tokens,
verifies hardware volume serial numbers and token challenge keys.
"""

import os
import ctypes
import string
import hashlib
from pathlib import Path
from typing import Optional
from config.settings import DEV_MODE, APP_SECRET_KEY, BASE_DIR

# Windows Drive Type Constants
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

TOKEN_FILENAME = ".securevault_token.key"
DEV_VIRTUAL_DONGLE_DIR = BASE_DIR / "storage" / "virtual_usb_dongle"

class USBDongleAuth:
    """
    USB Hardware Security Token Controller.
    """

    @staticmethod
    def get_volume_serial(drive_letter: str) -> Optional[str]:
        """Query hardware volume serial number for drive letter (e.g. 'E:\\')."""
        if not drive_letter.endswith("\\"):
            drive_letter += "\\"
        
        serial_num = ctypes.c_ulong()
        max_component_len = ctypes.c_ulong()
        file_system_flags = ctypes.c_ulong()
        volume_name_buffer = ctypes.create_unicode_buffer(260)
        file_system_name_buffer = ctypes.create_unicode_buffer(260)

        success = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_letter),
            volume_name_buffer,
            ctypes.sizeof(volume_name_buffer),
            ctypes.byref(serial_num),
            ctypes.byref(max_component_len),
            ctypes.byref(file_system_flags),
            file_system_name_buffer,
            ctypes.sizeof(file_system_name_buffer)
        )

        if success:
            return f"{serial_num.value:08X}"
        return None

    @classmethod
    def list_connected_usb_drives(cls) -> list[dict]:
        """
        Scan all system drives and return list of removable USB drives
        (also includes virtual dongle folder in DEV_MODE if present).
        """
        usb_drives = []

        for letter in string.ascii_uppercase:
            drive_path = f"{letter}:\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
            
            # Check for Removable USB drive
            if drive_type == DRIVE_REMOVABLE:
                serial = cls.get_volume_serial(drive_path)
                token_path = Path(drive_path) / TOKEN_FILENAME
                has_token = token_path.exists()
                
                usb_drives.append({
                    "drive": drive_path,
                    "label": f"USB Removable Drive ({letter}:)",
                    "serial": serial or "UNKNOWN",
                    "has_token": has_token,
                    "token_file": str(token_path),
                    "is_virtual": False
                })

        # Dev Mode fallback virtual USB dongle support
        if DEV_MODE:
            DEV_VIRTUAL_DONGLE_DIR.mkdir(parents=True, exist_ok=True)
            v_token = DEV_VIRTUAL_DONGLE_DIR / TOKEN_FILENAME
            usb_drives.append({
                "drive": str(DEV_VIRTUAL_DONGLE_DIR),
                "label": "Virtual USB Dongle [DEV MODE]",
                "serial": "VIRTUAL-DONGLE-SN-001",
                "has_token": v_token.exists(),
                "token_file": str(v_token),
                "is_virtual": True
            })

        return usb_drives

    @classmethod
    def compute_fingerprint(cls, volume_serial: str, token_secret: str) -> str:
        """Calculate cryptographically secure SHA-256 fingerprint for the token."""
        raw = f"{volume_serial}:{token_secret}:{APP_SECRET_KEY.hex()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def register_dongle_on_drive(cls, drive_path: str, user_id: int) -> dict:
        """
        Write security token file to target drive and generate dongle fingerprint.
        """
        p_drive = Path(drive_path)
        if not p_drive.exists():
            raise FileNotFoundError(f"Drive {drive_path} tidak ditemukan.")

        serial = cls.get_volume_serial(drive_path) or "VIRTUAL-DONGLE-SN-001"
        random_token = os.urandom(32).hex()

        # Write hidden token file
        token_file = p_drive / TOKEN_FILENAME
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(f"SECUREVAULT-TOKEN-V1:{user_id}:{random_token}")

        # Set hidden file attribute on Windows if it's a real drive
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(str(token_file), FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass

        fingerprint = cls.compute_fingerprint(serial, random_token)
        return {
            "fingerprint": fingerprint,
            "serial": serial,
            "token_file": str(token_file),
            "label": f"Security Dongle ({drive_path})"
        }

    @classmethod
    def verify_dongle_for_user(cls, registered_fingerprints: list[str]) -> tuple[bool, str]:
        """
        Scan connected USB devices to verify if any matches user's registered fingerprint.
        """
        if not registered_fingerprints:
            return True, "Tidak ada USB Dongle yang diwajibkan untuk pengguna ini."

        drives = cls.list_connected_usb_drives()
        
        for d in drives:
            token_file = Path(d["token_file"])
            if token_file.exists():
                try:
                    with open(token_file, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    parts = content.split(":")
                    if len(parts) >= 3 and parts[0] == "SECUREVAULT-TOKEN-V1":
                        token_secret = parts[2]
                        fp = cls.compute_fingerprint(d["serial"], token_secret)
                        if fp in registered_fingerprints:
                            virtual_note = " (Virtual Dev Token)" if d["is_virtual"] else ""
                            return True, f"USB Dongle Terverifikasi: {d['label']}{virtual_note}"
                except Exception:
                    continue

        if DEV_MODE:
            return True, "[DEV MODE] USB Dongle terdaftar tidak terdeteksi, namun login diizinkan dalam Dev Mode."
        
        return False, "Akses Ditolak: USB Security Dongle yang terdaftar belum ditancapkan ke komputer."
