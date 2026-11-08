"""
SecureVault - Service: Authentication & User Management
Coordinates Argon2id password hashing, multi-factor hardware checks (Dongle, Windows Hello),
and session lifecycle.
"""

from typing import Optional
from config.database import db
from core.security import hash_password, verify_password, generate_salt
from core.auth import session
from hardware.biometric import BiometricAuth
from hardware.dongle import USBDongleAuth

class AuthService:
    """Manages authentication, registration, and user security policies."""

    @staticmethod
    def register(username: str, password: str, full_name: str = "") -> tuple[bool, str]:
        """Register a new user account with Argon2id password hash."""
        username = username.strip()
        if len(username) < 3:
            return False, "Username harus memiliki minimal 3 karakter."
        if len(password) < 6:
            return False, "Password harus memiliki minimal 6 karakter."

        # Check existing username
        existing = db.fetch_one("SELECT id FROM users WHERE username = %s", (username,))
        if existing:
            return False, f"Username '{username}' sudah terdaftar. Silakan pilih username lain."

        salt = generate_salt(16)
        pwd_hash = hash_password(password)
        email = f"{username}@securevault.local"

        try:
            user_id = db.insert_get_id(
                "INSERT INTO users (username, email, password_hash, salt, full_name) VALUES (%s, %s, %s, %s, %s)",
                (username, email, pwd_hash, salt, full_name)
            )
            # Log activity
            db.execute_query(
                "INSERT INTO activity_logs (user_id, action, details) VALUES (%s, %s, %s)",
                (user_id, "USER_REGISTER", f"Pengguna {username} berhasil didaftarkan.")
            )
            return True, "Registrasi akun berhasil!"
        except Exception as e:
            return False, f"Terjadi kesalahan saat registrasi: {str(e)}"

    @staticmethod
    def login(username: str, password: str, require_biometric: bool = False, require_dongle: bool = False) -> tuple[bool, str]:
        """
        Authenticate user with Argon2id password verification,
        followed by Windows Hello and USB Dongle verification if enabled.
        """
        username = username.strip()
        user = db.fetch_one("SELECT * FROM users WHERE username = %s", (username,))
        if not user:
            return False, "Username atau password salah."

        # 1. Verify Argon2id password hash
        if not verify_password(user["password_hash"], password):
            db.execute_query(
                "INSERT INTO activity_logs (user_id, action, details, status) VALUES (%s, %s, %s, %s)",
                (user["id"], "LOGIN_FAILED", "Password tidak cocok.", "FAILED")
            )
            return False, "Username atau password salah."

        # 2. Check USB Dongle if required by user settings or global flag
        must_check_dongle = user.get("dongle_enabled", 0) == 1 or require_dongle
        if must_check_dongle:
            registered_dongles = db.fetch_all(
                "SELECT dongle_fingerprint FROM dongles WHERE user_id = %s",
                (user["id"],)
            )
            fingerprints = [d["dongle_fingerprint"] for d in registered_dongles]
            dongle_ok, dongle_msg = USBDongleAuth.verify_dongle_for_user(fingerprints)
            if not dongle_ok:
                return False, dongle_msg

        # 3. Check Windows Hello Biometric if required
        must_check_biometric = user.get("biometric_enabled", 0) == 1 or require_biometric
        if must_check_biometric:
            bio_ok, bio_msg = BiometricAuth.verify_biometric(
                prompt_message=f"Verifikasi identitas Windows Hello untuk akun {username}"
            )
            if not bio_ok:
                return False, bio_msg

        # Login success: initialize session & keys
        session.login(user, password)
        db.execute_query(
            "INSERT INTO activity_logs (user_id, action, details) VALUES (%s, %s, %s)",
            (user["id"], "LOGIN_SUCCESS", f"Pengguna {username} berhasil login.")
        )
        return True, "Login berhasil!"

    @staticmethod
    def get_user_security_settings(user_id: int) -> dict:
        """Fetch MFA configuration for user."""
        user = db.fetch_one("SELECT biometric_enabled, dongle_enabled FROM users WHERE id = %s", (user_id,))
        dongles = db.fetch_all("SELECT * FROM dongles WHERE user_id = %s", (user_id,))
        return {
            "biometric_enabled": bool(user["biometric_enabled"]) if user else False,
            "dongle_enabled": bool(user["dongle_enabled"]) if user else False,
            "registered_dongles": dongles
        }

    @staticmethod
    def update_security_settings(user_id: int, biometric_enabled: bool, dongle_enabled: bool):
        """Update MFA configuration flags for user."""
        db.execute_query(
            "UPDATE users SET biometric_enabled = %s, dongle_enabled = %s WHERE id = %s",
            (1 if biometric_enabled else 0, 1 if dongle_enabled else 0, user_id)
        )

    @staticmethod
    def register_usb_dongle(user_id: int, drive_path: str, label: str = "USB Key") -> tuple[bool, str]:
        """Register a new USB drive as hardware dongle."""
        try:
            reg_info = USBDongleAuth.register_dongle_on_drive(drive_path, user_id)
            db.execute_query(
                "INSERT INTO dongles (user_id, dongle_fingerprint, dongle_label) VALUES (%s, %s, %s)",
                (user_id, reg_info["fingerprint"], label or reg_info["label"])
            )
            db.execute_query("UPDATE users SET dongle_enabled = 1 WHERE id = %s", (user_id,))
            return True, f"USB Dongle berhasil didaftarkan: {reg_info['serial']}"
        except Exception as e:
            return False, f"Gagal mendaftarkan USB Dongle: {str(e)}"
