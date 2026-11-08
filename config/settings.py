"""
SecureVault - Configuration Settings
Handles environment loading, application directories, and security constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory of Project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)
else:
    load_dotenv()

# Database Settings (MySQL on XAMPP)
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "securevault")

# Storage Directories
STORAGE_DIR = BASE_DIR / "storage"
ENCRYPTED_FILES_DIR = STORAGE_DIR / "encrypted_files"
DECRYPTED_FILES_DIR = STORAGE_DIR / "decrypted_files"
STEGO_IMAGES_DIR = STORAGE_DIR / "stego_images"

for path in [STORAGE_DIR, ENCRYPTED_FILES_DIR, DECRYPTED_FILES_DIR, STEGO_IMAGES_DIR]:
    path.mkdir(parents=True, exist_ok=True)

# Hardware & Security Settings
DEV_MODE = os.getenv("DEV_MODE", "true").lower() in ("true", "1", "yes")
REQUIRE_USB_DONGLE = os.getenv("REQUIRE_USB_DONGLE", "false").lower() in ("true", "1", "yes")
REQUIRE_BIOMETRIC = os.getenv("REQUIRE_BIOMETRIC", "false").lower() in ("true", "1", "yes")
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "securevault_master_entropy_salt_2026_default").encode("utf-8")

# App Metadata
APP_NAME = "SecureVault"
APP_SUBTITLE = "Secure Communication & Data Protection System"
APP_VERSION = "1.0.0"
