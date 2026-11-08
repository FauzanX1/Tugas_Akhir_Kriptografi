"""
SecureVault - Key Manager
Manages memory-resident encryption keys, master secret derivation,
and ensures keys are never persisted in plaintext.
"""

import os
from typing import Optional
from core.security import derive_key
from config.settings import APP_SECRET_KEY

class KeyManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(KeyManager, cls).__new__(cls)
            cls._instance._user_keys = {}
        return cls._instance

    def set_user_master_key(self, user_id: int, password: str, user_salt: str):
        """
        Derive and store the user's master cryptographic key in memory.
        Combines user password, user-specific salt, and application master secret.
        """
        combined_secret = f"{password}:{APP_SECRET_KEY.decode('utf-8', errors='ignore')}"
        derived_key = derive_key(
            secret=combined_secret,
            salt=user_salt,
            length=32,
            info=b"securevault-user-master-key"
        )
        self._user_keys[user_id] = derived_key

    def get_user_master_key(self, user_id: int) -> Optional[bytes]:
        """Retrieve the in-memory master key for the user."""
        return self._user_keys.get(user_id)

    def clear_user_key(self, user_id: int):
        """Wipe the user's key from memory upon logout."""
        if user_id in self._user_keys:
            del self._user_keys[user_id]

    def derive_sub_key(self, user_id: int, purpose: str) -> bytes:
        """Derive a purpose-specific key (e.g. 'messages', 'files', 'stego')."""
        master_key = self.get_user_master_key(user_id)
        if not master_key:
            # Fallback for demonstration/dev mode if not logged in
            master_key = derive_key(APP_SECRET_KEY, "dev_salt", length=32)
        
        return derive_key(
            secret=master_key,
            salt=purpose.encode("utf-8"),
            length=32,
            info=f"securevault-{purpose}-subkey".encode("utf-8")
        )

key_manager = KeyManager()
