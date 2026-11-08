"""
SecureVault - Core Authentication & Session Manager
Maintains active user context, authentication state, and session lifecycles.
"""

from typing import Optional
from core.key_manager import key_manager

class SessionManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SessionManager, cls).__new__(cls)
            cls._instance._current_user = None
        return cls._instance

    def login(self, user_dict: dict, password: str):
        """Set the active user and initialize in-memory master cryptographic key."""
        self._current_user = user_dict
        user_id = user_dict["id"]
        salt = user_dict.get("salt", "")
        key_manager.set_user_master_key(user_id, password, salt)

    def logout(self):
        """Clear active user session and purge keys from memory."""
        if self._current_user:
            key_manager.clear_user_key(self._current_user["id"])
            self._current_user = None

    def is_authenticated(self) -> bool:
        """Check if an active session exists."""
        return self._current_user is not None

    def get_user(self) -> Optional[dict]:
        """Get currently logged-in user dictionary."""
        return self._current_user

    def get_user_id(self) -> Optional[int]:
        """Get ID of the current user."""
        return self._current_user["id"] if self._current_user else None

    def get_username(self) -> Optional[str]:
        """Get username of the current user."""
        return self._current_user["username"] if self._current_user else None

session = SessionManager()
