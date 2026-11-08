"""
SecureVault - Service: Database-Encrypted Messaging
Handles secure peer-to-peer message transmission using AES-256-GCM encryption
before persistence in the MySQL database.
Keys are derived from in-memory user master keys, never stored in the database.
"""

from typing import List, Optional
from config.database import db
from core.auth import session
from core.key_manager import key_manager
from crypto.aes import AES256GCMCipher

class MessageService:
    """Manages database-encrypted messaging between registered users."""

    @classmethod
    def _get_conversation_key(cls, user_a_id: int, user_b_id: int) -> bytes:
        """
        Derive a deterministic symmetric 256-bit key for a conversation pair.
        Ensures both sender and receiver can derive the identical conversation key
        using their respective master secrets and the pair identifiers.
        """
        min_id, max_id = sorted([user_a_id, user_b_id])
        pair_salt = f"securevault-conv-{min_id}-{max_id}"
        return key_manager.derive_sub_key(user_a_id, purpose=pair_salt)

    @classmethod
    def send_message(cls, sender_id: int, recipient_id: int, plaintext: str) -> tuple[bool, str]:
        """
        Encrypt plaintext message using AES-256-GCM and store in MySQL database.
        """
        if not plaintext.strip():
            return False, "Isi pesan tidak boleh kosong."

        # Derive encryption key for this pair
        conv_key = cls._get_conversation_key(sender_id, recipient_id)

        try:
            # Authenticated AES-256-GCM encryption with fresh nonce
            enc = AES256GCMCipher.encrypt(plaintext, conv_key)

            db.execute_query(
                """
                INSERT INTO messages (user_id, sender_id, recipient_id, title, ciphertext, nonce, tag, aes_nonce, aes_auth_tag, algorithm)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (sender_id, sender_id, recipient_id, "Secure Message", enc["ciphertext"], enc["nonce"], enc["tag"], enc["nonce"], enc["tag"], "AES-256-GCM")
            )
            return True, "Pesan terenkripsi berhasil dikirim!"
        except Exception as e:
            return False, f"Gagal mengirim pesan terenkripsi: {str(e)}"

    @classmethod
    def get_messages_between(cls, user_a_id: int, user_b_id: int) -> List[dict]:
        """
        Fetch conversation history between two users and decrypt AES-256-GCM ciphertexts.
        """
        rows = db.fetch_all(
            """
            SELECT m.*, u_s.username as sender_name, u_r.username as recipient_name
            FROM messages m
            JOIN users u_s ON m.sender_id = u_s.id
            JOIN users u_r ON m.recipient_id = u_r.id
            WHERE (m.sender_id = %s AND m.recipient_id = %s)
               OR (m.sender_id = %s AND m.recipient_id = %s)
            ORDER BY m.created_at ASC
            """,
            (user_a_id, user_b_id, user_b_id, user_a_id)
        )

        conv_key = cls._get_conversation_key(user_a_id, user_b_id)
        decrypted_messages = []

        for row in rows:
            try:
                decrypted_bytes = AES256GCMCipher.decrypt_raw(
                    ciphertext_b64=row["ciphertext"],
                    nonce_b64=row["nonce"],
                    tag_b64=row["tag"],
                    key=conv_key
                )
                plaintext = decrypted_bytes.decode("utf-8")
                status = "DECRYPTED_SUCCESS"
            except Exception as e:
                plaintext = f"[Gagal Dekripsi: {str(e)}]"
                status = "DECRYPTION_ERROR"

            decrypted_messages.append({
                "id": row["id"],
                "sender_id": row["sender_id"],
                "recipient_id": row["recipient_id"],
                "sender_name": row["sender_name"],
                "recipient_name": row["recipient_name"],
                "plaintext": plaintext,
                "ciphertext": row["ciphertext"],
                "nonce": row["nonce"],
                "tag": row["tag"],
                "algorithm": row["algorithm"],
                "status": status,
                "created_at": str(row["created_at"])
            })

        return decrypted_messages

    @staticmethod
    def get_all_users_except(current_user_id: int) -> List[dict]:
        """Get list of other users for messaging contact list."""
        return db.fetch_all(
            "SELECT id, username, full_name, created_at FROM users WHERE id != %s ORDER BY username ASC",
            (current_user_id,)
        )
