"""
SecureVault - Service: Asset Integrity Blockchain
Implements a simple cryptographic blockchain to record and audit
the tamper-evident integrity of sensitive vault assets (files, stego images, logs).
Uses SHA-256 chaining.
"""

import hashlib
from datetime import datetime
from typing import List, Optional
from config.database import db

class BlockchainService:
    """Manages simple blockchain operations, block mining, and integrity audits."""

    GENESIS_PREV_HASH = "0" * 64

    @classmethod
    def calculate_block_hash(cls, index: int, timestamp: str, asset_name: str, asset_type: str, asset_hash: str, previous_hash: str, nonce: int = 0) -> str:
        """Calculate SHA-256 block hash over all block fields."""
        payload = f"{index}|{timestamp}|{asset_name}|{asset_type}|{asset_hash}|{previous_hash}|{nonce}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def ensure_genesis_block(cls):
        """Ensure Genesis block #0 exists in database."""
        genesis = db.fetch_one("SELECT * FROM blockchain WHERE block_index = 0")
        if not genesis:
            ts = "2026-01-01 00:00:00"
            asset_hash = hashlib.sha256(b"SECUREVAULT_GENESIS_ROOT").hexdigest()
            b_hash = cls.calculate_block_hash(
                index=0,
                timestamp=ts,
                asset_name="GENESIS_ROOT_ASSET",
                asset_type="SYSTEM",
                asset_hash=asset_hash,
                previous_hash=cls.GENESIS_PREV_HASH,
                nonce=0
            )
            db.execute_query(
                """
                INSERT INTO blockchain (block_index, timestamp, asset_name, asset_type, asset_hash, previous_hash, nonce, block_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (0, ts, "GENESIS_ROOT_ASSET", "SYSTEM", asset_hash, cls.GENESIS_PREV_HASH, 0, b_hash)
            )

    @classmethod
    def get_latest_block(cls) -> dict:
        """Fetch the most recent block in the chain."""
        cls.ensure_genesis_block()
        latest = db.fetch_one("SELECT * FROM blockchain ORDER BY block_index DESC LIMIT 1")
        return latest

    @classmethod
    def add_asset_block(cls, asset_name: str, asset_type: str, asset_hash: str) -> dict:
        """
        Create and append a new block to the blockchain anchoring an asset.
        """
        cls.ensure_genesis_block()
        latest = cls.get_latest_block()
        
        new_index = latest["block_index"] + 1
        previous_hash = latest["block_hash"]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nonce = 0

        # Optional simple proof-of-work (e.g. hash starting with '0') for demonstration
        while True:
            candidate_hash = cls.calculate_block_hash(
                index=new_index,
                timestamp=timestamp,
                asset_name=asset_name,
                asset_type=asset_type,
                asset_hash=asset_hash,
                previous_hash=previous_hash,
                nonce=nonce
            )
            if candidate_hash.startswith("0"):  # Light difficulty for smooth instant UI response
                block_hash = candidate_hash
                break
            nonce += 1

        db.execute_query(
            """
            INSERT INTO blockchain (block_index, timestamp, asset_name, asset_type, asset_hash, previous_hash, nonce, block_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (new_index, timestamp, asset_name, asset_type, asset_hash, previous_hash, nonce, block_hash)
        )

        return {
            "block_index": new_index,
            "timestamp": timestamp,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "asset_hash": asset_hash,
            "previous_hash": previous_hash,
            "nonce": nonce,
            "block_hash": block_hash
        }

    @classmethod
    def get_all_blocks(cls) -> List[dict]:
        """Fetch all blocks in chain order."""
        cls.ensure_genesis_block()
        return db.fetch_all("SELECT * FROM blockchain ORDER BY block_index ASC")

    @classmethod
    def audit_chain_integrity(cls) -> dict:
        """
        Comprehensive blockchain verification.
        Validates hash linkage and content hash for every block in the database.
        Detects database tampering.
        """
        blocks = cls.get_all_blocks()
        if not blocks:
            return {"valid": True, "total_blocks": 0, "message": "Blockchain kosong."}

        for i, block in enumerate(blocks):
            # Recalculate block hash
            expected_hash = cls.calculate_block_hash(
                index=block["block_index"],
                timestamp=str(block["timestamp"]),
                asset_name=block["asset_name"],
                asset_type=block["asset_type"],
                asset_hash=block["asset_hash"],
                previous_hash=block["previous_hash"],
                nonce=block["nonce"]
            )

            # Check if block data was altered
            if block["block_hash"] != expected_hash:
                return {
                    "valid": False,
                    "tampered_index": block["block_index"],
                    "reason": f"Hash manipulasi terdeteksi pada Blok #{block['block_index']}! (Tersimpan: {block['block_hash'][:16]}..., Dihitung: {expected_hash[:16]}...)",
                    "total_blocks": len(blocks)
                }

            # Check chain linkage
            if i > 0:
                prev_block = blocks[i - 1]
                if block["previous_hash"] != prev_block["block_hash"]:
                    return {
                        "valid": False,
                        "tampered_index": block["block_index"],
                        "reason": f"Rantai terputus pada Blok #{block['block_index']}! Previous hash tidak cocok dengan hash Blok #{prev_block['block_index']}.",
                        "total_blocks": len(blocks)
                    }

        return {
            "valid": True,
            "total_blocks": len(blocks),
            "message": f"Seluruh rantai valid! {len(blocks)} blok diverifikasi secara kriptografis tanpa manipulasi data."
        }
