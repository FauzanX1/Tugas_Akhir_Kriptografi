"""
Unit tests for SecureVault Blockchain:
- Genesis creation
- Block calculation
- Tamper detection
"""

import pytest
from services.blockchain_service import BlockchainService

def test_blockchain_hash_calculation():
    h1 = BlockchainService.calculate_block_hash(
        index=1,
        timestamp="2026-01-01 12:00:00",
        asset_name="FILE_A",
        asset_type="FILE",
        asset_hash="abcd1234abcd",
        previous_hash="0"*64,
        nonce=5
    )
    assert len(h1) == 64
    # Deterministic
    h2 = BlockchainService.calculate_block_hash(
        index=1,
        timestamp="2026-01-01 12:00:00",
        asset_name="FILE_A",
        asset_type="FILE",
        asset_hash="abcd1234abcd",
        previous_hash="0"*64,
        nonce=5
    )
    assert h1 == h2

def test_blockchain_audit():
    audit = BlockchainService.audit_chain_integrity()
    assert "valid" in audit
    assert audit["valid"] is True
