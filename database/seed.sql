-- SecureVault Initial Seed Data
USE securevault;

-- Genesis Block for Blockchain
INSERT INTO blockchain (block_index, timestamp, asset_name, asset_type, asset_hash, previous_hash, nonce, block_hash)
VALUES (
    0,
    '2026-01-01 00:00:00',
    'GENESIS_ROOT',
    'SYSTEM',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '0000000000000000000000000000000000000000000000000000000000000000',
    0,
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
)
ON DUPLICATE KEY UPDATE block_index=block_index;
