-- SecureVault Database Schema
-- Database Name: securevault

CREATE DATABASE IF NOT EXISTS securevault CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securevault;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    full_name VARCHAR(128) DEFAULT NULL,
    biometric_enabled TINYINT(1) DEFAULT 0,
    dongle_enabled TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Messages Table (Encrypted with AES-256-GCM)
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    ciphertext MEDIUMTEXT NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    tag VARCHAR(64) NOT NULL,
    algorithm VARCHAR(32) NOT NULL DEFAULT 'AES-256-GCM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 3. Files Table (Encrypted with ChaCha20-Poly1305)
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    storage_name VARCHAR(255) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    algorithm VARCHAR(32) NOT NULL DEFAULT 'ChaCha20-Poly1305',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4. Steganography Records Table
CREATE TABLE IF NOT EXISTS steganography (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    image_name VARCHAR(255) NOT NULL,
    original_image_path VARCHAR(512) DEFAULT NULL,
    stego_image_path VARCHAR(512) NOT NULL,
    payload_size_bytes INT NOT NULL,
    algorithm VARCHAR(64) NOT NULL DEFAULT 'LSB + AES-256-GCM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. Blockchain Table (Asset Integrity Log)
CREATE TABLE IF NOT EXISTS blockchain (
    id INT AUTO_INCREMENT PRIMARY KEY,
    block_index INT NOT NULL UNIQUE,
    timestamp VARCHAR(32) NOT NULL,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL DEFAULT 'ASSET',
    asset_hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    nonce INT NOT NULL DEFAULT 0,
    block_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 6. Dongles Table
CREATE TABLE IF NOT EXISTS dongles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    dongle_fingerprint VARCHAR(255) NOT NULL,
    dongle_label VARCHAR(128) DEFAULT 'USB Security Token',
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7. Activity Logs Table
CREATE TABLE IF NOT EXISTS activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(64) NOT NULL,
    details TEXT DEFAULT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;
