-- Logical schema for Threat Intelligence Sharing (SQLAlchemy creates tables automatically).
-- Use this file as documentation or for manual PostgreSQL setup.

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'analyst',
    organization_name VARCHAR(200),
    wallet_address VARCHAR(42),
    wallet_private_key_encrypted TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE INDEX IF NOT EXISTS ix_users_wallet_address ON users (wallet_address);

CREATE TABLE IF NOT EXISTS threat_reports (
    id SERIAL PRIMARY KEY,
    organization_name VARCHAR(200) NOT NULL,
    attack_title VARCHAR(500) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    ioc_ips TEXT DEFAULT '',
    ioc_hashes TEXT DEFAULT '',
    ioc_domains TEXT DEFAULT '',
    attack_description TEXT NOT NULL,
    how_it_happened TEXT NOT NULL,
    impact TEXT NOT NULL,
    mitigation TEXT NOT NULL,
    date_of_attack VARCHAR(32) NOT NULL,
    report_hash VARCHAR(66) NOT NULL UNIQUE,
    ipfs_hash VARCHAR(200) NOT NULL,
    submitter_user_id INTEGER REFERENCES users (id),
    tx_hash VARCHAR(66),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_threat_reports_attack_type ON threat_reports (attack_type);
CREATE INDEX IF NOT EXISTS ix_threat_reports_report_hash ON threat_reports (report_hash);
