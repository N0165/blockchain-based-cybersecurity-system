"""SQLAlchemy models: users, roles, and threat report metadata."""
import enum
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ORGANIZATION = "organization"
    ANALYST = "analyst"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    # String storage works cleanly with SQLite and PostgreSQL
    role = db.Column(db.String(20), nullable=False, default=UserRole.ANALYST.value)
    organization_name = db.Column(db.String(200), nullable=True)
    # Ethereum identity for on-chain submissions (organization users)
    wallet_address = db.Column(db.String(42), nullable=True, index=True)
    wallet_private_key_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_public_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "organization_name": self.organization_name,
            "wallet_address": self.wallet_address,
        }


class ThreatReport(db.Model):
    """Off-chain index of reports; integrity anchor lives on blockchain + payload on IPFS."""

    __tablename__ = "threat_reports"

    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.String(200), nullable=False)
    attack_title = db.Column(db.String(500), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False, index=True)
    ioc_ips = db.Column(db.Text, default="")
    ioc_hashes = db.Column(db.Text, default="")
    ioc_domains = db.Column(db.Text, default="")
    attack_description = db.Column(db.Text, nullable=False)
    how_it_happened = db.Column(db.Text, nullable=False)
    impact = db.Column(db.Text, nullable=False)
    mitigation = db.Column(db.Text, nullable=False)
    date_of_attack = db.Column(db.String(32), nullable=False)
    # Integrity & storage
    report_hash = db.Column(db.String(66), nullable=False, unique=True, index=True)  # 0x + 64 hex
    ipfs_hash = db.Column(db.String(200), nullable=False)
    submitter_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    tx_hash = db.Column(db.String(66), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    submitter = db.relationship("User", backref=db.backref("reports", lazy="dynamic"))

    def to_dict(self):
        return {
            "id": self.id,
            "organization_name": self.organization_name,
            "attack_title": self.attack_title,
            "attack_type": self.attack_type,
            "ioc": {
                "ips": self.ioc_ips,
                "hashes": self.ioc_hashes,
                "domains": self.ioc_domains,
            },
            "attack_description": self.attack_description,
            "how_it_happened": self.how_it_happened,
            "impact": self.impact,
            "mitigation": self.mitigation,
            "date_of_attack": self.date_of_attack,
            "report_hash": self.report_hash,
            "ipfs_hash": self.ipfs_hash,
            "tx_hash": self.tx_hash,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }
