"""Application configuration loaded from environment variables."""
import os
from pathlib import Path

from dotenv import load_dotenv

_env = Path(__file__).resolve().parent / ".env"
load_dotenv(_env)


class Config:
    BASE_DIR = Path(__file__).resolve().parent.parent
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me-in-production")
    JWT_SECRET = os.environ.get("JWT_SECRET", "jwt-dev-change-me")
    JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "24"))

    # SQLite by default for easy local runs; set DATABASE_URL for PostgreSQL
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'database' / 'threat_intel.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Ethereum / Hardhat local node
    ETH_RPC_URL = os.environ.get("ETH_RPC_URL", "http://127.0.0.1:8545")
    CONTRACT_ADDRESS = (os.environ.get("CONTRACT_ADDRESS") or "").strip()

    # Admin wallet (deployer): registers org addresses on-chain
    ADMIN_PRIVATE_KEY = os.environ.get("ADMIN_PRIVATE_KEY", "")

    # Optional Fernet key (44-char urlsafe base64) for encrypting org private keys at rest
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")

    IPFS_API = os.environ.get("IPFS_API", "/ip4/127.0.0.1/tcp/5001")

    # HTTPS: in production terminate TLS at reverse proxy; Flask runs HTTP behind nginx
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "http")

    # First-time admin bootstrap (optional)
    BOOTSTRAP_ADMIN_USERNAME = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "")
    BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
