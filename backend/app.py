"""
Flask API: JWT auth, RBAC, threat submission, IPFS + Ethereum anchors.
"""
from __future__ import annotations

import datetime
import logging
import re
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from crypto_util import decrypt_private_key, encrypt_private_key
from models import User, UserRole, ThreatReport, db
from ipfs_service import add_json
from blockchain_service import (
    canonical_payload_hash,
    fetch_chain_reports,
    fund_org_wallet,
    register_org_on_chain,
    submit_report_on_chain,
    verify_on_chain,
)
from eth_account import Account

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("threat_intel")

ATTACK_TYPES = frozenset(
    {
        "DDoS",
        "Phishing",
        "Malware",
        "Ransomware",
        "SQL Injection",
        "Insider Threat",
        "Supply Chain",
        "Other",
    }
)


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    db.init_app(app)

    with app.app_context():
        db_path = app.config["BASE_DIR"] / "database"
        db_path.mkdir(parents=True, exist_ok=True)
        db.create_all()
        _bootstrap_admin(app)

    @app.after_request
    def add_security_headers(resp):
        # Encourage HTTPS in production behind TLS terminator
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        return resp

    # --- Auth helpers ---

    def jwt_encode(user: User) -> str:
        exp = datetime.datetime.utcnow() + datetime.timedelta(
            hours=app.config["JWT_EXPIRATION_HOURS"]
        )
        payload = {
            "sub": user.id,
            "role": user.role,
            "username": user.username,
            "exp": exp,
        }
        return jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")

    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"ok": False, "error": "Missing or invalid Authorization"}), 401
            token = auth[7:].strip()
            try:
                data = jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
                g.user_id = data["sub"]
                g.role = data["role"]
                g.username = data.get("username", "")
            except jwt.ExpiredSignatureError:
                return jsonify({"ok": False, "error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"ok": False, "error": "Invalid token"}), 401
            return f(*args, **kwargs)

        return decorated

    def require_roles(*roles):
        def deco(f):
            @wraps(f)
            def inner(*args, **kwargs):
                if g.role not in roles:
                    return jsonify({"ok": False, "error": "Insufficient role"}), 403
                return f(*args, **kwargs)

            return inner

        return deco

    def get_user():
        return User.query.get(g.user_id)

    # --- Validation ---

    def validate_register(body):
        err = None
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        org_name = (body.get("organization_name") or "").strip()
        role_s = (body.get("role") or "analyst").strip().lower()
        if len(username) < 3 or len(username) > 80:
            err = "username length 3-80"
        elif len(password) < 8:
            err = "password min 8 characters"
        elif role_s not in ("organization", "analyst"):
            err = "role must be organization or analyst"
        elif role_s == "organization" and (len(org_name) < 2 or len(org_name) > 200):
            err = "organization_name required for organization role"
        return username, password, org_name, role_s, err

    def validate_threat(body):
        required = [
            "organization_name",
            "attack_title",
            "attack_type",
            "attack_description",
            "how_it_happened",
            "impact",
            "mitigation",
            "date_of_attack",
        ]
        for k in required:
            if not (body.get(k) or "").strip():
                return None, f"missing field: {k}"
        at = (body.get("attack_type") or "").strip()
        if at not in ATTACK_TYPES:
            return None, f"attack_type must be one of: {', '.join(sorted(ATTACK_TYPES))}"
        return {
            "organization_name": body["organization_name"].strip()[:200],
            "attack_title": body["attack_title"].strip()[:500],
            "attack_type": at,
            "ioc_ips": (body.get("ioc_ips") or "").strip()[:2000],
            "ioc_hashes": (body.get("ioc_hashes") or "").strip()[:2000],
            "ioc_domains": (body.get("ioc_domains") or "").strip()[:2000],
            "attack_description": body["attack_description"].strip()[:20000],
            "how_it_happened": body["how_it_happened"].strip()[:20000],
            "impact": body["impact"].strip()[:20000],
            "mitigation": body["mitigation"].strip()[:20000],
            "date_of_attack": body["date_of_attack"].strip()[:32],
        }, None

    # --- Routes ---

    @app.route("/api/health")
    def health():
        return jsonify({"ok": True, "service": "threat-intel-api"})

    @app.route("/api/register", methods=["POST"])
    def register():
        body = request.get_json(silent=True) or {}
        username, password, org_name, role_s, err = validate_register(body)
        if err:
            return jsonify({"ok": False, "error": err}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"ok": False, "error": "username taken"}), 409

        role_val = UserRole.ORGANIZATION.value if role_s == "organization" else UserRole.ANALYST.value
        wallet_address = None
        wallet_enc = None

        if role_s == "organization":
            acct = Account.create()
            wallet_address = acct.address
            wallet_enc = encrypt_private_key(app.config, acct.key.hex())

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role_val,
            organization_name=org_name if role_s == "organization" else None,
            wallet_address=wallet_address,
            wallet_private_key_encrypted=wallet_enc,
        )
        db.session.add(user)
        db.session.commit()

        # Register org wallet on-chain (admin key) + fund for gas on local networks
        if role_s == "organization" and wallet_address and org_name:
            try:
                tx = register_org_on_chain(app.config, wallet_address, org_name)
                log.info("Org registered on-chain tx=%s user=%s", tx, username)
                fund_org_wallet(app.config, wallet_address)
            except Exception as e:
                # In dev/education setups the local chain (RPC/contract) may be offline.
                # Don't fail account creation; allow the user to register and use off-chain APIs.
                log.exception("Org on-chain onboarding failed for user=%s: %s", username, e)

        token = jwt_encode(user)
        return jsonify({"ok": True, "token": token, "user": user.to_public_dict()}), 201

    @app.route("/api/login", methods=["POST"])
    def login():
        body = request.get_json(silent=True) or {}
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"ok": False, "error": "Invalid credentials"}), 401
        token = jwt_encode(user)
        return jsonify({"ok": True, "token": token, "user": user.to_public_dict()})

    @app.route("/api/submitThreat", methods=["POST"])
    @token_required
    @require_roles(UserRole.ADMIN.value, UserRole.ORGANIZATION.value)
    def submit_threat():
        body = request.get_json(silent=True) or {}
        data, err = validate_threat(body)
        if err:
            return jsonify({"ok": False, "error": err}), 400

        user = get_user()
        if user.role == UserRole.ORGANIZATION.value:
            data["organization_name"] = user.organization_name or data["organization_name"]

        ipfs_payload = {**data, "submitted_by_user_id": user.id}
        ipfs_cid = add_json(app.config, ipfs_payload)
        report_hash_bytes = canonical_payload_hash(ipfs_payload)
        report_hash_hex = "0x" + report_hash_bytes.hex()

        existing = ThreatReport.query.filter_by(report_hash=report_hash_hex).first()
        if existing:
            return jsonify({"ok": False, "error": "duplicate content hash"}), 409

        tx_hash = None
        if user.role == UserRole.ORGANIZATION.value and user.wallet_private_key_encrypted:
            pk = decrypt_private_key(app.config, user.wallet_private_key_encrypted)
            try:
                tx_hash = submit_report_on_chain(
                    app.config,
                    pk,
                    report_hash_bytes,
                    ipfs_cid,
                    data["organization_name"],
                )
            except Exception as e:
                log.exception("On-chain submit failed: %s", e)
                return jsonify({"ok": False, "error": f"blockchain submit failed: {e!s}"}), 502
        elif user.role == UserRole.ADMIN.value:
            # Admin can record in DB + IPFS; optional: use env ORG key for chain — skip or document
            log.info("Admin submit stored off-chain anchor only unless org wallet used")

        rec = ThreatReport(
            organization_name=data["organization_name"],
            attack_title=data["attack_title"],
            attack_type=data["attack_type"],
            ioc_ips=data["ioc_ips"],
            ioc_hashes=data["ioc_hashes"],
            ioc_domains=data["ioc_domains"],
            attack_description=data["attack_description"],
            how_it_happened=data["how_it_happened"],
            impact=data["impact"],
            mitigation=data["mitigation"],
            date_of_attack=data["date_of_attack"],
            report_hash=report_hash_hex,
            ipfs_hash=ipfs_cid,
            submitter_user_id=user.id,
            tx_hash=tx_hash,
        )
        db.session.add(rec)
        db.session.commit()

        return jsonify(
            {
                "ok": True,
                "report": rec.to_dict(),
                "report_hash": report_hash_hex,
                "ipfs_hash": ipfs_cid,
                "tx_hash": tx_hash,
            }
        ), 201

    @app.route("/api/getThreats", methods=["GET"])
    @token_required
    def get_threats():
        q = ThreatReport.query
        attack_type = request.args.get("attack_type")
        if attack_type:
            q = q.filter_by(attack_type=attack_type.strip())
        rows = q.order_by(ThreatReport.created_at.desc()).limit(500).all()
        return jsonify({"ok": True, "threats": [r.to_dict() for r in rows]})

    @app.route("/api/verifyThreat", methods=["POST"])
    @token_required
    def verify_threat():
        body = request.get_json(silent=True) or {}
        rh = (body.get("report_hash") or "").strip()
        if not rh or not re.match(r"^0x[a-fA-F0-9]{64}$", rh):
            return jsonify({"ok": False, "error": "report_hash must be 0x + 64 hex chars"}), 400
        chain_ok = verify_on_chain(app.config, rh)
        local = ThreatReport.query.filter_by(report_hash=rh.lower()).first()
        return jsonify(
            {
                "ok": True,
                "report_hash": rh.lower(),
                "verified_on_chain": chain_ok,
                "found_in_database": local is not None,
                "database_record": local.to_dict() if local else None,
            }
        )

    @app.route("/api/stats", methods=["GET"])
    @token_required
    def stats():
        from sqlalchemy import func

        total = ThreatReport.query.count()
        by_type = (
            db.session.query(ThreatReport.attack_type, func.count(ThreatReport.id))
            .group_by(ThreatReport.attack_type)
            .all()
        )
        recent = (
            ThreatReport.query.order_by(ThreatReport.created_at.desc()).limit(10).all()
        )
        chain_count = len(fetch_chain_reports(app.config)) if app.config.get("CONTRACT_ADDRESS") else 0
        return jsonify(
            {
                "ok": True,
                "total_reports": total,
                "attack_types": {t: c for t, c in by_type},
                "on_chain_reports": chain_count,
                "recent": [r.to_dict() for r in recent],
            }
        )

    @app.route("/api/chainThreats", methods=["GET"])
    @token_required
    @require_roles(UserRole.ADMIN.value, UserRole.ANALYST.value, UserRole.ORGANIZATION.value)
    def chain_threats():
        return jsonify({"ok": True, "reports": fetch_chain_reports(app.config)})

    # Serve static frontend (optional single-process demo)
    frontend_root = app.config["BASE_DIR"] / "frontend"

    @app.route("/")
    def index_page():
        return send_from_directory(frontend_root, "index.html")

    @app.route("/<path:path>")
    def static_proxy(path):
        return send_from_directory(frontend_root, path)

    return app


def _bootstrap_admin(app):
    u = app.config.get("BOOTSTRAP_ADMIN_USERNAME")
    p = app.config.get("BOOTSTRAP_ADMIN_PASSWORD")
    if not u or not p:
        return
    if User.query.filter_by(username=u).first():
        return
    admin = User(
        username=u,
        password_hash=generate_password_hash(p),
        role=UserRole.ADMIN.value,
        organization_name="Platform Admin",
    )
    db.session.add(admin)
    db.session.commit()
    log.info("Bootstrap admin user %s created", u)


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True)
