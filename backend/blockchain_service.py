"""Web3 helpers: load contract, hash reports, register orgs, submit and verify."""
import json
import logging
from pathlib import Path
from typing import Optional

from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3

log = logging.getLogger(__name__)

_abi_cache = None


def _load_abi():
    global _abi_cache
    if _abi_cache is not None:
        return _abi_cache
    base = Path(__file__).resolve().parent / "abi" / "ThreatIntelligence.json"
    with open(base, encoding="utf-8") as f:
        _abi_cache = json.load(f)["abi"]
    return _abi_cache


def get_web3(config):
    return Web3(Web3.HTTPProvider(config.ETH_RPC_URL))


def get_contract(w3, config):
    if not config.CONTRACT_ADDRESS:
        return None
    return w3.eth.contract(
        address=to_checksum_address(config.CONTRACT_ADDRESS),
        abi=_load_abi(),
    )


def canonical_payload_hash(payload: dict) -> bytes:
    """Keccak256 of canonical JSON (must match backend hashing used for anchors)."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return keccak(primitive=body)


def fund_org_wallet(config, org_address: str, wei: int = 10**18) -> Optional[str]:
    """Send ETH from admin to org for gas (local dev / testnets with funded admin)."""
    if not config.ADMIN_PRIVATE_KEY:
        return None
    w3 = get_web3(config)
    admin = Account.from_key(config.ADMIN_PRIVATE_KEY)
    to = to_checksum_address(org_address)
    tx = {
        "to": to,
        "value": wei,
        "nonce": w3.eth.get_transaction_count(admin.address),
        "gas": 21000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    }
    signed = w3.eth.account.sign_transaction(tx, private_key=config.ADMIN_PRIVATE_KEY)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(h)
    log.info("Funded org %s tx=%s", org_address, receipt["transactionHash"].hex())
    return receipt["transactionHash"].hex()


def register_org_on_chain(config, org_address: str, org_name: str) -> Optional[str]:
    """Admin registers an organization wallet. Returns tx hash or None if skipped."""
    if not config.ADMIN_PRIVATE_KEY or not config.CONTRACT_ADDRESS:
        log.warning("Skipping on-chain registerOrganization (missing admin key or contract)")
        return None
    w3 = get_web3(config)
    contract = get_contract(w3, config)
    if not contract:
        return None
    admin = Account.from_key(config.ADMIN_PRIVATE_KEY)
    org_address = to_checksum_address(org_address)
    tx = contract.functions.registerOrganization(org_address, org_name).build_transaction(
        {
            "from": admin.address,
            "nonce": w3.eth.get_transaction_count(admin.address),
            "gas": 500_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )
    signed = w3.eth.account.sign_transaction(tx, private_key=config.ADMIN_PRIVATE_KEY)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(h)
    log.info("registerOrganization tx=%s", receipt["transactionHash"].hex())
    return receipt["transactionHash"].hex()


def submit_report_on_chain(
    config,
    org_private_key_hex: str,
    report_hash_bytes: bytes,
    ipfs_hash: str,
    organization_name: str,
) -> Optional[str]:
    """Organization signs and sends addThreatReport."""
    if not config.CONTRACT_ADDRESS:
        return None
    w3 = get_web3(config)
    contract = get_contract(w3, config)
    if not contract:
        return None
    acct = Account.from_key(org_private_key_hex)
    if len(report_hash_bytes) != 32:
        raise ValueError("report_hash must be 32 bytes")

    tx = contract.functions.addThreatReport(
        report_hash_bytes, ipfs_hash, organization_name
    ).build_transaction(
        {
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
            "gas": 800_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )
    signed = w3.eth.account.sign_transaction(tx, private_key=org_private_key_hex)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(h)
    return receipt["transactionHash"].hex()


def verify_on_chain(config, report_hash_hex: str) -> Optional[bool]:
    """Returns True/False if contract configured; None if no contract."""
    if not config.CONTRACT_ADDRESS:
        return None
    w3 = get_web3(config)
    contract = get_contract(w3, config)
    if not contract:
        return None
    h = report_hash_hex[2:] if report_hash_hex.startswith("0x") else report_hash_hex
    b = bytes.fromhex(h)
    return contract.functions.verifyReport(b).call()


def fetch_chain_reports(config):
    """Return list of on-chain report structs as dicts."""
    if not config.CONTRACT_ADDRESS:
        return []
    w3 = get_web3(config)
    contract = get_contract(w3, config)
    if not contract:
        return []
    raw = contract.functions.getThreatReports().call()
    out = []
    for r in raw:
        hhex = Web3.to_hex(r[0])
        sub = r[4]
        sub_s = sub if isinstance(sub, str) else Web3.to_checksum_address(sub)
        out.append(
            {
                "report_hash": hhex,
                "ipfs_hash": r[1],
                "organization": r[2],
                "timestamp": int(r[3]),
                "submitter": sub_s,
            }
        )
    return out
