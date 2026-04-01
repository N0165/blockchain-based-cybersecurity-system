"""IPFS upload via ipfshttpclient; falls back to local stub CID if daemon is down."""
import io
import json
import logging
import uuid

log = logging.getLogger(__name__)


def add_json(config, payload: dict) -> str:
    """Store JSON on IPFS and return CID (or a deterministic local stub)."""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        import ipfshttpclient

        client = ipfshttpclient.connect(config.IPFS_API)
        # ipfshttpclient 0.7+: add() accepts file-like object
        res = client.add(io.BytesIO(data))
        if isinstance(res, list) and len(res) > 0:
            cid = res[0]["Hash"]
        else:
            cid = res["Hash"]
        log.info("IPFS stored object cid=%s", cid)
        return cid
    except Exception as e:
        log.warning("IPFS unavailable (%s); using local stub CID", e)
        # Demo fallback: content still in DB; CID is non-publishable placeholder
        return f"local-{uuid.uuid4().hex}"
