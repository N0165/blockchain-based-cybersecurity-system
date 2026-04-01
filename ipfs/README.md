# IPFS (content addressing for full reports)

Large JSON payloads are stored on **IPFS**; the **CID** (content identifier) and a **Keccak256 hash** of the canonical JSON are anchored on Ethereum.

## Option A — Docker (recommended)

From the project root:

```bash
docker compose up -d ipfs
```

The HTTP API listens on `127.0.0.1:5001`. Set in `backend/.env`:

```env
IPFS_API=/ip4/127.0.0.1/tcp/5001
```

## Option B — Kubo binary

Install [Kubo](https://github.com/ipfs/kubo/releases), run `ipfs init` once, then `ipfs daemon`.

## Fallback

If no daemon is reachable, the API stores a placeholder CID (`local-<uuid>`) and still saves metadata in the database so the UI keeps working for demos.
