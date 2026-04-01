# Blockchain-Based Cybersecurity Threat Intelligence Sharing (prototype)

End-to-end **educational** demo: organizations share structured threat data; **IPFS** stores full reports; **Ethereum (Solidity)** anchors **Keccak256** hashes and CIDs; **Flask** exposes JWT-protected REST APIs; a **vanilla JS** dashboard lists, filters, and verifies reports.

## Quick architecture

- **Frontend:** `frontend/` — HTML/CSS/JS, Chart.js charts.
- **Backend:** `backend/` — Flask, SQLAlchemy, JWT, RBAC, Web3, IPFS client.
- **Blockchain:** `blockchain/` — Hardhat + `ThreatIntelligence.sol`.
- **Database:** SQLite by default, or PostgreSQL via `DATABASE_URL`.
- **IPFS:** Optional Docker service or local Kubo; fallback CID if offline.
- **Docs:** `docs/ARCHITECTURE.md`, `docs/EXAMPLE_DATA.json`.

## Prerequisites

- **Python 3.10+** (3.9 may work with current dependencies).
- **Node.js 18+** and **npm** (for Hardhat).
- Optional: **Docker** (PostgreSQL + IPFS from `docker-compose.yml`).

## Step-by-step setup (local)

### 1. Blockchain: compile & run node

```bash
cd blockchain
npm install
npx hardhat compile
```

In **terminal A**, start Hardhat with persistent chain:

```bash
npx hardhat node
```

Leave it running. Note **Hardhat account #0** private key (used as admin in the backend):

`0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` (local only — never use on mainnet).

### 2. Deploy contract

```bash
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```

Copy the contract address into `backend/.env` (see below).

### 3. Backend configuration

```bash
cd backend
py -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
copy .env.example .env     # Windows; or cp on Unix
```

Edit `backend/.env`:

- Set `CONTRACT_ADDRESS` to the deployed address.
- Set `ADMIN_PRIVATE_KEY` to the Hardhat #0 key above (local dev).
- Optional: `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` for an admin login.

### 4. Optional: PostgreSQL + IPFS (Docker)

From project root:

```bash
docker compose up -d
```

In `backend/.env`:

```env
DATABASE_URL=postgresql+psycopg2://threat:threat_dev@127.0.0.1:5432/threat_intel
IPFS_API=/ip4/127.0.0.1/tcp/5001
```

If you skip Docker, the app uses **SQLite** at `database/threat_intel.db` and IPFS **fallback** CIDs.

### 5. Run API + dashboard

```bash
cd backend
py app.py
```

Open **http://127.0.0.1:5000/** — Flask serves the `frontend/` static files.

### 6. HTTPS (production)

Terminate TLS at **nginx**, **Caddy**, or a cloud load balancer; proxy to Flask on `127.0.0.1:5000`. The app sets basic security headers; enable HSTS and real certificates in the proxy.

## REST API (summary)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register` | — | Register analyst or organization (org gets a wallet; admin registers it on-chain). |
| POST | `/api/login` | — | JWT login. |
| POST | `/api/submitThreat` | JWT | Org or admin; stores IPFS + DB; org signs on-chain tx. |
| GET | `/api/getThreats` | JWT | List threats; `?attack_type=` filter. |
| POST | `/api/verifyThreat` | JWT | `{ "report_hash": "0x..." }` — chain + DB check. |
| GET | `/api/stats` | JWT | Counts, attack-type breakdown, recent rows. |
| GET | `/api/chainThreats` | JWT | Raw on-chain anchors. |

## Roles

- **organization** — Can submit; backend generates an Ethereum key, registers it on-chain, funds it from Hardhat admin, and signs `addThreatReport`.
- **analyst** — Read-only API usage (list, stats, verify).
- **admin** — Bootstrap via env; can submit DB records (on-chain tx optional for org flow).

## Example test data

See `docs/EXAMPLE_DATA.json`. After registering an **organization** user and logging in, POST JSON to `/api/submitThreat` with the same shape.

## Security (prototype limitations)

- Demo keys and well-known Hardhat accounts must **never** be used on public networks.
- Encrypt sensitive IPFS payloads separately if you need confidentiality.
- Rotate JWT secrets and use strong passwords in any shared deployment.

## Project layout

```
BlockchainProject/
├── frontend/          # Web UI
├── backend/             # Flask API
├── blockchain/          # Hardhat + Solidity
├── database/            # schema.sql + SQLite file (generated)
├── ipfs/                # IPFS notes
├── docs/                # Architecture + examples
├── docker-compose.yml
└── README.md
```

## License

Educational use. MIT for sample code unless you add your own policies.
