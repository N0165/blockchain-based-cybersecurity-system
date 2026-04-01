# Ethereum smart contract (Hardhat)

- **Contract:** `contracts/ThreatIntelligence.sol`
- **Network:** local Hardhat node (`chainId` 31337) for development.

## Commands

```bash
npm install
npx hardhat compile
npx hardhat test
```

In one terminal, start a persistent node:

```bash
npx hardhat node
```

Then deploy (uses first account as `admin`):

```bash
npx hardhat run scripts/deploy.js --network localhost
```

Copy the printed address into `backend/.env` as `CONTRACT_ADDRESS`.

The deploy script also writes `deployed-address.txt` in this folder.

## Accounts

Hardhat’s default accounts are pre-funded with ETH. **Account #0** is the contract `admin` and should be used as `ADMIN_PRIVATE_KEY` in the backend (see root `README.md`).
