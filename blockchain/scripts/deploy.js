const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with:", deployer.address);

  const ThreatIntelligence = await hre.ethers.getContractFactory("ThreatIntelligence");
  const contract = await ThreatIntelligence.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("ThreatIntelligence deployed to:", address);

  // Optional: write address for backend .env
  const fs = require("fs");
  const path = require("path");
  const out = path.join(__dirname, "..", "deployed-address.txt");
  fs.writeFileSync(out, address, "utf8");
  console.log("Wrote", out);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
