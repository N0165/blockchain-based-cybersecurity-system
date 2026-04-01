const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatIntelligence", function () {
  async function deploy() {
    const [admin, org, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("ThreatIntelligence");
    const c = await Factory.deploy();
    await c.waitForDeployment();
    return { c, admin, org, other };
  }

  it("registers org and adds report", async function () {
    const { c, admin, org, other } = await deploy();
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes("report-payload-v1"));
    const ipfsHash = "QmExampleCID123456789";

    await c.connect(admin).registerOrganization(org.address, "Acme SOC");
    await expect(
      c.connect(other).addThreatReport(reportHash, ipfsHash, "Acme SOC")
    ).to.be.reverted;

    await c.connect(org).addThreatReport(reportHash, ipfsHash, "Acme SOC");
    expect(await c.verifyReport(reportHash)).to.equal(true);

    const reports = await c.getThreatReports();
    expect(reports.length).to.equal(1);
    expect(reports[0].reportHash).to.equal(reportHash);
  });
});
