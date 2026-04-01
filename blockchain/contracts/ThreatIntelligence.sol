// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatIntelligence
 * @notice Immutable registry of cyber threat intelligence report hashes on-chain.
 *         Full report payloads live on IPFS; only hashes and metadata are stored here.
 *         Only registered organization addresses may submit reports (enforced by msg.sender).
 */
contract ThreatIntelligence {
    struct ThreatReport {
        bytes32 reportHash;
        string ipfsHash;
        string organization;
        uint256 timestamp;
        address submitter;
    }

    address public admin;

    /// @notice Registered Ethereum addresses allowed to submit threat reports
    mapping(address => bool) public registeredOrganizations;

    /// @notice Human-readable org name per registered address (for transparency)
    mapping(address => string) public organizationNames;

    /// @notice All reports in append-only order (immutable ledger)
    ThreatReport[] private _threatReports;

    /// @notice Quick lookup: keccak256 hash of report content -> exists on chain
    mapping(bytes32 => bool) public reportExists;

    event OrganizationRegistered(address indexed orgAddress, string name);
    event ThreatReportAdded(
        bytes32 indexed reportHash,
        string ipfsHash,
        string organization,
        address indexed submitter,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "ThreatIntelligence: not admin");
        _;
    }

    modifier onlyRegisteredOrganization() {
        require(registeredOrganizations[msg.sender], "ThreatIntelligence: org not registered");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /**
     * @notice Admin registers an organization wallet that may submit reports on-chain.
     */
    function registerOrganization(address orgAddress, string calldata name) external onlyAdmin {
        require(orgAddress != address(0), "ThreatIntelligence: zero address");
        require(bytes(name).length > 0, "ThreatIntelligence: empty name");
        registeredOrganizations[orgAddress] = true;
        organizationNames[orgAddress] = name;
        emit OrganizationRegistered(orgAddress, name);
    }

    /**
     * @notice Append a threat report anchor. Callable only by a registered organization address.
     * @param reportHash Keccak256 hash of the canonical report content (integrity anchor)
     * @param ipfsHash IPFS CID of the full report JSON
     * @param organization Organization display name (redundant with chain mapping, for indexing)
     */
    function addThreatReport(
        bytes32 reportHash,
        string calldata ipfsHash,
        string calldata organization
    ) external onlyRegisteredOrganization {
        require(reportHash != bytes32(0), "ThreatIntelligence: invalid report hash");
        require(bytes(ipfsHash).length > 0, "ThreatIntelligence: empty IPFS hash");
        require(!reportExists[reportHash], "ThreatIntelligence: duplicate report");

        reportExists[reportHash] = true;
        _threatReports.push(
            ThreatReport({
                reportHash: reportHash,
                ipfsHash: ipfsHash,
                organization: organization,
                timestamp: block.timestamp,
                submitter: msg.sender
            })
        );

        emit ThreatReportAdded(reportHash, ipfsHash, organization, msg.sender, block.timestamp);
    }

    /**
     * @notice Return all on-chain threat report anchors (prototype; not gas-optimized for huge arrays).
     */
    function getThreatReports() external view returns (ThreatReport[] memory) {
        return _threatReports;
    }

    /**
     * @notice Verify that a given content hash was recorded on-chain.
     */
    function verifyReport(bytes32 reportHash) external view returns (bool) {
        return reportExists[reportHash];
    }

    function threatReportCount() external view returns (uint256) {
        return _threatReports.length;
    }

    function getThreatReport(uint256 index) external view returns (ThreatReport memory) {
        require(index < _threatReports.length, "ThreatIntelligence: out of bounds");
        return _threatReports[index];
    }
}
