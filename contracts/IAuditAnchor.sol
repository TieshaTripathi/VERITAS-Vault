// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title IAuditAnchor
 * @notice Standard interface for VERITAS-Vault Hybrid Blockchain Audit Anchoring.
 * @dev Deployable on Hyperledger Besu (private permissioned QBFT) and Ethereum Sepolia (public testnet).
 *
 * Architecture Guarantees:
 * 1. Zero PII: No biometric features, images, embeddings, names, or evidence payloads are stored on-chain.
 * 2. Independent Network Operation: Can anchor roots on Besu, Sepolia, or both without cross-dependencies.
 * 3. Tamper Resistance: Prevents duplicate batch IDs and validates chronological sequence integrity.
 */
interface IAuditAnchor {
    /**
     * @notice Immutable metadata record of an anchored Merkle root batch.
     */
    struct AnchorRecord {
        bytes32 rootHash;          // SHA-256 Merkle root of the batch
        bytes32 batchId;           // Deterministic unique batch identifier
        uint64 firstSequence;      // Starting sequence number in the audit ledger
        uint64 lastSequence;       // Ending sequence number in the audit ledger
        uint64 eventCount;         // Count of events aggregated in this batch
        uint64 blockTimestamp;     // EVM block timestamp when anchored
        address anchoredBy;        // Relayer address that submitted the anchor transaction
        bytes32 crossChainRef;     // Optional Besu TxHash or external anchor reference (0x0 if standalone)
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /**
     * @notice Emitted when a Merkle batch root is successfully committed to the blockchain.
     */
    event BatchAnchored(
        bytes32 indexed batchId,
        bytes32 indexed rootHash,
        uint64 eventCount,
        uint64 firstSequence,
        uint64 lastSequence,
        uint64 blockTimestamp,
        address indexed anchoredBy,
        bytes32 crossChainRef
    );

    /**
     * @notice Emitted when a relayer authorization status is updated.
     */
    event RelayerStatusChanged(address indexed relayer, bool indexed authorized);

    /**
     * @notice Emitted when 2-step ownership transfer is initiated.
     */
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /**
     * @notice Emitted when 2-step ownership transfer is completed.
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // -------------------------------------------------------------------------
    // Anchoring Operations
    // -------------------------------------------------------------------------

    /**
     * @notice Anchor a Merkle batch root without cross-chain reference.
     * @param batchId Deterministic unique identifier for the batch.
     * @param rootHash SHA-256 Merkle root hash of the batched audit events.
     * @param eventCount Number of events aggregated in this batch.
     * @param firstSequence Monotonic sequence number of the first event in the batch.
     * @param lastSequence Monotonic sequence number of the last event in the batch.
     * @return success Returns true upon successful state commit.
     */
    function anchorBatch(
        bytes32 batchId,
        bytes32 rootHash,
        uint64 eventCount,
        uint64 firstSequence,
        uint64 lastSequence
    ) external returns (bool success);

    /**
     * @notice Anchor a Merkle batch root with an optional cross-chain reference (e.g. Besu TxHash on Sepolia).
     * @param batchId Deterministic unique identifier for the batch.
     * @param rootHash SHA-256 Merkle root hash of the batched audit events.
     * @param eventCount Number of events aggregated in this batch.
     * @param firstSequence Monotonic sequence number of the first event in the batch.
     * @param lastSequence Monotonic sequence number of the last event in the batch.
     * @param crossChainRef Optional external transaction hash or anchor reference.
     * @return success Returns true upon successful state commit.
     */
    function anchorBatchWithRef(
        bytes32 batchId,
        bytes32 rootHash,
        uint64 eventCount,
        uint64 firstSequence,
        uint64 lastSequence,
        bytes32 crossChainRef
    ) external returns (bool success);

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Retrieve the full anchor record for a given batch ID.
     */
    function getAnchor(bytes32 batchId) external view returns (AnchorRecord memory);

    /**
     * @notice Query whether a specific batch ID has already been anchored.
     */
    function isBatchAnchored(bytes32 batchId) external view returns (bool);

    /**
     * @notice Query whether a specific Merkle root hash is registered in any batch.
     */
    function isRootAnchored(bytes32 rootHash) external view returns (bool);

    /**
     * @notice Total number of batches anchored in this contract.
     */
    function totalAnchors() external view returns (uint256);

    /**
     * @notice Verify if an address is an authorized relayer.
     */
    function isRelayer(address relayer) external view returns (bool);

    /**
     * @notice Current contract owner address.
     */
    function owner() external view returns (address);

    /**
     * @notice Pending owner address in 2-step ownership transfer.
     */
    function pendingOwner() external view returns (address);
}
