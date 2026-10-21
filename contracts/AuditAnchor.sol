// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IAuditAnchor} from "./IAuditAnchor.sol";

/**
 * @title AuditAnchor
 * @notice Cryptographic Audit Anchoring Contract for VERITAS-Vault.
 * @dev Anchors batches of SHA-256 Merkle roots on Hyperledger Besu (private QBFT)
 *      and Ethereum Sepolia (public testnet).
 *
 * Core Architecture & Security Features:
 * 1. OpenZeppelin Ownable2Step Access Control: Prevents accidental loss of contract
 *    ownership through a 2-step propose-and-claim pattern.
 * 2. Multi-Relayer Authorization: Authorized automated relayers can anchor roots while
 *    critical governance remains restricted to the owner.
 * 3. Immutable Batch Registry: Prevents batch ID duplication and rejects non-monotonic
 *    or malformed sequence spans.
 * 4. Zero Personal Data: Stores only root hashes, batch IDs, sequence bounds, counts,
 *    and block timestamps. Never accepts biometric vectors, images, or plaintext PII.
 * 5. Asynchronous Cross-Chain Support: Sepolia anchoring functions independently without
 *    mandating prior Besu settlement, while allowing optional Besu TxHash references.
 */
contract AuditAnchor is IAuditAnchor {
    // -------------------------------------------------------------------------
    // Custom Errors (Gas-Optimized)
    // -------------------------------------------------------------------------

    error UnauthorizedCaller(address caller);
    error BatchAlreadyAnchored(bytes32 batchId);
    error InvalidBatchId();
    error InvalidRootHash();
    error InvalidEventCount();
    error InvalidSequenceRange(uint64 firstSequence, uint64 lastSequence);
    error InvalidSequenceSpan(uint64 firstSequence, uint64 lastSequence, uint64 eventCount);
    error InvalidNewOwner(address newOwner);
    error CallerNotPendingOwner(address caller);
    error ZeroAddressRelayer();

    // -------------------------------------------------------------------------
    // State Storage
    // -------------------------------------------------------------------------

    address private _owner;
    address private _pendingOwner;

    // batchId => AnchorRecord
    mapping(bytes32 => AnchorRecord) private _anchors;

    // rootHash => batchId (first batch associated with this root)
    mapping(bytes32 => bytes32) private _rootToBatch;

    // Authorized relayers
    mapping(address => bool) private _relayers;

    // Counter of total batches anchored
    uint256 private _totalAnchors;

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != _owner) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    modifier onlyAuthorizedRelayer() {
        if (msg.sender != _owner && !_relayers[msg.sender]) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @notice Initializes the AuditAnchor contract with an initial owner.
     * @param initialOwner Address of contract administrator (defaults to msg.sender if address(0)).
     */
    constructor(address initialOwner) {
        address assignedOwner = initialOwner != address(0) ? initialOwner : msg.sender;
        _owner = assignedOwner;
        emit OwnershipTransferred(address(0), assignedOwner);
    }

    // -------------------------------------------------------------------------
    // Anchoring Functions
    // -------------------------------------------------------------------------

    /**
     * @inheritdoc IAuditAnchor
     */
    function anchorBatch(
        bytes32 batchId,
        bytes32 rootHash,
        uint64 eventCount,
        uint64 firstSequence,
        uint64 lastSequence
    ) external override onlyAuthorizedRelayer returns (bool success) {
        return _anchorBatchInternal(batchId, rootHash, eventCount, firstSequence, lastSequence, bytes32(0));
    }

    /**
     * @inheritdoc IAuditAnchor
     */
    function anchorBatchWithRef(
        bytes32 batchId,
        bytes32 rootHash,
        uint64 eventCount,
        uint64 firstSequence,
        uint64 lastSequence,
        bytes32 crossChainRef
    ) external override onlyAuthorizedRelayer returns (bool success) {
        return _anchorBatchInternal(batchId, rootHash, eventCount, firstSequence, lastSequence, crossChainRef);
    }

    /**
     * @dev Internal implementation for registering an anchor record.
     */
    function _anchorBatchInternal(
        bytes32 batchId,
        bytes32 rootHash,
        uint64 eventCount,
        uint64 firstSequence,
        uint64 lastSequence,
        bytes32 crossChainRef
    ) internal returns (bool) {
        if (batchId == bytes32(0)) {
            revert InvalidBatchId();
        }
        if (rootHash == bytes32(0)) {
            revert InvalidRootHash();
        }
        if (eventCount == 0) {
            revert InvalidEventCount();
        }
        if (firstSequence > lastSequence) {
            revert InvalidSequenceRange(firstSequence, lastSequence);
        }
        // Ensure the sequence window is large enough to contain the declared number of events
        if (uint256(lastSequence) - uint256(firstSequence) + 1 < uint256(eventCount)) {
            revert InvalidSequenceSpan(firstSequence, lastSequence, eventCount);
        }
        if (_anchors[batchId].batchId != bytes32(0)) {
            revert BatchAlreadyAnchored(batchId);
        }

        uint64 currentTimestamp = uint64(block.timestamp);

        AnchorRecord memory record = AnchorRecord({
            rootHash: rootHash,
            batchId: batchId,
            firstSequence: firstSequence,
            lastSequence: lastSequence,
            eventCount: eventCount,
            blockTimestamp: currentTimestamp,
            anchoredBy: msg.sender,
            crossChainRef: crossChainRef
        });

        _anchors[batchId] = record;
        if (_rootToBatch[rootHash] == bytes32(0)) {
            _rootToBatch[rootHash] = batchId;
        }
        _totalAnchors += 1;

        emit BatchAnchored(
            batchId,
            rootHash,
            eventCount,
            firstSequence,
            lastSequence,
            currentTimestamp,
            msg.sender,
            crossChainRef
        );

        return true;
    }

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /**
     * @inheritdoc IAuditAnchor
     */
    function getAnchor(bytes32 batchId) external view override returns (AnchorRecord memory) {
        AnchorRecord memory record = _anchors[batchId];
        if (record.batchId == bytes32(0)) {
            revert InvalidBatchId();
        }
        return record;
    }

    /**
     * @inheritdoc IAuditAnchor
     */
    function isBatchAnchored(bytes32 batchId) external view override returns (bool) {
        return _anchors[batchId].batchId != bytes32(0);
    }

    /**
     * @inheritdoc IAuditAnchor
     */
    function isRootAnchored(bytes32 rootHash) external view override returns (bool) {
        return _rootToBatch[rootHash] != bytes32(0);
    }

    /**
     * @inheritdoc IAuditAnchor
     */
    function totalAnchors() external view override returns (uint256) {
        return _totalAnchors;
    }

    /**
     * @inheritdoc IAuditAnchor
     */
    function isRelayer(address relayer) external view override returns (bool) {
        return _relayers[relayer];
    }

    // -------------------------------------------------------------------------
    // Relayer Administration
    // -------------------------------------------------------------------------

    /**
     * @notice Grants or revokes relayer privileges for automated backend signers.
     * @param relayer Address of the relayer.
     * @param authorized True to authorize, false to revoke.
     */
    function setRelayer(address relayer, bool authorized) external onlyOwner {
        if (relayer == address(0)) {
            revert ZeroAddressRelayer();
        }
        _relayers[relayer] = authorized;
        emit RelayerStatusChanged(relayer, authorized);
    }

    // -------------------------------------------------------------------------
    // Ownable2Step Implementation
    // -------------------------------------------------------------------------

    /**
     * @inheritdoc IAuditAnchor
     */
    function owner() public view override returns (address) {
        return _owner;
    }

    /**
     * @inheritdoc IAuditAnchor
     */
    function pendingOwner() public view override returns (address) {
        return _pendingOwner;
    }

    /**
     * @notice Starts the 2-step ownership transfer procedure.
     * @param newOwner Address to propose as the new owner.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert InvalidNewOwner(address(0));
        }
        if (newOwner == _owner) {
            revert InvalidNewOwner(newOwner);
        }
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(_owner, newOwner);
    }

    /**
     * @notice Claims ownership by the pending owner.
     */
    function acceptOwnership() external {
        if (msg.sender != _pendingOwner) {
            revert CallerNotPendingOwner(msg.sender);
        }
        address oldOwner = _owner;
        _owner = _pendingOwner;
        delete _pendingOwner;
        emit OwnershipTransferred(oldOwner, _owner);
    }

    /**
     * @notice Renounces ownership, leaving the contract without an admin.
     * @dev Can be executed only by the current owner.
     */
    function renounceOwnership() external onlyOwner {
        address oldOwner = _owner;
        delete _owner;
        delete _pendingOwner;
        emit OwnershipTransferred(oldOwner, address(0));
    }
}
