// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseWebAuthn} from "../auth/BaseWebAuthn.sol";

interface IWallet7702 {
    /// @notice Struct to hold passkey WebAuthn coordinates.
    struct PasskeyData {
        uint256 pubKeyX;
        uint256 pubKeyY;
    }

    /// @notice A single call in a batched transaction.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice Strict policy constraints for a localized Session Key.
    struct SessionKeyPolicy {
        uint48 validAfter;
        uint48 validUntil;
        address target; // Target contract address (address(0) for any)
        bytes4 selector; // Allowed function selector (bytes4(0) for any)
        uint256 valueLimit; // Maximum Native ETH transaction value
    }

    // --- Events ---
    event WalletInitialized(address indexed eoa, uint256 pubKeyX, uint256 pubKeyY);
    event PasskeyRotated(uint256 newPubKeyX, uint256 newPubKeyY);
    event SessionKeyAdded(address indexed sessionKey, SessionKeyPolicy policy);
    event SessionKeyRevoked(address indexed sessionKey);

    // --- Errors ---
    error Unauthorized();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidInitializationSignature();
    error SessionKeyExpired();
    error PolicyViolationTarget();
    error PolicyViolationSelector();
    error PolicyViolationValue();
    error SelfCallNotAllowed();

    // --- Core Functions ---
    /// @notice Initializes the EOA with root Passkey data. Signer must be the underlying EOA key.
    function initialize(PasskeyData calldata passkey, bytes calldata eoaSignature) external;

    /// @notice Root key transaction execution.
    function executeRoot(address target, uint256 value, bytes calldata data, BaseWebAuthn.WebAuthnAuth calldata auth)
        external
        payable
        returns (bytes memory);

    /// @notice Session key transaction execution.
    function executeSession(
        address sessionKey,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata sessionSignature
    ) external payable returns (bytes memory);

    /// @notice Root key batched transaction execution.
    function executeBatchRoot(Call[] calldata calls, BaseWebAuthn.WebAuthnAuth calldata auth)
        external
        payable
        returns (bytes[] memory);

    /// @notice Session key batched transaction execution.
    function executeBatchSession(address sessionKey, Call[] calldata calls, bytes calldata sessionSignature)
        external
        payable
        returns (bytes[] memory);

    /// @notice Handles WebAuthn root key updates.
    function rotatePasskey(PasskeyData calldata newPasskey) external;

    /// @notice Register or revoke a session key.
    function setSessionKey(address sessionKey, SessionKeyPolicy calldata policy) external;
}
