// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWallet7702} from "./interfaces/IWallet7702.sol";
import {Storage} from "./Storage.sol";
import {BaseWebAuthn} from "./auth/BaseWebAuthn.sol";
import {SessionManager} from "./auth/SessionManager.sol";

/// @title Wallet7702 - EIP-7702 Delegated Smart Account Singleton
/// @notice Stateless singleton serving as the EIP-7702 delegation target for EOAs.
///         Provides Passkey (WebAuthn) root auth, ephemeral Session Key execution,
///         EIP-712 replay protection, and ERC-7201 namespaced storage.
/// @dev    Shares EIP-712 helpers & constants with SessionManager to avoid
///         code duplication (SessionManager is an internal library and gets inlined).
contract Wallet7702 is IWallet7702 {
    bytes32 private constant _INIT_TYPEHASH = keccak256("Initialize(uint256 pubKeyX,uint256 pubKeyY)");

    bytes32 private constant _ROOT_EXECUTION_TYPEHASH =
        keccak256("RootExecution(address target,uint256 value,bytes data,uint256 nonce)");

    bytes32 private constant _ROOT_BATCH_EXECUTION_TYPEHASH =
        keccak256("RootBatchExecution(Call[] calls,uint256 nonce)Call(address target,uint256 value,bytes data)");

    /// @notice Accepts direct calls routed to the EOA after EIP-7702 delegation.
    ///         Known selectors are dispatched by the compiler; unknown selectors land here.
    fallback() external payable {
        revert Unauthorized();
    }

    /// @notice Accept plain ETH transfers.
    receive() external payable {}

    // =============================================================
    // EIP-712 Helpers — delegates to SessionManager
    // =============================================================

    function _domainSeparator() internal view returns (bytes32) {
        return SessionManager.domainSeparator();
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return SessionManager._hashTypedData(structHash);
    }

    // =============================================================
    // initialize()
    // =============================================================

    /// @inheritdoc IWallet7702
    function initialize(PasskeyData calldata passkey, bytes calldata eoaSignature) external {
        Storage.WalletStorage storage $ = Storage._getWalletStorage();
        if ($.isInitialized) revert AlreadyInitialized();

        // Verify ECDSA signature from the EOA's native private key.
        bytes32 structHash = keccak256(abi.encode(_INIT_TYPEHASH, passkey.pubKeyX, passkey.pubKeyY));
        bytes32 digest = _hashTypedData(structHash);

        address recovered = _recoverSigner(digest, eoaSignature);
        if (recovered != address(this)) revert InvalidInitializationSignature();

        $.isInitialized = true;
        $.passkeyX = passkey.pubKeyX;
        $.passkeyY = passkey.pubKeyY;

        emit WalletInitialized(address(this), passkey.pubKeyX, passkey.pubKeyY);
    }

    // =============================================================
    // executeRoot()
    // =============================================================

    /// @inheritdoc IWallet7702
    function executeRoot(address target, uint256 value, bytes calldata data, BaseWebAuthn.WebAuthnAuth calldata auth)
        external
        payable
        returns (bytes memory)
    {
        Storage.WalletStorage storage $ = Storage._getWalletStorage();
        if (!$.isInitialized) revert NotInitialized();

        // Build EIP-712 challenge that the WebAuthn authenticator signed
        uint256 nonce = $.nonce;
        bytes32 structHash = keccak256(abi.encode(_ROOT_EXECUTION_TYPEHASH, target, value, keccak256(data), nonce));
        bytes32 digest = _hashTypedData(structHash);
        bytes memory challenge = abi.encodePacked(digest);

        bool valid = BaseWebAuthn.verify(challenge, true, auth, $.passkeyX, $.passkeyY);
        if (!valid) revert Unauthorized();

        $.nonce = nonce + 1;

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        return result;
    }

    // =============================================================
    // executeSession()
    // =============================================================

    /// @inheritdoc IWallet7702
    function executeSession(
        address sessionKey,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata sessionSignature
    ) external payable returns (bytes memory) {
        Storage.WalletStorage storage $ = Storage._getWalletStorage();
        if (!$.isInitialized) revert NotInitialized();

        // Validate session key signature + enforce all policy constraints.
        // Internally verifies EIP-712, self-call prevention, time/target/selector/value limits.
        SessionManager.validateAndUseNonce(sessionKey, target, value, data, sessionSignature);

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        return result;
    }

    // =============================================================
    // executeBatchRoot()
    // =============================================================

    /// @inheritdoc IWallet7702
    function executeBatchRoot(Call[] calldata calls, BaseWebAuthn.WebAuthnAuth calldata auth)
        external
        payable
        returns (bytes[] memory)
    {
        Storage.WalletStorage storage $ = Storage._getWalletStorage();
        if (!$.isInitialized) revert NotInitialized();

        uint256 nonce = $.nonce;

        bytes32 callsHash = _hashCalls(calls);
        bytes32 structHash = keccak256(abi.encode(_ROOT_BATCH_EXECUTION_TYPEHASH, callsHash, nonce));
        bytes32 digest = _hashTypedData(structHash);
        bytes memory challenge = abi.encodePacked(digest);

        bool valid = BaseWebAuthn.verify(challenge, true, auth, $.passkeyX, $.passkeyY);
        if (!valid) revert Unauthorized();

        $.nonce = nonce + 1;

        return _executeBatch(calls);
    }

    // =============================================================
    // executeBatchSession()
    // =============================================================

    /// @inheritdoc IWallet7702
    function executeBatchSession(address sessionKey, Call[] calldata calls, bytes calldata sessionSignature)
        external
        payable
        returns (bytes[] memory)
    {
        Storage.WalletStorage storage $ = Storage._getWalletStorage();
        if (!$.isInitialized) revert NotInitialized();

        SessionManager.validateBatchAndUseNonce(sessionKey, calls, sessionSignature);

        return _executeBatch(calls);
    }

    // =============================================================
    // Batch Execution Helpers
    // =============================================================

    /// @dev Delegates to SessionManager.
    function _hashCalls(Call[] calldata calls) private pure returns (bytes32) {
        return SessionManager._hashCalls(calls);
    }

    /// @dev Execute all calls in a batch. Reverts the entire batch if any call fails.
    function _executeBatch(Call[] calldata calls) private returns (bytes[] memory results) {
        uint256 len = calls.length;
        results = new bytes[](len);
        for (uint256 i = 0; i < len; i++) {
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            results[i] = result;
        }
    }

    // =============================================================
    // rotatePasskey()
    // =============================================================

    /// @inheritdoc IWallet7702
    /// @dev Only callable via executeRoot (msg.sender == address(this)).
    function rotatePasskey(PasskeyData calldata newPasskey) external {
        if (msg.sender != address(this)) revert Unauthorized();
        Storage.WalletStorage storage $ = Storage._getWalletStorage();
        if (!$.isInitialized) revert NotInitialized();

        $.passkeyX = newPasskey.pubKeyX;
        $.passkeyY = newPasskey.pubKeyY;

        emit PasskeyRotated(newPasskey.pubKeyX, newPasskey.pubKeyY);
    }

    // =============================================================
    // setSessionKey()
    // =============================================================

    /// @inheritdoc IWallet7702
    /// @dev Only callable via executeRoot (msg.sender == address(this)).
    function setSessionKey(address sessionKey, SessionKeyPolicy calldata policy) external {
        if (msg.sender != address(this)) revert Unauthorized();
        if (!Storage._getWalletStorage().isInitialized) revert NotInitialized();
        SessionManager.setSessionKey(sessionKey, policy);
    }

    // =============================================================
    // ECDSA Signature Recovery — delegates to SessionManager
    // =============================================================

    /// @dev Recover the signer of an ECDSA signature (secp256k1, 65 bytes r||s||v).
    function _recoverSigner(bytes32 digest, bytes memory signature) private pure returns (address) {
        return SessionManager._recoverSigner(digest, signature);
    }
}
