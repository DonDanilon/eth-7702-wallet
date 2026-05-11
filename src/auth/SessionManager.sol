// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWallet7702} from "../interfaces/IWallet7702.sol";
import {Storage} from "../Storage.sol";

/// @title SessionManager - Ephemeral secp256k1 session key lifecycle & policy enforcement
/// @notice Registers/revokes session keys in ERC-7201 namespaced storage. Validates
///         EIP-712 structured signatures from session keys and enforces scoped policies
///         (time window, target address, function selector, ETH value limit).
library SessionManager {
    bytes32 private constant _EXECUTION_TYPEHASH =
        keccak256("SessionExecution(address sessionKey,address target,uint256 value,bytes data,uint256 nonce)");

    bytes32 internal constant _CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");

    bytes32 private constant _BATCH_EXECUTION_TYPEHASH = keccak256(
        "SessionBatchExecution(address sessionKey,Call[] calls,uint256 nonce)Call(address target,uint256 value,bytes data)"
    );

    bytes32 internal constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 internal constant _NAME_HASH = keccak256("EIP-7702 Wallet");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    function _storage() private pure returns (Storage.WalletStorage storage $) {
        $ = Storage._getWalletStorage();
    }

    /// @notice Compute the EIP-712 domain separator for this wallet (EOA).
    function domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, address(this)));
    }

    /// @notice Register or revoke a session key. Pass a zeroed policy to revoke.
    /// @dev Caller must be the root authority.
    function setSessionKey(address sessionKey, IWallet7702.SessionKeyPolicy calldata policy) internal {
        Storage.WalletStorage storage $ = _storage();
        bool isRevoking =
            (policy.validAfter == 0 && policy.validUntil == 0 && policy.target == address(0)
                && policy.selector == bytes4(0) && policy.valueLimit == 0);

        if (isRevoking) {
            delete $.sessionKeys[sessionKey];
            emit IWallet7702.SessionKeyRevoked(sessionKey);
        } else {
            $.sessionKeys[sessionKey] = policy;
            emit IWallet7702.SessionKeyAdded(sessionKey, policy);
        }
    }

    /// @notice Validate a session key signature and enforce all policy constraints.
    /// @param sessionKey    The session key's Ethereum address (secp256k1).
    /// @param target        The target contract being called.
    /// @param value         Native ETH value being sent.
    /// @param data          Calldata for the target call.
    /// @param signature     ECDSA signature over the EIP-712 SessionExecution digest.
    function validateAndUseNonce(
        address sessionKey,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) internal {
        Storage.WalletStorage storage $ = _storage();

        // 1. Load policy
        IWallet7702.SessionKeyPolicy memory policy = $.sessionKeys[sessionKey];
        if (policy.validAfter == 0 && policy.validUntil == 0) {
            revert IWallet7702.Unauthorized();
        }

        // 2. Self-call prevention (privilege escalation guard)
        if (target == address(this)) {
            revert IWallet7702.SelfCallNotAllowed();
        }

        // 3. Time window check
        if (block.timestamp < policy.validAfter || block.timestamp > policy.validUntil) {
            revert IWallet7702.SessionKeyExpired();
        }

        // 4. Target whitelist check
        if (policy.target != address(0) && target != policy.target) {
            revert IWallet7702.PolicyViolationTarget();
        }

        // 5. Selector whitelist check
        if (policy.selector != bytes4(0)) {
            bytes4 calledSelector = bytes4(data);
            if (calledSelector != policy.selector) {
                revert IWallet7702.PolicyViolationSelector();
            }
        }

        // 6. Value limit check
        if (value > policy.valueLimit) {
            revert IWallet7702.PolicyViolationValue();
        }

        // 7. Signature verification
        uint256 nonce = $.nonce;
        bytes32 digest = _hashTypedData(
            keccak256(abi.encode(_EXECUTION_TYPEHASH, sessionKey, target, value, keccak256(data), nonce))
        );
        address recovered = _recoverSigner(digest, signature);
        if (recovered != sessionKey) {
            revert IWallet7702.Unauthorized();
        }

        $.nonce = nonce + 1;
    }

    /// @notice Validate a batch of calls authorized by a session key signature.
    ///         Enforces the session key's policy against every call in the batch.
    /// @param sessionKey    The session key's Ethereum address (secp256k1).
    /// @param calls         Array of Call structs to execute.
    /// @param signature     ECDSA signature over the EIP-712 SessionBatchExecution digest.
    function validateBatchAndUseNonce(address sessionKey, IWallet7702.Call[] calldata calls, bytes calldata signature)
        internal
    {
        Storage.WalletStorage storage $ = _storage();

        // 1. Load policy
        IWallet7702.SessionKeyPolicy memory policy = $.sessionKeys[sessionKey];
        if (policy.validAfter == 0 && policy.validUntil == 0) {
            revert IWallet7702.Unauthorized();
        }

        // 2. Time window check
        // solhint-disable-next-line not-rely-on-time
        if (block.timestamp < policy.validAfter || block.timestamp > policy.validUntil) {
            revert IWallet7702.SessionKeyExpired();
        }

        // 3. Enforce policy constraints on every call in the batch
        uint256 len = calls.length;
        for (uint256 i = 0; i < len; i++) {
            if (calls[i].target == address(this)) {
                revert IWallet7702.SelfCallNotAllowed();
            }
            if (policy.target != address(0) && calls[i].target != policy.target) {
                revert IWallet7702.PolicyViolationTarget();
            }
            if (policy.selector != bytes4(0)) {
                bytes4 calledSelector = bytes4(calls[i].data);
                if (calledSelector != policy.selector) {
                    revert IWallet7702.PolicyViolationSelector();
                }
            }
            if (calls[i].value > policy.valueLimit) {
                revert IWallet7702.PolicyViolationValue();
            }
        }

        // 4. EIP-712 signature verification
        uint256 nonce = $.nonce;
        bytes32 callsHash = _hashCalls(calls);
        bytes32 digest = _hashTypedData(keccak256(abi.encode(_BATCH_EXECUTION_TYPEHASH, sessionKey, callsHash, nonce)));
        address recovered = _recoverSigner(digest, signature);
        if (recovered != sessionKey) {
            revert IWallet7702.Unauthorized();
        }

        $.nonce = nonce + 1;
    }

    /// @notice Check if a session key exists (has a non-zero policy).
    function isSessionKey(address sessionKey) internal view returns (bool) {
        Storage.WalletStorage storage $ = _storage();
        IWallet7702.SessionKeyPolicy memory policy = $.sessionKeys[sessionKey];
        return !(policy.validAfter == 0 && policy.validUntil == 0 && policy.target == address(0)
                && policy.selector == bytes4(0) && policy.valueLimit == 0);
    }

    // --- EIP-712 Helpers (shared with Wallet7702) ---

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @dev Hash an array of Call structs according to EIP-712 encoding.
    function _hashCalls(IWallet7702.Call[] calldata calls) internal pure returns (bytes32) {
        uint256 len = calls.length;
        bytes32[] memory hashes = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            hashes[i] = keccak256(abi.encode(_CALL_TYPEHASH, calls[i].target, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    // --- ECDSA Signature Recovery (shared with Wallet7702) ---

    function _recoverSigner(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(digest, v, r, s);
    }
}
