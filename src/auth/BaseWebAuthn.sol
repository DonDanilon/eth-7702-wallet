// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base64URL} from "./Base64URL.sol";
import {FCL} from "./FCL.sol";

/// @title BaseWebAuthn - WebAuthn assertion verification with RIP-7212 + FCL fallback
/// @notice Verifies WebAuthn/FIDO2 authentication assertions. Prioritizes RIP-7212
///         precompile (address 0x100, ~3,450 gas) and falls back to Daimo's FCL
///         on-chain P-256 math (~330k gas) if the precompile returns empty data.
library BaseWebAuthn {
    struct WebAuthnAuth {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 challengeIndex;
        uint256 typeIndex;
        uint256 r;
        uint256 s;
    }

    bytes1 private constant _AUTH_DATA_FLAGS_UP = 0x01; // User Present
    bytes1 private constant _AUTH_DATA_FLAGS_UV = 0x04; // User Verified
    address private constant _RIP7212 = address(0x100);

    /// @notice Verify a WebAuthn authentication assertion.
    /// @param challenge      Raw challenge bytes provided by the relying party.
    /// @param requireUV      Require User Verification (e.g., biometric).
    /// @param auth           The WebAuthnAuth struct.
    /// @param pubKeyX        P-256 public key X coordinate.
    /// @param pubKeyY        P-256 public key Y coordinate.
    /// @return valid         True if the assertion is valid.
    function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory auth, uint256 pubKeyX, uint256 pubKeyY)
        internal
        view
        returns (bool valid)
    {
        // --- Malleability guard ---
        if (auth.s > FCL.N_DIV_2) return false;

        // --- Verify authenticatorData is well-formed ---
        if (auth.authenticatorData.length < 37) return false;
        bytes1 flags = auth.authenticatorData[32];
        if (flags & _AUTH_DATA_FLAGS_UP != _AUTH_DATA_FLAGS_UP) return false;
        if (requireUV && (flags & _AUTH_DATA_FLAGS_UV) != _AUTH_DATA_FLAGS_UV) return false;

        // --- Verify response type is "webauthn.get" ---
        if (!_contains(auth.clientDataJSON, auth.typeIndex, '"type":"webauthn.get"')) return false;

        // --- Verify challenge is present in clientDataJSON ---
        string memory expectedChallenge = string.concat('"challenge":"', Base64URL.encode(challenge), '"');
        if (!_contains(auth.clientDataJSON, auth.challengeIndex, expectedChallenge)) return false;

        // --- Compute the signed message hash ---
        bytes32 clientDataHash = sha256(bytes(auth.clientDataJSON));
        bytes32 messageHash = sha256(abi.encodePacked(auth.authenticatorData, clientDataHash));

        // Try RIP-7212 precompile first
        bytes memory args = abi.encode(messageHash, auth.r, auth.s, pubKeyX, pubKeyY);
        (bool success, bytes memory ret) = _RIP7212.staticcall(args);

        // If precompile exists AND returned a result, decode and check
        if (success && ret.length > 0) {
            return abi.decode(ret, (uint256)) == 1;
        }

        // Fallback: Daimo FCL on-chain verification
        return FCL.ecdsa_verify(messageHash, auth.r, auth.s, pubKeyX, pubKeyY);
    }

    function _contains(string memory haystack, uint256 offset, string memory needle) private pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory n = bytes(needle);
        uint256 nLen = n.length;
        if (offset + nLen > h.length) return false;
        for (uint256 i = 0; i < nLen; i++) {
            if (h[offset + i] != n[i]) return false;
        }
        return true;
    }
}
