// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FCL - P-256 (secp256r1) Signature Verification via Daimo's Audited Verifier
/// @notice Thin wrapper around Daimo's P256Verifier deployed at a deterministic CREATE2
///         address. Used as fallback when RIP-7212 precompile (0x100) is unavailable.
/// @dev    Daimo's contract: 0xc2b78104907F722DABAc4C69f826a522B2754De4
///         Gas cost ~330k per verification.
library FCL {
    /// @notice Daimo's audited P256Verifier, deployed via CREATE2.
    ///         Same address on all EVM chains. Matches EIP-7212 precompile interface.
    address internal constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    uint256 internal constant N_DIV_2 = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8;

    /// @notice Verify a P-256 ECDSA signature.
    /// @dev    Calls Daimo's P256Verifier via staticcall following EIP-7212 calldata format.
    ///         Malleability check (s <= N/2) is enforced by the caller (BaseWebAuthn).
    function ecdsa_verify(bytes32 messageHash, uint256 r, uint256 s, uint256 pubKeyX, uint256 pubKeyY)
        internal
        view
        returns (bool)
    {
        // EIP-7212 calldata encoding:
        // input[  0: 32] = signed data hash
        // input[ 32: 64] = signature r
        // input[ 64: 96] = signature s
        // input[ 96:128] = public key x
        // input[128:160] = public key y
        bytes memory input = abi.encode(messageHash, r, s, pubKeyX, pubKeyY);

        (bool success, bytes memory ret) = P256_VERIFIER.staticcall(input);

        if (!success || ret.length < 32) return false;

        return abi.decode(ret, (uint256)) == 1;
    }
}
