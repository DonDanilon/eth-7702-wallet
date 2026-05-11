// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseWebAuthn} from "../../src/auth/BaseWebAuthn.sol";

/// @notice Mock wrapper exposing BaseWebAuthn for Foundry tests.
contract WebAuthnMock {
    function verify(
        bytes memory challenge,
        bool requireUV,
        BaseWebAuthn.WebAuthnAuth memory auth,
        uint256 pubKeyX,
        uint256 pubKeyY
    ) external view returns (bool) {
        return BaseWebAuthn.verify(challenge, requireUV, auth, pubKeyX, pubKeyY);
    }
}
