// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWallet7702} from "../../src/interfaces/IWallet7702.sol";
import {SessionManager} from "../../src/auth/SessionManager.sol";
import {Storage} from "../../src/Storage.sol";

/// @notice Mock wrapper exposing SessionManager library functions for Foundry tests.
contract SessionManagerMock {
    function setSessionKey(address sessionKey, IWallet7702.SessionKeyPolicy calldata policy) external {
        SessionManager.setSessionKey(sessionKey, policy);
    }

    function validateAndUseNonce(
        address sessionKey,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) external {
        SessionManager.validateAndUseNonce(sessionKey, target, value, data, signature);
    }

    function isSessionKey(address sessionKey) external view returns (bool) {
        return SessionManager.isSessionKey(sessionKey);
    }

    function domainSeparator() external view returns (bytes32) {
        return SessionManager.domainSeparator();
    }

    function nonce() external view returns (uint256) {
        return Storage._getWalletStorage().nonce;
    }
}
