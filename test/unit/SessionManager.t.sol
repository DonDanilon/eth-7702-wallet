// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SessionManagerMock} from "../mocks/SessionManagerMock.sol";
import {IWallet7702} from "../../src/interfaces/IWallet7702.sol";

/// @title SessionManagerTest - Unit tests for SessionManager library
/// @notice Covers session key lifecycle (add/revoke), policy enforcement
///         (time, target, selector, value limits), self-call prevention,
///         EIP-712 domain separation, and replay protection.
contract SessionManagerTest is Test {
    SessionManagerMock mock;

    uint256 constant SESSION_KEY_PK = 0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD;
    address sessionKey = vm.addr(SESSION_KEY_PK);

    bytes32 constant _EXECUTION_TYPEHASH =
        keccak256("SessionExecution(address sessionKey,address target,uint256 value,bytes data,uint256 nonce)");

    function setUp() public {
        // Warp to a known reasonable timestamp to avoid underflows
        vm.warp(365 days);
        mock = new SessionManagerMock();
    }

    // --- Helper: Build EIP-712 SessionExecution digest ---

    function _buildDigest(address session, address target, uint256 value, bytes memory data, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(_EXECUTION_TYPEHASH, session, target, value, keccak256(data), nonce));
        bytes32 domainSep = mock.domainSeparator();
        return keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
    }

    // --- Helper: Sign a digest with the session key using Foundry cheatcode ---

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    // =============================================================
    // Session Key Lifecycle Tests
    // =============================================================

    function test_SetSessionKey_EmitsEvent() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });

        vm.expectEmit(true, true, true, true);
        emit IWallet7702.SessionKeyAdded(sessionKey, policy);
        mock.setSessionKey(sessionKey, policy);

        assertTrue(mock.isSessionKey(sessionKey));
    }

    function test_RevokeSessionKey_EmitsEvent() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);
        assertTrue(mock.isSessionKey(sessionKey));

        IWallet7702.SessionKeyPolicy memory zeroPolicy;
        vm.expectEmit(true, true, true, true);
        emit IWallet7702.SessionKeyRevoked(sessionKey);
        mock.setSessionKey(sessionKey, zeroPolicy);

        assertFalse(mock.isSessionKey(sessionKey));
    }

    function test_IsSessionKey_ReturnsFalseForUnknownKey() public {
        address unknown = makeAddr("unknown");
        assertFalse(mock.isSessionKey(unknown));
    }

    // =============================================================
    // Self-Call Prevention
    // =============================================================

    function test_Validate_Revert_SelfCall() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"deadbeef";
        bytes32 digest = _buildDigest(sessionKey, address(mock), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.SelfCallNotAllowed.selector);
        mock.validateAndUseNonce(sessionKey, address(mock), 0, data, sig);
    }

    // =============================================================
    // Unauthorized / Unknown Session Key
    // =============================================================

    function test_Validate_Revert_UnknownSessionKey() public {
        address unknown = makeAddr("unknown");
        bytes memory data = hex"deadbeef";
        bytes memory sig = hex"";

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        mock.validateAndUseNonce(unknown, address(0x1), 0, data, sig);
    }

    // =============================================================
    // Time Window Enforcement
    // =============================================================

    function test_Validate_Revert_NotYetValid() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp + 1 hours),
            validUntil: uint48(block.timestamp + 2 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.SessionKeyExpired.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    function test_Validate_Revert_Expired() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp - 2 days),
            validUntil: uint48(block.timestamp - 1 hours),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.SessionKeyExpired.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    function test_Validate_Success_WithinTimeWindow() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
        assertEq(mock.nonce(), 1);
    }

    // =============================================================
    // Target Whitelist Enforcement
    // =============================================================

    function test_Validate_Revert_WrongTarget() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0xDEAD),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0xBEEF), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.PolicyViolationTarget.selector);
        mock.validateAndUseNonce(sessionKey, address(0xBEEF), 0, data, sig);
    }

    function test_Validate_Success_CorrectTarget() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0xDEAD),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0xDEAD), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0xDEAD), 0, data, sig);
        assertEq(mock.nonce(), 1);
    }

    function test_Validate_Success_AnyTarget() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0xCAFE), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0xCAFE), 0, data, sig);
        assertEq(mock.nonce(), 1);
    }

    // =============================================================
    // Selector Enforcement
    // =============================================================

    function test_Validate_Revert_WrongSelector() public {
        bytes4 allowedSelector = bytes4(keccak256("transfer(address,uint256)"));
        bytes4 actualSelector = bytes4(keccak256("approve(address,uint256)"));
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: allowedSelector,
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = abi.encodeWithSelector(actualSelector, address(0x1), uint256(100));
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.PolicyViolationSelector.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    function test_Validate_Success_CorrectSelector() public {
        bytes4 allowedSelector = bytes4(keccak256("transfer(address,uint256)"));
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: allowedSelector,
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = abi.encodeWithSelector(allowedSelector, address(0x1), uint256(100));
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
        assertEq(mock.nonce(), 1);
    }

    function test_Validate_Success_AnySelector() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = abi.encodeWithSignature("doSomething()");
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
        assertEq(mock.nonce(), 1);
    }

    // =============================================================
    // Value Limit Enforcement
    // =============================================================

    function test_Validate_Revert_ValueExceedsLimit() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 0.5 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 1 ether, data, mock.nonce());
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.PolicyViolationValue.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 1 ether, data, sig);
    }

    function test_Validate_Success_ValueWithinLimit() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0.5 ether, data, mock.nonce());
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0x1), 0.5 ether, data, sig);
        assertEq(mock.nonce(), 1);
    }

    // =============================================================
    // EIP-712 Signature Validation
    // =============================================================

    function test_Validate_Revert_InvalidSignature() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        // Build digest for a different wallet but sign with our session key
        bytes32 digest = _buildDigest(makeAddr("other"), address(0x1), 0, data, mock.nonce());
        bytes memory sig = _sign(digest);

        // The recovered address will be sessionKey, but sessionKey in the struct is "other"
        vm.expectRevert(IWallet7702.Unauthorized.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    function test_Validate_Revert_WrongDomainSeparator() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        // Build domain separator with a different verifyingContract
        bytes32 wrongDomain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EIP-7702 Wallet"),
                keccak256("1"),
                block.chainid,
                address(0xBADC0DE)
            )
        );
        // Use same struct hash but wrong domain => wrong digest
        bytes32 structHash = keccak256(
            abi.encode(_EXECUTION_TYPEHASH, sessionKey, address(0x1), uint256(0), keccak256(data), mock.nonce())
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", wrongDomain, structHash));
        bytes memory sig = _sign(digest);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    function test_Validate_Revert_WrongSigner() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, mock.nonce());
        // Sign with a DIFFERENT key
        uint256 otherPk = SESSION_KEY_PK + 1;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    // =============================================================
    // Nonce / Replay Protection
    // =============================================================

    function test_Validate_NonceIncrements() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest1 = _buildDigest(sessionKey, address(0x1), 0, data, 0);
        bytes memory sig1 = _sign(digest1);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig1);
        assertEq(mock.nonce(), 1);

        bytes32 digest2 = _buildDigest(sessionKey, address(0x1), 0, data, 1);
        bytes memory sig2 = _sign(digest2);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig2);
        assertEq(mock.nonce(), 2);
    }

    function test_Validate_Revert_ReplaySameNonce() public {
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        mock.setSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes32 digest = _buildDigest(sessionKey, address(0x1), 0, data, 0);
        bytes memory sig = _sign(digest);

        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
        assertEq(mock.nonce(), 1);

        // Replay: sig was signed for nonce=0, but current nonce is 1.
        // The contract computes digest with nonce=1, which doesn't match the sig.
        vm.expectRevert(IWallet7702.Unauthorized.selector);
        mock.validateAndUseNonce(sessionKey, address(0x1), 0, data, sig);
    }

    // =============================================================
    // Domain Separator Integrity
    // =============================================================

    function test_DomainSeparator_MatchesExpected() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EIP-7702 Wallet"),
                keccak256("1"),
                block.chainid,
                address(mock)
            )
        );
        assertEq(mock.domainSeparator(), expected);
    }
}
