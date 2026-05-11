// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {Wallet7702} from "../../src/Wallet7702.sol";
import {IWallet7702} from "../../src/interfaces/IWallet7702.sol";
import {BaseWebAuthn} from "../../src/auth/BaseWebAuthn.sol";
import {Base64URL} from "../../src/auth/Base64URL.sol";
import {Storage} from "../../src/Storage.sol";

/// @title Wallet7702Test - Integration tests for the EIP-7702 Wallet singleton
/// @notice Uses vm.etch to simulate EIP-7702 delegation (wallet code runs in EOA context).
///         Mocks RIP-7212 precompile at 0x100 for positive executeRoot tests.
contract Wallet7702Test is Test {
    Wallet7702 walletImpl;

    uint256 constant EOA_PK = 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF;
    address eoa = vm.addr(EOA_PK);

    uint256 constant SESSION_PK = 0xCAFECAFECAFECAFECAFECAFECAFECAFECAFECAFECAFECAFECAFECAFECAFECAFE;
    address sessionKey = vm.addr(SESSION_PK);

    uint256 constant DUMMY_PK_X = 1;
    uint256 constant DUMMY_PK_Y = 2;

    bytes32 constant _INIT_TYPEHASH = keccak256("Initialize(uint256 pubKeyX,uint256 pubKeyY)");
    bytes32 constant _ROOT_EXECUTION_TYPEHASH =
        keccak256("RootExecution(address target,uint256 value,bytes data,uint256 nonce)");
    bytes32 constant _CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
    bytes32 constant _ROOT_BATCH_EXECUTION_TYPEHASH =
        keccak256("RootBatchExecution(Call[] calls,uint256 nonce)Call(address target,uint256 value,bytes data)");
    bytes32 constant _SESSION_BATCH_EXECUTION_TYPEHASH = keccak256(
        "SessionBatchExecution(address sessionKey,Call[] calls,uint256 nonce)Call(address target,uint256 value,bytes data)"
    );
    bytes32 constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant _NAME_HASH = keccak256("EIP-7702 Wallet");
    bytes32 constant _VERSION_HASH = keccak256("1");

    // Target contract for execution tests
    address constant TARGET = address(0xB0B);

    function setUp() public {
        // Warp to a known timestamp to avoid underflows.
        vm.warp(365 days);
        walletImpl = new Wallet7702();
        // Simulate EIP-7702 delegation: etch the wallet implementation code onto the EOA.
        // After this, calls to `eoa` execute Wallet7702 logic with address(this) == eoa.
        vm.etch(eoa, address(walletImpl).code);

        _deployRIP7212Mock();
    }

    // =============================================================
    // RIP-7212 Mock Precompile
    // =============================================================

    /// @dev Etch a tiny contract at 0x100 that returns abi.encode(uint256(1)).
    ///      Bytecode: mstore(0,1) return(0,32) => 0x600160005260206000F3
    function _deployRIP7212Mock() internal {
        bytes memory code = hex"600160005260206000F3";
        vm.etch(address(0x100), code);
    }

    // =============================================================
    // Helpers
    // =============================================================

    /// @dev Compute the EIP-712 domain separator as Wallet7702 would.
    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, verifyingContract));
    }

    /// @dev Hash typed data EIP-712 style.
    function _hashTypedData(address verifyingContract, bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(verifyingContract), structHash));
    }

    /// @dev Build and sign an initialize() digest with the EOA key.
    ///      verifyingContract must be `eoa` because after vm.etch, address(this) == eoa.
    function _signInit(uint256 pkX, uint256 pkY) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(_INIT_TYPEHASH, pkX, pkY));
        bytes32 digest = _hashTypedData(eoa, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EOA_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build a minimal WebAuthnAuth for negative tests (crypto will fail).
    function _dummyAuth() internal pure returns (BaseWebAuthn.WebAuthnAuth memory) {
        bytes memory authData = new bytes(37);
        authData[32] = 0x01; // UP flag set
        return BaseWebAuthn.WebAuthnAuth({
            authenticatorData: authData,
            clientDataJSON: '{"type":"webauthn.get","challenge":"AA","origin":"https://test.com"}',
            challengeIndex: 23,
            typeIndex: 1,
            r: 1,
            s: 1
        });
    }

    /// @dev Build a valid WebAuthnAuth whose challenge matches the EIP-712 RootExecution digest.
    function _buildValidAuth(address target, uint256 value, bytes memory data, uint256 nonce)
        internal
        view
        returns (BaseWebAuthn.WebAuthnAuth memory)
    {
        // Compute the EIP-712 digest that executeRoot expects as the challenge
        bytes32 structHash = keccak256(abi.encode(_ROOT_EXECUTION_TYPEHASH, target, value, keccak256(data), nonce));
        bytes32 digest = _hashTypedData(eoa, structHash);
        bytes memory challenge = abi.encodePacked(digest);
        string memory encodedChallenge = Base64URL.encode(challenge);

        // Build clientDataJSON with the correct challenge embedded
        string memory cdJSON =
            string.concat('{"type":"webauthn.get","challenge":"', encodedChallenge, '","origin":"https://test.com"}');

        // Build authenticatorData: 37 bytes, UP|UV flags at byte 32
        bytes memory authData = new bytes(37);
        authData[32] = 0x05; // UP=1, UV=1

        return BaseWebAuthn.WebAuthnAuth({
            authenticatorData: authData,
            clientDataJSON: cdJSON,
            challengeIndex: 23, // start of "challenge":"..."
            typeIndex: 1, // start of "type":"webauthn.get"
            r: 1,
            s: 1
        });
    }

    /// @dev Initialize the wallet (must be called as the EOA).
    function _doInitialize() internal {
        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);
        bytes memory sig = _signInit(DUMMY_PK_X, DUMMY_PK_Y);
        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    /// @dev Add a session key via the root-authorized path (prank as eoa == address(this)).
    function _addSessionKey(address sk, IWallet7702.SessionKeyPolicy memory policy) internal {
        vm.prank(eoa);
        IWallet7702(eoa).setSessionKey(sk, policy);
    }

    /// @dev Sign a SessionExecution EIP-712 digest with a session key.
    function _signSessionExecution(
        address sk,
        uint256 skPk,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 execTypehash = keccak256(
            "SessionExecution(address sessionKey,address target,uint256 value,bytes data,uint256 nonce)"
        );
        bytes32 structHash = keccak256(abi.encode(execTypehash, sk, target, value, keccak256(data), nonce));
        // After etch, address(this) == eoa, so domain verifyingContract = eoa
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EIP-7702 Wallet"),
                keccak256("1"),
                block.chainid,
                eoa
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(skPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // =============================================================
    // receive() Tests
    // =============================================================

    function test_Receive_AcceptsETH() public {
        uint256 balBefore = eoa.balance;
        (bool ok,) = eoa.call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(eoa.balance, balBefore + 1 ether);
    }

    // =============================================================
    // fallback() Tests
    // =============================================================

    function test_Fallback_RevertsOnUnknownSelector() public {
        // Low-level call with unknown selector hits fallback → Unauthorized
        (bool ok,) = eoa.call(abi.encodeWithSignature("nonexistent()"));
        assertFalse(ok);
    }

    // =============================================================
    // initialize() — Positive
    // =============================================================

    function test_Initialize_Success() public {
        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);
        bytes memory sig = _signInit(DUMMY_PK_X, DUMMY_PK_Y);

        vm.expectEmit(true, true, true, true);
        emit IWallet7702.WalletInitialized(eoa, DUMMY_PK_X, DUMMY_PK_Y);

        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    function test_Initialize_EmitsCorrectEOA() public {
        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);
        bytes memory sig = _signInit(DUMMY_PK_X, DUMMY_PK_Y);

        vm.expectEmit(true, false, false, false);
        emit IWallet7702.WalletInitialized(eoa, 0, 0);

        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    // =============================================================
    // initialize() — Negative
    // =============================================================

    function test_Initialize_Revert_AlreadyInitialized() public {
        _doInitialize();

        IWallet7702.PasskeyData memory passkey2 = IWallet7702.PasskeyData(DUMMY_PK_X + 1, DUMMY_PK_Y + 1);
        bytes memory sig2 = _signInit(DUMMY_PK_X + 1, DUMMY_PK_Y + 1);

        vm.expectRevert(IWallet7702.AlreadyInitialized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey2, sig2);
    }

    function test_Initialize_Revert_WrongSigner() public {
        // Attacker signs with their own key for the victim's (eoa) domain.
        // recovered == attacker, but address(this) == eoa → mismatch.
        uint256 attackerPk = 0xBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF;
        address attacker = vm.addr(attackerPk);

        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);
        bytes32 structHash = keccak256(abi.encode(_INIT_TYPEHASH, DUMMY_PK_X, DUMMY_PK_Y));
        bytes32 digest = _hashTypedData(eoa, structHash); // domain = eoa (victim)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(IWallet7702.InvalidInitializationSignature.selector);
        vm.prank(attacker);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    function test_Initialize_Revert_InvalidSignature() public {
        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);
        bytes memory badSig = hex"deadbeef";

        vm.expectRevert(IWallet7702.InvalidInitializationSignature.selector);
        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, badSig);
    }

    function test_Initialize_Revert_WrongPasskeyInSig() public {
        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(3, 4);
        bytes memory sig = _signInit(1, 2); // signed for (1,2)

        vm.expectRevert(IWallet7702.InvalidInitializationSignature.selector);
        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    function test_Initialize_Revert_WrongDomain() public {
        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);

        bytes32 structHash = keccak256(abi.encode(_INIT_TYPEHASH, DUMMY_PK_X, DUMMY_PK_Y));
        bytes32 wrongDomain =
            keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, address(0xBADC0DE)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", wrongDomain, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EOA_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(IWallet7702.InvalidInitializationSignature.selector);
        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    // =============================================================
    // executeRoot() — Positive
    // =============================================================

    function test_ExecuteRoot_Success() public {
        _doInitialize();

        bytes memory callData = hex"deadbeef";
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidAuth(TARGET, 0, callData, 0);

        vm.prank(eoa);
        bytes memory result = IWallet7702(eoa).executeRoot(TARGET, 0, callData, auth);
        // TARGET has no code, so call succeeds with empty return
        assertEq(result.length, 0);
    }

    function test_ExecuteRoot_Success_WithValue() public {
        _doInitialize();
        vm.deal(eoa, 2 ether);

        bytes memory callData = hex"";
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidAuth(TARGET, 1 ether, callData, 0);

        uint256 balBefore = TARGET.balance;

        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 1 ether, callData, auth);

        assertEq(TARGET.balance, balBefore + 1 ether);
    }

    function test_ExecuteRoot_Success_RotatePasskey() public {
        // Full flow: initialize → executeRoot → rotatePasskey (self-call)
        _doInitialize();

        IWallet7702.PasskeyData memory newPk = IWallet7702.PasskeyData(99, 100);
        bytes memory callData = abi.encodeWithSelector(IWallet7702.rotatePasskey.selector, newPk);

        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidAuth(eoa, 0, callData, 0);

        vm.expectEmit(true, true, true, true);
        emit IWallet7702.PasskeyRotated(99, 100);

        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(eoa, 0, callData, auth);
    }

    function test_ExecuteRoot_Success_SetSessionKey() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        bytes memory callData = abi.encodeWithSelector(IWallet7702.setSessionKey.selector, sessionKey, policy);

        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidAuth(eoa, 0, callData, 0);

        vm.expectEmit(true, true, true, true);
        emit IWallet7702.SessionKeyAdded(sessionKey, policy);

        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(eoa, 0, callData, auth);
    }

    // =============================================================
    // executeRoot() — Negative (not initialized)
    // =============================================================

    function test_ExecuteRoot_Revert_NotInitialized() public {
        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        vm.expectRevert(IWallet7702.NotInitialized.selector);
        IWallet7702(eoa).executeRoot(TARGET, 0, hex"", auth);
    }

    // =============================================================
    // executeRoot() — Negative (invalid WebAuthn)
    // =============================================================

    function test_ExecuteRoot_Revert_InvalidAuth_ShortAuthData() public {
        _doInitialize();

        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        auth.authenticatorData = hex"dead"; // too short (< 37 bytes)

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, hex"", auth);
    }

    function test_ExecuteRoot_Revert_InvalidAuth_UserPresentNotSet() public {
        _doInitialize();

        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        auth.authenticatorData = new bytes(37); // all zeros, UP not set

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, hex"", auth);
    }

    function test_ExecuteRoot_Revert_InvalidAuth_WrongType() public {
        _doInitialize();

        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        auth.clientDataJSON = '{"type":"webauthn.create","challenge":"AA","origin":"https://test.com"}';

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, hex"", auth);
    }

    function test_ExecuteRoot_Revert_InvalidAuth_MalleableSignature() public {
        _doInitialize();

        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        // s > N/2 triggers malleability rejection
        auth.s = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DACE5618E24C9B; // N/2 + 1

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, hex"", auth);
    }

    function test_ExecuteRoot_Revert_InvalidAuth_RequireUVNotSet() public {
        _doInitialize();

        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        // UP set but UV not set — executeRoot requires UV (requireUV=true)
        auth.authenticatorData[32] = 0x01; // UP=1, UV=0

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, hex"", auth);
    }

    // =============================================================
    // executeRoot() — Nonce replay protection
    // =============================================================

    function test_ExecuteRoot_NoncePreventsReplay() public {
        _doInitialize();

        bytes memory callData = hex"deadbeef";
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidAuth(TARGET, 0, callData, 0);

        // First call succeeds
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, callData, auth);

        // Replay with same auth (nonce was 0, now it's 1 → challenge mismatch)
        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeRoot(TARGET, 0, callData, auth);
    }

    // =============================================================
    // executeRoot() — msg.value forwarding
    // =============================================================

    function test_ExecuteRoot_Revert_NotInitialized_WithValue() public {
        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        vm.expectRevert(IWallet7702.NotInitialized.selector);
        IWallet7702(eoa).executeRoot{value: 1 ether}(TARGET, 1 ether, hex"", auth);
    }

    // =============================================================
    // executeSession() — Positive
    // =============================================================

    function test_ExecuteSession_Success() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"deadbeef";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 0, data, 0);

        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);
    }

    function test_ExecuteSession_Success_WithValue() public {
        _doInitialize();
        vm.deal(eoa, 2 ether);

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 0.5 ether, data, 0);

        uint256 balBefore = TARGET.balance;

        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0.5 ether, data, sig);

        assertEq(TARGET.balance, balBefore + 0.5 ether);
    }

    // =============================================================
    // executeSession() — Negative
    // =============================================================

    function test_ExecuteSession_Revert_NotInitialized() public {
        vm.expectRevert(IWallet7702.NotInitialized.selector);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, hex"", hex"");
    }

    function test_ExecuteSession_Revert_UnknownSessionKey() public {
        _doInitialize();

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, hex"", hex"");
    }

    function test_ExecuteSession_Revert_SelfCall() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, eoa, 0, data, 0);

        vm.expectRevert(IWallet7702.SelfCallNotAllowed.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, eoa, 0, data, sig);
    }

    function test_ExecuteSession_Revert_Expired() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp - 2 days),
            validUntil: uint48(block.timestamp - 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 0, data, 0);

        vm.expectRevert(IWallet7702.SessionKeyExpired.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);
    }

    function test_ExecuteSession_Revert_NotYetValid() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp + 1 hours),
            validUntil: uint48(block.timestamp + 2 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 0, data, 0);

        vm.expectRevert(IWallet7702.SessionKeyExpired.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);
    }

    function test_ExecuteSession_Revert_WrongTarget() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0xDEAD),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, address(0xBEEF), 0, data, 0);

        vm.expectRevert(IWallet7702.PolicyViolationTarget.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, address(0xBEEF), 0, data, sig);
    }

    function test_ExecuteSession_Revert_WrongSelector() public {
        _doInitialize();

        bytes4 allowedSelector = bytes4(keccak256("transfer(address,uint256)"));
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: allowedSelector,
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes4 actualSelector = bytes4(keccak256("approve(address,uint256)"));
        bytes memory data = abi.encodeWithSelector(actualSelector, address(0x1), uint256(100));
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 0, data, 0);

        vm.expectRevert(IWallet7702.PolicyViolationSelector.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);
    }

    function test_ExecuteSession_Revert_ValueExceedsLimit() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 0.5 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 1 ether, data, 0);

        vm.expectRevert(IWallet7702.PolicyViolationValue.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 1 ether, data, sig);
    }

    function test_ExecuteSession_Revert_InvalidSignature() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        // Sign with wrong key
        uint256 otherPk = SESSION_PK + 1;
        bytes32 execTypehash =
            keccak256("SessionExecution(address sessionKey,address target,uint256 value,bytes data,uint256 nonce)");
        bytes32 structHash =
            keccak256(abi.encode(execTypehash, sessionKey, TARGET, uint256(0), keccak256(data), uint256(0)));
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EIP-7702 Wallet"),
                keccak256("1"),
                block.chainid,
                eoa
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);
    }

    function test_ExecuteSession_Revert_ReplaySameNonce() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes memory data = hex"";
        bytes memory sig = _signSessionExecution(sessionKey, SESSION_PK, TARGET, 0, data, 0);

        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);

        // Replay: same sig, but nonce has advanced to 1
        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeSession(sessionKey, TARGET, 0, data, sig);
    }

    // =============================================================
    // rotatePasskey() — Access Control
    // =============================================================

    function test_RotatePasskey_Revert_DirectCall() public {
        _doInitialize();

        IWallet7702.PasskeyData memory newPk = IWallet7702.PasskeyData(99, 100);

        // Direct call from non-self address must revert
        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(address(0xB0B));
        IWallet7702(eoa).rotatePasskey(newPk);
    }

    function test_RotatePasskey_Revert_NotInitialized() public {
        // Deploy a fresh EOA that hasn't been initialized
        address freshEoa = address(0xABCD);
        vm.etch(freshEoa, address(walletImpl).code);

        IWallet7702.PasskeyData memory newPk = IWallet7702.PasskeyData(99, 100);

        vm.expectRevert(IWallet7702.NotInitialized.selector);
        vm.prank(freshEoa);
        IWallet7702(freshEoa).rotatePasskey(newPk);
    }

    function test_RotatePasskey_Success_WhenCalledViaSelf() public {
        _doInitialize();

        IWallet7702.PasskeyData memory newPk = IWallet7702.PasskeyData(99, 100);

        vm.expectEmit(true, true, true, true);
        emit IWallet7702.PasskeyRotated(99, 100);

        vm.prank(eoa);
        IWallet7702(eoa).rotatePasskey(newPk);
    }

    // =============================================================
    // setSessionKey() — Access Control
    // =============================================================

    function test_SetSessionKey_Revert_DirectCall() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(address(0xB0B));
        IWallet7702(eoa).setSessionKey(sessionKey, policy);
    }

    function test_SetSessionKey_Revert_NotInitialized() public {
        address freshEoa = address(0xABCD);
        vm.etch(freshEoa, address(walletImpl).code);

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });

        vm.expectRevert(IWallet7702.NotInitialized.selector);
        vm.prank(freshEoa);
        IWallet7702(freshEoa).setSessionKey(sessionKey, policy);
    }

    function test_SetSessionKey_Success_AddAndRevoke() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });

        vm.expectEmit(true, true, true, true);
        emit IWallet7702.SessionKeyAdded(sessionKey, policy);
        vm.prank(eoa);
        IWallet7702(eoa).setSessionKey(sessionKey, policy);

        // Revoke
        IWallet7702.SessionKeyPolicy memory zeroPolicy;
        vm.expectEmit(true, true, true, true);
        emit IWallet7702.SessionKeyRevoked(sessionKey);
        vm.prank(eoa);
        IWallet7702(eoa).setSessionKey(sessionKey, zeroPolicy);
    }

    // =============================================================
    // EIP-712 Domain Separation
    // =============================================================

    function test_DomainSeparation_DifferentWalletDifferentDomain() public {
        // Deploy a second wallet implementation and etch onto a different EOA
        Wallet7702 walletImpl2 = new Wallet7702();
        address eoa2 = address(0xBBBB);
        vm.etch(eoa2, address(walletImpl2).code);

        IWallet7702.PasskeyData memory passkey = IWallet7702.PasskeyData(DUMMY_PK_X, DUMMY_PK_Y);

        // Sign for eoa2's domain
        bytes32 structHash = keccak256(abi.encode(_INIT_TYPEHASH, DUMMY_PK_X, DUMMY_PK_Y));
        bytes32 domain2 = keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, eoa2));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain2, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EOA_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Try to use eoa2's signature on eoa — must fail
        vm.expectRevert(IWallet7702.InvalidInitializationSignature.selector);
        vm.prank(eoa);
        IWallet7702(eoa).initialize(passkey, sig);
    }

    // =============================================================
    // executeSession() — msg.value forwarding
    // =============================================================

    function test_ExecuteSession_Revert_NotInitialized_WithValue() public {
        vm.expectRevert(IWallet7702.NotInitialized.selector);
        IWallet7702(eoa).executeSession{value: 1 ether}(sessionKey, TARGET, 1 ether, hex"", hex"");
    }

    // =============================================================
    // Batch Helpers
    // =============================================================

    /// @dev Build Call array from pairs of (target, value, data).
    function _buildCalls(address[] memory targets, uint256[] memory values, bytes[] memory datas)
        internal
        pure
        returns (IWallet7702.Call[] memory calls)
    {
        uint256 len = targets.length;
        calls = new IWallet7702.Call[](len);
        for (uint256 i = 0; i < len; i++) {
            calls[i] = IWallet7702.Call({target: targets[i], value: values[i], data: datas[i]});
        }
    }

    /// @dev Build a valid WebAuthnAuth for executeBatchRoot.
    function _buildValidBatchAuth(IWallet7702.Call[] memory calls, uint256 nonce)
        internal
        view
        returns (BaseWebAuthn.WebAuthnAuth memory)
    {
        bytes32 callsHash = _hashCallsHelper(calls);
        bytes32 structHash = keccak256(abi.encode(_ROOT_BATCH_EXECUTION_TYPEHASH, callsHash, nonce));
        bytes32 digest = _hashTypedData(eoa, structHash);
        bytes memory challenge = abi.encodePacked(digest);
        string memory encodedChallenge = Base64URL.encode(challenge);

        string memory cdJSON =
            string.concat('{"type":"webauthn.get","challenge":"', encodedChallenge, '","origin":"https://test.com"}');
        bytes memory authData = new bytes(37);
        authData[32] = 0x05;

        return BaseWebAuthn.WebAuthnAuth({
            authenticatorData: authData, clientDataJSON: cdJSON, challengeIndex: 23, typeIndex: 1, r: 1, s: 1
        });
    }

    /// @dev Hash a Call[] array for EIP-712 (matches contract _hashCalls).
    function _hashCallsHelper(IWallet7702.Call[] memory calls) internal pure returns (bytes32) {
        uint256 len = calls.length;
        bytes32[] memory hashes = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            hashes[i] = keccak256(abi.encode(_CALL_TYPEHASH, calls[i].target, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /// @dev Sign a SessionBatchExecution EIP-712 digest with a session key.
    function _signSessionBatchExecution(address sk, uint256 skPk, IWallet7702.Call[] memory calls, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 callsHash = _hashCallsHelper(calls);
        bytes32 structHash = keccak256(abi.encode(_SESSION_BATCH_EXECUTION_TYPEHASH, sk, callsHash, nonce));
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EIP-7702 Wallet"),
                keccak256("1"),
                block.chainid,
                eoa
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(skPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // =============================================================
    // executeBatchRoot() — Positive
    // =============================================================

    function test_ExecuteBatchRoot_Success_SingleCall() public {
        _doInitialize();

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"cafe";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidBatchAuth(calls, 0);

        vm.prank(eoa);
        bytes[] memory results = IWallet7702(eoa).executeBatchRoot(calls, auth);
        assertEq(results.length, 1);
    }

    function test_ExecuteBatchRoot_Success_MultipleCalls() public {
        _doInitialize();

        address[] memory targets = new address[](3);
        targets[0] = TARGET;
        targets[1] = address(0xB0C);
        targets[2] = address(0xB0D);
        uint256[] memory values = new uint256[](3);
        bytes[] memory datas = new bytes[](3);
        datas[0] = hex"01";
        datas[1] = hex"02";
        datas[2] = hex"03";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidBatchAuth(calls, 0);

        vm.prank(eoa);
        bytes[] memory results = IWallet7702(eoa).executeBatchRoot(calls, auth);
        assertEq(results.length, 3);
    }

    function test_ExecuteBatchRoot_Success_WithValue() public {
        _doInitialize();
        vm.deal(eoa, 3 ether);

        address[] memory targets = new address[](2);
        targets[0] = TARGET;
        targets[1] = address(0xB0C);
        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 0.5 ether;
        bytes[] memory datas = new bytes[](2);

        uint256 balTBef = TARGET.balance;
        uint256 balCBef = address(0xB0C).balance;

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidBatchAuth(calls, 0);

        vm.prank(eoa);
        IWallet7702(eoa).executeBatchRoot(calls, auth);

        assertEq(TARGET.balance, balTBef + 1 ether);
        assertEq(address(0xB0C).balance, balCBef + 0.5 ether);
    }

    function test_ExecuteBatchRoot_Success_RotateAndSetSessionInBatch() public {
        // Root can self-call in batch: rotatePasskey + setSessionKey in one batch
        _doInitialize();

        IWallet7702.PasskeyData memory newPk = IWallet7702.PasskeyData(77, 88);
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 2 ether
        });

        address[] memory targets = new address[](2);
        targets[0] = eoa;
        targets[1] = eoa;
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(IWallet7702.rotatePasskey.selector, newPk);
        datas[1] = abi.encodeWithSelector(IWallet7702.setSessionKey.selector, sessionKey, policy);

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);

        // Both events should fire
        vm.expectEmit(true, true, true, true);
        emit IWallet7702.PasskeyRotated(77, 88);
        vm.expectEmit(true, true, true, true);
        emit IWallet7702.SessionKeyAdded(sessionKey, policy);

        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidBatchAuth(calls, 0);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchRoot(calls, auth);
    }

    // =============================================================
    // executeBatchRoot() — Negative
    // =============================================================

    function test_ExecuteBatchRoot_Revert_NotInitialized() public {
        IWallet7702.Call[] memory calls = new IWallet7702.Call[](0);
        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();
        vm.expectRevert(IWallet7702.NotInitialized.selector);
        IWallet7702(eoa).executeBatchRoot(calls, auth);
    }

    function test_ExecuteBatchRoot_Revert_UnauthorizedAuth() public {
        _doInitialize();

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"ff";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        // Use dummy auth (wrong challenge) instead of valid batch auth
        BaseWebAuthn.WebAuthnAuth memory auth = _dummyAuth();

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchRoot(calls, auth);
    }

    function test_ExecuteBatchRoot_Revert_ReplaySameNonce() public {
        _doInitialize();

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"bb";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidBatchAuth(calls, 0);

        vm.prank(eoa);
        IWallet7702(eoa).executeBatchRoot(calls, auth);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchRoot(calls, auth);
    }

    function test_ExecuteBatchRoot_Revert_TargetCallFailure() public {
        _doInitialize();

        // Deploy a contract that always reverts
        Reverter reverter = new Reverter();

        address[] memory targets = new address[](1);
        targets[0] = address(reverter);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"00000000";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        BaseWebAuthn.WebAuthnAuth memory auth = _buildValidBatchAuth(calls, 0);

        vm.expectRevert();
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchRoot(calls, auth);
    }

    // =============================================================
    // executeBatchSession() — Positive
    // =============================================================

    function test_ExecuteBatchSession_Success_SingleCall() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"beef";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.prank(eoa);
        bytes[] memory results = IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
        assertEq(results.length, 1);
    }

    function test_ExecuteBatchSession_Success_MultipleCalls() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](3);
        targets[0] = TARGET;
        targets[1] = address(0xB0C);
        targets[2] = address(0xB0D);
        uint256[] memory values = new uint256[](3);
        bytes[] memory datas = new bytes[](3);
        datas[0] = hex"10";
        datas[1] = hex"20";
        datas[2] = hex"30";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.prank(eoa);
        bytes[] memory results = IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
        assertEq(results.length, 3);
    }

    function test_ExecuteBatchSession_Success_WithValue() public {
        _doInitialize();
        vm.deal(eoa, 2 ether);

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](2);
        targets[0] = TARGET;
        targets[1] = address(0xB0C);
        uint256[] memory values = new uint256[](2);
        values[0] = 0.3 ether;
        values[1] = 0.7 ether;
        bytes[] memory datas = new bytes[](2);

        uint256 balTBef = TARGET.balance;
        uint256 balCBef = address(0xB0C).balance;

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);

        assertEq(TARGET.balance, balTBef + 0.3 ether);
        assertEq(address(0xB0C).balance, balCBef + 0.7 ether);
    }

    // =============================================================
    // executeBatchSession() — Negative
    // =============================================================

    function test_ExecuteBatchSession_Revert_NotInitialized() public {
        IWallet7702.Call[] memory calls = new IWallet7702.Call[](0);
        vm.expectRevert(IWallet7702.NotInitialized.selector);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, hex"");
    }

    function test_ExecuteBatchSession_Revert_UnknownSessionKey() public {
        _doInitialize();

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, hex"");
    }

    function test_ExecuteBatchSession_Revert_SelfCall() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = eoa; // self-call
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert(IWallet7702.SelfCallNotAllowed.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_Expired() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp - 2 days),
            validUntil: uint48(block.timestamp - 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert(IWallet7702.SessionKeyExpired.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_NotYetValid() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp + 1 hours),
            validUntil: uint48(block.timestamp + 2 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert(IWallet7702.SessionKeyExpired.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_WrongTarget() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: TARGET, // only TARGET allowed
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        // Batch tries to call a different address
        address[] memory targets = new address[](1);
        targets[0] = address(0xBEEF);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert(IWallet7702.PolicyViolationTarget.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_WrongSelector() public {
        _doInitialize();

        bytes4 allowedSelector = bytes4(keccak256("transfer(address,uint256)"));
        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: allowedSelector,
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        bytes4 badSelector = bytes4(keccak256("approve(address,uint256)"));
        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(badSelector, address(0x1), uint256(100));

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert(IWallet7702.PolicyViolationSelector.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_ValueExceedsLimit() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 0.5 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        values[0] = 1 ether; // exceeds per-call limit
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert(IWallet7702.PolicyViolationValue.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_InvalidSignature() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"ff";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        // Sign with a different key
        uint256 otherPk = SESSION_PK + 1;
        bytes memory sig = _signSessionBatchExecution(sessionKey, otherPk, calls, 0);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_ReplaySameNonce() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        address[] memory targets = new address[](1);
        targets[0] = TARGET;
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"dd";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);

        vm.expectRevert(IWallet7702.Unauthorized.selector);
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }

    function test_ExecuteBatchSession_Revert_TargetCallFailure() public {
        _doInitialize();

        IWallet7702.SessionKeyPolicy memory policy = IWallet7702.SessionKeyPolicy({
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 1 days),
            target: address(0),
            selector: bytes4(0),
            valueLimit: 1 ether
        });
        _addSessionKey(sessionKey, policy);

        Reverter reverter = new Reverter();

        address[] memory targets = new address[](1);
        targets[0] = address(reverter);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"00000000";

        IWallet7702.Call[] memory calls = _buildCalls(targets, values, datas);
        bytes memory sig = _signSessionBatchExecution(sessionKey, SESSION_PK, calls, 0);

        vm.expectRevert();
        vm.prank(eoa);
        IWallet7702(eoa).executeBatchSession(sessionKey, calls, sig);
    }
}

/// @notice Minimal contract that always reverts with 0xdead for testing batch call failures.
contract Reverter {
    fallback() external payable {
        assembly {
            mstore(0, 0xdead)
            revert(28, 2)
        }
    }
}
