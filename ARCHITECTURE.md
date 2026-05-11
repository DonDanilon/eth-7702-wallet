# Technical Specification: EIP-7702 Account Abstraction Wallet

## 1. Feasibility Analysis

__EIP-7702 + Passkeys (WebAuthn) + Session Keys__ This ecosystem perfectly marries maximum usability with cutting-edge protocol design:

- __EIP-7702 Synergy__: By including an authorization tuple in a transaction, a standard EOA temporarily (or persistently) points its code to a smart contract implementation. Because an EOA maintains its own storage space, it effectively becomes an instance of the Wallet Implementation smart contract without moving funds.
- __Passkeys as Root Authority__: Once the EOA is delegated to the Wallet Implementation, all subsequent major transactions are verified against the stored P-256 public key (WebAuthn). This eliminates the need for seed phrases, offloading security to hardware components (Secure Enclave/Biometrics).
- __Session Keys for Scalability__: Passkeys are high-friction for rapid consecutive actions (like gaming or high-frequency trading). Session Keys act as ephemeral ECDSA keypairs stored directly in the delegated EOA's storage. They bypass the Passkey checks, enabling highly scoped (time, target, value, selector) permissions for DApps without compromising the root account.
- __Batch transactions__: Allows to execute batches of transactions, signing them with either passkeys or session keys. 
- __Gas sponsorship__: Allows to integrate with paymasters.

## 2. System Architecture Overview

The system relies on an execution flow split into 4 core domain components:

1. __The EOA (The Account)__: Remains a fundamentally standard Ethereum address but natively delegates all smart contract functionalities using the EIP-7702 designator (`0xef0100 || ImplementationAddress`).
2. __Wallet Implementation (EIP-7702 Target)__: A singleton, stateless proxy target contract containing the business logic for standard `execute` and ERC-1271 `isValidSignature`.
3. __Passkey Verifier (Auth Module)__: An internal library resolving assertions. It first invokes __RIP-7212__ (via a `staticcall` to precompile address `0x100`). If the current chain lacks this precompile, it falls back to the __Daimo FreshCryptoLib (FCL) P-256__ implementation on-chain.
4. __Session Key Manager (Delegation Module)__: Intercepts `execute` calls routed with Session Key signatures. Validates the signature via ECDSA (`secp256k1`) and strictly enforces the preset policies (e.g., expiry, target whitelisting, Ether spend limits, and specific function selectors).

## 3. Wallet Interface Specs

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWallet7702 {
    /// @notice Struct to hold passkey WebAuthn coordinates.
    struct PasskeyData {
        uint256 pubKeyX;
        uint256 pubKeyY;
    }

    /// @notice Strict policy constraints for a localized Session Key.
    struct SessionKeyPolicy {
        uint48 validAfter;
        uint48 validUntil;
        address target;       // Target contract address (address(0) for any)
        bytes4 selector;      // Allowed function selector (bytes4(0) for any)
        uint256 valueLimit;   // Maximum Native ETH transaction value
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
    function executeRoot(address target, uint256 value, bytes calldata data, BaseWebAuthn.WebAuthnAuth calldata auth) external payable returns (bytes memory);
    
    /// @notice Session key transaction execution.
    function executeSession(
        address sessionKey,
        address target, 
        uint256 value, 
        bytes calldata data, 
        bytes calldata sessionSignature
    ) external payable returns (bytes memory);

    /// @notice Root key batched transaction execution.
    function executeBatchRoot(Call[] calldata calls, BaseWebAuthn.WebAuthnAuth calldata auth) external payable returns (bytes[] memory);

    /// @notice Session key batched transaction execution.
    function executeBatchSession(
        address sessionKey,
        Call[] calldata calls,
        bytes calldata sessionSignature
    ) external payable returns (bytes[] memory);

    /// @notice Handles WebAuthn root key updates.
    function rotatePasskey(PasskeyData calldata newPasskey) external;

    /// @notice Register or revoke a session key.
    function setSessionKey(address sessionKey, SessionKeyPolicy calldata policy) external;
}
```

## 4. Storage Layout Plan

Because EIP-7702 executes logic directly in the EOA's context, an unstructured storage approach risks collisions. Therefore, __ERC-7201 (Namespaced Storage Layout)__ is utilized.

- __Location__: Derived from `keccak256(abi.encode(uint256(keccak256("wallet.storage.v1")) - 1))`.

- __Structure Definitions__:

  ```solidity
  struct WalletStorage {
      bool isInitialized;
      uint256 passkeyX;
      uint256 passkeyY;
      
      // Session Key mapping: Session ECDSA Public Address => Policy
      mapping(address => SessionKeyPolicy) sessionKeys;

      uint256 nonce; 
  }
  ```

## 5. Foundry Project Structure

To maintain clean separation between the 7702 singleton logic, cryptographic libraries, and session key management rules, the project directory should be structured as follows:

```text
├── lib/                        # Submodules (forge-std, solady, etc.)
├── script/                     # Foundry deployment scripts
│   ├── DeployWallet.s.sol      # Script to deploy the wallet contract
├── src/                        # Smart Contracts
│   ├── Wallet7702.sol          # Main EIP-7702 singleton instance (Fallback, ERC-4337, execute)
│   ├── Storage.sol             # ERC-7201 Namespaced Storage layout definition
│   ├── auth/                   # Cryptographic algorithms & Auth resolution
│   │   ├── Base64URL.sol       # Minimal base64url encoding for WebAuthn verification
│   │   ├── BaseWebAuthn.sol    # RIP-7212 (Primary) & Daimo/FCL (Fallback) logic
│   │   ├── FCL.sol             # Now just an interlayer for calling signature verifications (maybe later I will implement my own lib) 
|   |   ├── P256Verifier.sol    # Daimo's implementation of mathematical curve components
│   │   └── SessionManager.sol  # Logic specifically governing session keys
│   └── interfaces/
│       └── IWallet7702.sol     # The interface defined above
└── test/                       
    ├── integration/            # EIP-7702 specific delegation & execution tests
    │   ├── Wallet7702.t.sol    # Test wallet functionality end-to-end
    ├── unit/                   
    │   ├── SessionManager.t.sol# Boundary constraints and expiration tests
    │   └── WebAuthn.t.sol      # Test RIP-7212 staticcalls and mathematical fallbacks
    └── mocks/                  # Empty mock contracts for target interactions
        ├── SessionManagerMock.sol   # Mock wrapper exposing SessionManager library functions
        └── WebAuthnMock.sol         # Mock wrapper exposing BaseWebAuthn
```

## 6. Security Assumptions & Attack Vectors

These are critical invariants that have been considered:

1. __Front-running Initialization via EIP-7702:__ According to the official EIP-7702 docs, initializing the storage of the EOA cannot be magically bundled safely via initcode. To avoid an attacker delegating the code and explicitly setting *their own* passkey as the root for a victim's EOA, the `initialize()` function __strictly requires an ECDSA signature originating from the EOA's native private key__.
2. __Cross-chain & Cross-contract Replay Attacks:__ Signatures processed by the wallet (WebAuthn and Session Key) incorporate EIP-712 structured data that validates both the specific `chain.id` and the `address(this)`.
3. __Privilege Escalation (Self-Calls):__ A Session Key is explicitly restricted from calling `target == address(this)`. If a session key can call `address(this).setSessionKey(...)`, it can elevate its own privileges to an infinite limit or swap the root WebAuthn passkey.
4. __RIP-7212 Fallback Nuances:__ Calling the precompile address `0x100` via `staticcall` will silently return `success = true` with empty output (`ret.length == 0`) if the precompile doesn’t exist on that EVM chain. The code must gracefully capture `ret.length == 0` and route execution sequentially into Daimo’s `FCL_ecdsa` fallback logic without defaulting to a failed transaction.
