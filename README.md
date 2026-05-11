# Project Overview

This project is a bachelor thesis: "Design and Development of an EIP-7702 User Wallet for International Financial Operations". 

A non-custodial EVM smart contract wallet utilizing **EIP-7702** to temporarily delegate standard EOAs to a fully functional smart account implementation. 

## Core Authorization Features
1. **Passkeys (WebAuthn/FIDO2):** Replaces the seed phrase. Leverages device secure modules (biometrics). Because standard `secp256r1` verification on-chain costs $\approx 330,000$ gas, we prioritize the new RIP-7212 precompile ($3,450$ gas), falling back to Daimo's FCL library otherwise.
2. **Session Keys:** Ephemeral `secp256k1` keys stored in the delegated EOA's storage. They bypass Passkey checks to allow highly scoped permissions (time limits, specific DApp targets, function selectors, or value limits) for seamless UX without repeated signing.

## Business features
1. **Batch transactions:** By bundling several related financial steps into a single array of calls, the wallet drastically cuts down on overlapping base network fees. This lowers the overhead for complex workflows, such as approving token movement and immediately forwarding that capital.
2. **Gas sponsorship:** The contract architecture and especially session keys allow wallet to be gas sponsorship-compatible.

## Architecture
The entire technical specification, including interfaces, storage layout, system flow, and security vectors, is defined in `ARCHITECTURE.md`.
