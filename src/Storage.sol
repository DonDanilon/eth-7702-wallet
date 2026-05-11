// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWallet7702} from "./interfaces/IWallet7702.sol";

/// @title Storage - ERC-7201 Namespaced Storage Layout for EIP-7702 Wallet
/// @notice Uses ERC-7201 formula to avoid storage collisions between EOA and implementation.
///         Location: keccak256(abi.encode(uint256(keccak256("wallet.storage.v1")) - 1))
library Storage {
    /// @custom:storage-location erc7201:wallet.storage.v1
    struct WalletStorage {
        bool isInitialized;
        uint256 passkeyX;
        uint256 passkeyY;

        mapping(address => IWallet7702.SessionKeyPolicy) sessionKeys;

        uint256 nonce;
    }

    // keccak256(abi.encode(uint256(keccak256("wallet.storage.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_LOCATION = 0x1047cfd764c230cf504fc206b6c88c816c704fd66a1fc7a10c777097c7f51200;

    function _getWalletStorage() internal pure returns (WalletStorage storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
