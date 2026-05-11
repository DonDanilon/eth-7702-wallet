// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {Wallet7702} from "../src/Wallet7702.sol";

/// @title DeployWallet - deploy EIP-7702 Wallet7702 Singleton
/// @notice Two-phase deployment:
///         deploy the Wallet7702 singleton -> broadcast the type-4 set-code transaction.
contract DeployWallet is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPk);

        Wallet7702 walletImpl = new Wallet7702();

        vm.stopBroadcast();

        address deployedAddr = address(walletImpl);

        console2.log("");
        console2.log("======================================================");
        console2.log("EIP-7702 DEPLOYMENT COMPLETE");
        console2.log("======================================================");
        console2.log("Wallet7702 singleton deployed at:", vm.toString(deployedAddr));
        console2.log("");
    }
}
