// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TestToken} from "../src/TestToken.sol";
import {Vault, IERC20} from "../src/Vault.sol";

/// Deploys TestToken and Vault, approves the vault and makes the first deposit, all from
/// the broadcasting key. Four transactions. Dry run (no --broadcast) prints the gas estimate.
///
/// Env:
///   KASPA_SPK       33-byte hex (0x + 66 hex chars): version byte + 32-byte payload,
///                   from `node bin/kaspa-spk.mjs kaspa:...`
///   DEPOSIT_AMOUNT  token base units, default 1000000 (= 1.000000 KBT at 6 decimals)
contract Deploy is Script {
    uint256 constant SUPPLY = 1_000_000 * 1e6; // 1,000,000.000000 KBT

    function run() external {
        bytes memory kaspaSpk = vm.envBytes("KASPA_SPK");
        require(kaspaSpk.length == 33, "KASPA_SPK must be 33 bytes");
        uint64 amount = uint64(vm.envOr("DEPOSIT_AMOUNT", uint256(1_000_000)));

        vm.startBroadcast();
        TestToken token = new TestToken(SUPPLY);
        Vault vault = new Vault(IERC20(address(token)));
        token.approve(address(vault), amount);
        uint64 n = vault.deposit(amount, kaspaSpk);
        vm.stopBroadcast();

        console.log("TestToken  :", address(token));
        console.log("Vault      :", address(vault));
        console.log("deposit nonce :", n);
        console.log("deposit amount:", amount);
        console.logBytes(kaspaSpk);
    }
}
