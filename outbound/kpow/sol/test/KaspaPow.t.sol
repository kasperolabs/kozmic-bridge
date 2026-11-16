// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {KaspaPow} from "../src/KaspaPow.sol";

/// Checks the Solidity port against vectors produced by rusty-kaspa v2.1.0 (kpow-vectors) and prints gas per stage.
///   KPOW_VECTORS=vectors.json forge test -vv
contract KaspaPowTest is Test {
    KaspaPow k;
    string json;
    uint256 n;

    function setUp() public {
        k = new KaspaPow();
        json = vm.readFile(vm.envOr("KPOW_VECTORS", string("vectors.json")));
        n = vm.parseJsonUintArray(json, ".levels").length;
    }

    function _calldataGas(bytes memory b) internal pure returns (uint256 g) {
        for (uint256 i = 0; i < b.length; i++) g += b[i] == 0 ? 4 : 16;
    }

    /// Every stage must equal rusty-kaspa's value, for every vector.
    function test_matchesRustyKaspa() public view {
        for (uint256 i = 0; i < n; i++) _checkStages(i);
    }

    function _at(string memory key, uint256 i) internal pure returns (string memory) {
        return string.concat(".", key, "[", vm.toString(i), "]");
    }

    function _checkStages(uint256 i) internal view {
        bytes memory pre = vm.parseJsonBytes(json, _at("preimages", i));
        uint256 skip = vm.parseJsonUint(json, _at("attempts", i)) - 1;
        KaspaPow.Parsed memory p = k.parse(pre);
        assertEq(k.blake2bBlockHash(pre), vm.parseJsonBytes32(json, _at("hashes", i)), "block hash");
        bytes32 pp = k.prePowHash(pre, p);
        assertEq(pp, vm.parseJsonBytes32(json, _at("prePows", i)), "pre_pow_hash");
        bytes32 ph = k.powHash(pp, p.timestamp, p.nonce);
        assertEq(ph, vm.parseJsonBytes32(json, _at("powHashes", i)), "pow hash");
        uint256[64] memory rows = k.genMatrix(pp, skip);
        bytes memory mtx = vm.parseJsonBytes(json, _at("matrices", i));
        for (uint256 r = 0; r < 64; r++) {
            bytes32 want;
            assembly { want := mload(add(add(mtx, 32), shl(5, r))) }
            assertEq(bytes32(rows[r]), want, "matrix row");
        }
        assertTrue(k.fullRank(rows), "rank");
        _checkVerify(i, pre, skip);
    }

    function _checkVerify(uint256 i, bytes memory pre, uint256 skip) internal view {
        (bytes32 h, uint256 pow, uint256 level, bool ok) = k.verify(pre, skip, true);
        assertEq(h, vm.parseJsonBytes32(json, _at("hashes", i)), "verify hash");
        assertEq(bytes32(pow), vm.parseJsonBytes32(json, _at("pows", i)), "pow");
        assertEq(level, vm.parseJsonUint(json, _at("levels", i)), "level");
        assertEq(ok, vm.parseJsonUint(json, _at("passed", i)) == 1, "passed");
    }

    /// On real headers (PoW passes), changing one nonce bit must break the PoW.
    function test_tamperedNonceFails() public view {
        if (vm.parseJsonUint(json, _at("passed", 0)) == 0) return; // synthetic vectors: nothing to tamper
        bytes memory pre = vm.parseJsonBytes(json, _at("preimages", 0));
        KaspaPow.Parsed memory p = k.parse(pre);
        pre[p.timestampOffset + 12] ^= 0x01;
        (,,, bool ok) = k.verify(pre, 0, false);
        assertFalse(ok, "tampered header passed");
    }

    /// Gas per header. Stages are measured inside the contract; `verify` is measured as a real external call
    /// (what a relay contract would pay in execution gas); calldata and the 21000 base are added for a tx total.
    function test_gasReport() public view {
        bytes[] memory pre = vm.parseJsonBytesArray(json, ".preimages");
        uint256[] memory levels = vm.parseJsonUintArray(json, ".levels");
        uint256[] memory attempts = vm.parseJsonUintArray(json, ".attempts");
        uint256[10] memory sum;
        console2.log("  #  bytes  level |  parse   blake  prePow powHash  matrix   heavy |     rank | verify  calldata  TX TOTAL");
        for (uint256 i = 0; i < n; i++) {
            uint256[10] memory g = _measure(pre[i], attempts[i] - 1);
            for (uint256 j = 0; j < 10; j++) sum[j] += g[j];
            _row(i, pre[i].length, levels[i], g);
        }
        console2.log("averages over", n, "headers (gas)");
        console2.log("  parse              ", sum[0] / n);
        console2.log("  blake2b block hash ", sum[1] / n);
        console2.log("  blake2b pre_pow    ", sum[2] / n);
        console2.log("  pow hash (keccak-f)", sum[3] / n);
        console2.log("  matrix generation  ", sum[4] / n);
        console2.log("  heavy hash         ", sum[5] / n);
        console2.log("  rank mod p (opt.)  ", sum[6] / n);
        console2.log("  VERIFY execution   ", sum[7] / n);
        console2.log("  calldata 16/4      ", sum[8] / n);
        console2.log("  TX TOTAL, 1 header ", sum[9] / n);
    }

    function _measure(bytes memory h, uint256 skip) internal view returns (uint256[10] memory g) {
        uint256[7] memory p = k.profile(h, skip);
        for (uint256 j = 0; j < 7; j++) g[j] = p[j];
        uint256 t = gasleft();
        k.verify(h, skip, false);
        g[7] = t - gasleft();
        g[8] = _calldataGas(h);
        g[9] = 21000 + g[7] + g[8];
    }

    function _row(uint256 i, uint256 len, uint256 level, uint256[10] memory g) internal pure {
        string memory a = string.concat(_pad(vm.toString(i), 3), _pad(vm.toString(len), 7), _pad(vm.toString(level), 7), " |");
        string memory b = string.concat(_pad(vm.toString(g[0]), 7), _pad(vm.toString(g[1]), 8), _pad(vm.toString(g[2]), 8));
        string memory c = string.concat(_pad(vm.toString(g[3]), 8), _pad(vm.toString(g[4]), 8), _pad(vm.toString(g[5]), 8), " |");
        string memory d = string.concat(_pad(vm.toString(g[6]), 9), " |", _pad(vm.toString(g[7]), 7), _pad(vm.toString(g[8]), 10));
        console2.log(string.concat(a, b, c, d, _pad(vm.toString(g[9]), 10)));
    }

    function _pad(string memory s, uint256 w) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= w) return string.concat(" ", s);
        bytes memory sp = new bytes(w - b.length);
        for (uint256 i = 0; i < sp.length; i++) sp[i] = " ";
        return string.concat(string(sp), s);
    }
}
