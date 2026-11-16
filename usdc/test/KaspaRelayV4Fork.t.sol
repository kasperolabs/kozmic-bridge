// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {KaspaRelayV4} from "../src/KaspaRelayV4.sol";
import {ISettlementV3} from "../src/ISettlementV3.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";

/// @notice The beacon check against a real Ethereum network: the real EIP-2935 contract and a real header, as
///         `cast block N --raw` prints it. Skips itself unless BEACON_RPC_URL is set. Env:
///           BEACON_RPC_URL  the network's RPC (never committed)
///           BEACON_NUMBER, BEACON_HASH, BEACON_TIME  the block (from `cast block N --field ...`)
///           BEACON_RLP      its header RLP (`cast block N --raw`)
contract KaspaRelayV4ForkTest is Test {
    function test_real_beacon_header_and_history() public {
        string memory url = vm.envOr("BEACON_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        KaspaRelayV4 relay = new KaspaRelayV4(
            IRiscZeroVerifier(address(1)),
            bytes32(uint256(1)),
            ISettlementV3(address(1)),
            KaspaRelayV4.Params({
                checkpoint: bytes32(uint256(1)),
                checkpointDaa: 1,
                checkpointBlueWork: 1,
                tokenCovId: bytes32(uint256(1)),
                templateHash: bytes32(uint256(1)),
                cmpLevel: 30,
                floor: 300,
                alphaBps: 5_000,
                betaBps: 8_000,
                slowSpanDaa: 864_000,
                rate0: 1,
                attestUnit: 0,
                minBurn: 1,
                minInstallment: 1
            })
        );
        bytes memory rlp = vm.envBytes("BEACON_RLP");
        uint64 n = uint64(vm.envUint("BEACON_NUMBER"));
        bytes32 h = vm.envBytes32("BEACON_HASH");
        (uint256 hn, uint256 hts) = relay.headerNumberAndTime(rlp);
        emit log_named_uint("header bytes", rlp.length);
        emit log_named_uint("header number", hn);
        emit log_named_uint("header time", hts);
        assertEq(hn, n, "number field");
        assertEq(hts, vm.envUint("BEACON_TIME"), "timestamp field");
        assertEq(keccak256(rlp), h, "keccak of the RLP is the block hash");
        uint256 ts = relay.beaconTime(n, h, rlp);
        assertEq(ts, hts, "beaconTime through the real EIP-2935 contract");
        uint256 g = gasleft();
        relay.beaconTime(n, h, rlp);
        emit log_named_uint("beaconTime gas", g - gasleft());
    }
}
