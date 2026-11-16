// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UsdcVault, IERC20} from "../src/UsdcVault.sol";
import {KaspaRelayV2} from "../src/KaspaRelayV2.sol";
import {RelayFactory} from "../src/RelayFactory.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {MockFiatToken} from "./MockFiatToken.sol";
import {MockVerifier} from "./MockVerifier.sol";

/// The O5 list against the v2 relay, through the factory, plus the four v2 changes: per-amount depth and
/// window, the window that never shrinks on replacement, compare-and-swap, and settlement through the vault.
contract KaspaRelayV2Test is Test {
    // settled parameters (docs/USDC-PARAMETERS.md)
    uint64 constant CAP0 = 500e6;
    uint64 constant CEILING = 50_000e6;
    uint64 constant DOUBLING = 7 days;
    uint64 constant MIN_DEPOSIT = 10e6;
    uint8 constant CMP = 30;
    uint32 constant FLOOR = 100;
    uint32 constant ATTEST_FLOOR = 100;
    uint64 constant ATTEST_UNIT = 15e6;
    uint64 constant WINDOW_FLOOR = 1800;
    uint64 constant WINDOW_UNIT = 10_000e6;

    bytes32 constant IMAGE = bytes32(uint256(0xB3B9));
    bytes32 constant INBOUND = bytes32(uint256(0x4756));
    bytes32 constant TOKEN_ID = bytes32(uint256(0x87B5));
    bytes32 constant TEMPLATE = bytes32(uint256(0xB532));
    bytes32 constant K0 = bytes32(uint256(0xD30A));
    uint64 constant K0_DAA = 566_872_866;

    MockFiatToken token;
    MockVerifier verifier;
    RelayFactory factory;
    UsdcVault vault;
    KaspaRelayV2 relay;
    address alice = address(0xA1);
    address bob = address(0xB0B);
    address honest = address(0x401);
    address attacker = address(0xBAD);

    function setUp() public {
        vm.warp(1_800_000_000);
        token = new MockFiatToken();
        verifier = new MockVerifier();
        factory = new RelayFactory(
            IRiscZeroVerifier(address(verifier)),
            IMAGE,
            INBOUND,
            IERC20(address(token)),
            CMP,
            RelayFactory.Limits({
                knownDaa: 566_000_000,
                maxCeiling: CEILING,
                maxCap0: CAP0,
                minDoubling: DOUBLING,
                minMinDeposit: MIN_DEPOSIT,
                minFloor: FLOOR,
                minAttestFloor: ATTEST_FLOOR,
                maxAttestUnit: ATTEST_UNIT,
                minWindowFloor: WINDOW_FLOOR,
                maxWindowUnit: WINDOW_UNIT
            })
        );
        (address v, address r) = factory.create(bytes32(uint256(1)), vaultParams(), relayParams());
        vault = UsdcVault(v);
        relay = KaspaRelayV2(r);
        token.mint(alice, 1_000_000e6);
        vm.prank(alice);
        token.approve(address(vault), type(uint256).max);
        // something to release
        vm.prank(alice);
        vault.deposit(500e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
    }

    function vaultParams() internal pure returns (RelayFactory.VaultParams memory) {
        return RelayFactory.VaultParams({cap0: CAP0, ceiling: CEILING, doubling: DOUBLING, minDeposit: MIN_DEPOSIT});
    }

    function relayParams() internal pure returns (KaspaRelayV2.Params memory) {
        return KaspaRelayV2.Params({
            checkpoint: K0,
            checkpointDaa: K0_DAA,
            tokenCovId: TOKEN_ID,
            templateHash: TEMPLATE,
            cmpLevel: CMP,
            floor: FLOOR,
            attestFloor: ATTEST_FLOOR,
            attestUnit: ATTEST_UNIT,
            windowFloor: WINDOW_FLOOR,
            windowUnit: WINDOW_UNIT
        });
    }

    // ------------------------------------------------------------------ journal builder (KZO3)

    struct Burn {
        bytes32 txId;
        uint64 amount;
        uint64 tip;
        address recipient;
    }

    function journal(bytes32 k, bytes32 t, uint64 tDaa, uint32 count, uint32 attesting, address target, Burn[] memory burns)
        internal
        pure
        returns (bytes memory j)
    {
        bytes memory levels = abi.encodePacked(uint8(CMP), count, attesting);
        for (uint256 i = 1; i < 8; i++) levels = abi.encodePacked(levels, uint8(0), uint32(0), uint32(0));
        j = abi.encodePacked(
            bytes4(0x4b5a4f33), k, t, tDaa, bytes32(uint256(0xB)), tDaa - 500, uint32(600), uint8(1), levels, target
        );
        j = abi.encodePacked(j, TOKEN_ID, TEMPLATE, uint8(burns.length));
        for (uint256 i = 0; i < burns.length; i++) {
            j = abi.encodePacked(j, burns[i].txId, burns[i].amount, burns[i].tip, burns[i].recipient);
        }
    }

    function one(bytes32 txId, uint64 amount, uint64 tip) internal view returns (Burn[] memory b) {
        b = new Burn[](1);
        b[0] = Burn(txId, amount, tip, bob);
    }

    /// @dev sha256 is a precompile CALL, which Foundry counts as "the next call": always compute the seal into a
    ///      variable BEFORE vm.expectRevert / vm.prank, never inline in the submit call.
    function seal(bytes memory j) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(IMAGE, sha256(j))));
    }

    function submitAs(address who, bytes memory j, bytes32 expect) internal {
        bytes memory s = seal(j);
        vm.prank(who);
        relay.submit(s, j, expect);
    }

    // ------------------------------------------------------------------ factory

    function testFactoryRecords() public view {
        assertTrue(factory.isInstance(address(relay)));
        assertTrue(factory.isInstance(address(vault)));
        assertFalse(factory.isInstance(address(this)));
        assertEq(factory.count(), 1);
        assertEq(vault.relay(), address(relay));
        assertEq(address(relay.SETTLEMENT()), address(vault));
        assertEq(relay.IMAGE_ID(), IMAGE);
        assertEq(address(relay.VERIFIER()), address(verifier));
    }

    function testFactoryPredictsAddresses() public {
        bytes32 salt = bytes32(uint256(2));
        address pv = factory.predictVault(salt, vaultParams());
        address pr = factory.predictRelay(salt, vaultParams(), relayParams());
        (address v, address r) = factory.create(salt, vaultParams(), relayParams());
        assertEq(v, pv, "vault address known before deployment");
        assertEq(r, pr);
        assertEq(factory.count(), 2);
    }

    function testFactoryRefusesWeakConstants() public {
        RelayFactory.VaultParams memory v = vaultParams();
        KaspaRelayV2.Params memory r = relayParams();
        v.ceiling = CEILING + 1;
        vm.expectRevert("factory: ceiling");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        v.doubling = 1 days;
        vm.expectRevert("factory: doubling");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        r.attestUnit = ATTEST_UNIT + 1; // weaker: more dollars per attester
        vm.expectRevert("factory: attest unit");
        factory.create(bytes32(uint256(9)), v, r);
        r = relayParams();
        r.windowFloor = 60;
        vm.expectRevert("factory: window floor");
        factory.create(bytes32(uint256(9)), v, r);
        r = relayParams();
        r.checkpointDaa = 565_000_000; // before the known block
        vm.expectRevert("factory: checkpoint");
        factory.create(bytes32(uint256(9)), v, r);
        r = relayParams();
        r.cmpLevel = 28;
        vm.expectRevert("factory: cmp level");
        factory.create(bytes32(uint256(9)), v, r);
        r = relayParams();
        r.attestUnit = 1e6; // stronger is fine
        factory.create(bytes32(uint256(9)), v, r);
    }

    // ------------------------------------------------------------------ the formulas

    function testFormulas() public view {
        assertEq(relay.requiredAttest(20e6), 100);
        assertEq(relay.requiredAttest(1_500e6), 100);
        assertEq(relay.requiredAttest(1_501e6), 101);
        assertEq(relay.requiredAttest(10_000e6), 667);
        assertEq(relay.requiredAttest(50_000e6), 3334);
        assertEq(relay.windowFor(20e6), 1800 + 7);
        assertEq(relay.windowFor(10_000e6), 5400);
        assertEq(relay.windowFor(50_000e6), 1800 + 5 * 3600);
    }

    // ------------------------------------------------------------------ journal gates (before the verifier)

    function testGates() public {
        bytes memory s;
        bytes memory j;
        j = journal(bytes32(uint256(1)), bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        s = seal(j);
        vm.expectRevert("relay: journal does not start at the checkpoint");
        relay.submit(s, j, 0);
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(0xdead), one(bytes32(uint256(1)), 100e6, 0));
        s = seal(j);
        vm.expectRevert("relay: journal target is not this relay");
        relay.submit(s, j, 0);
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        s = seal(j);
        vm.expectRevert("relay: tip is not past the checkpoint");
        relay.submit(s, j, 0);
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 99, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        s = seal(j);
        vm.expectRevert("relay: below the floor");
        relay.submit(s, j, 0);
        // the forged-B attack: honest count, attesting 0
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 4958, 0, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        vm.expectRevert("relay: not enough attestation");
        relay.submit(hex"00", j, 0);
        // $10k needs 667 attesters, not 100
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 700, 600, address(relay), one(bytes32(uint256(1)), 10_000e6, 0));
        vm.expectRevert("relay: not enough attestation");
        relay.submit(hex"00", j, 0);
        // bad seal, after the gates
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        vm.expectRevert("verifier: bad seal");
        relay.submit(hex"00", j, 0);
    }

    function testWrongTokenRefused() public {
        bytes memory s;
        Burn[] memory b = one(bytes32(uint256(1)), 100e6, 0);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), b);
        // flip one byte of the template hash (offset 245..277)
        j[250] = bytes1(uint8(j[250]) ^ 1);
        s = seal(j);
        vm.expectRevert("relay: not this token");
        relay.submit(s, j, 0);
    }

    // ------------------------------------------------------------------ a full cycle through the vault

    function testCycleSettlesThroughVault() public {
        bytes memory s;
        Burn[] memory b = one(bytes32(uint256(0x51)), 100e6, 1e6);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), b);
        submitAs(honest, j, 0);
        (bytes32 tip,,,, uint64 deadline, uint64 window,,) = relay.candidate();
        assertEq(tip, bytes32(uint256(0xA1)));
        assertEq(window, 1800 + 36);
        assertEq(deadline, block.timestamp + 1836);
        vm.expectRevert("relay: window still open");
        relay.finalize(j);
        vm.warp(deadline);
        relay.finalize(j);
        assertEq(relay.checkpoint(), bytes32(uint256(0xA1)));
        assertEq(token.balanceOf(bob), 99e6);
        assertEq(token.balanceOf(honest), 1e6);
        assertTrue(relay.settled(bytes32(uint256(0x51))));
        assertEq(vault.outstanding(), 400e6);
        // replay of the same journal: stale checkpoint
        s = seal(j);
        vm.expectRevert("relay: journal does not start at the checkpoint");
        relay.submit(s, j, 0);
    }

    function testRefusedBurnStaysClaimable() public {
        token.blacklist(bob);
        Burn[] memory b = new Burn[](2);
        b[0] = Burn(bytes32(uint256(0x61)), 50e6, 0, bob);
        b[1] = Burn(bytes32(uint256(0x62)), 50e6, 0, alice);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), b);
        submitAs(honest, j, 0);
        vm.warp(block.timestamp + 2000);
        relay.finalize(j);
        assertFalse(relay.settled(bytes32(uint256(0x61))), "bob's burn refused, unmarked");
        assertTrue(relay.settled(bytes32(uint256(0x62))), "alice's burn in the same journal settled");
        assertEq(vault.outstanding(), 450e6);
        // later journal from the new checkpoint carries bob's burn again, after Circle clears him
        token.unBlacklist(bob);
        bytes memory j2 = journal(bytes32(uint256(0xA1)), bytes32(uint256(0xA2)), K0_DAA + 2000, 300, 200, address(relay), one(bytes32(uint256(0x61)), 50e6, 0));
        submitAs(honest, j2, 0);
        vm.warp(block.timestamp + 2000);
        relay.finalize(j2);
        assertTrue(relay.settled(bytes32(uint256(0x61))));
        assertEq(token.balanceOf(bob), 50e6);
    }

    // ------------------------------------------------------------------ compare-and-swap and the race

    function testCompareAndSwap() public {
        bytes memory s;
        bytes memory a = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        bytes memory b = journal(K0, bytes32(uint256(0xB1)), K0_DAA + 1100, 310, 210, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        submitAs(honest, a, 0);
        // a robot that saw no candidate must not leapfrog
        s = seal(b);
        vm.prank(attacker);
        vm.expectRevert("relay: candidate changed");
        relay.submit(s, b, 0);
        // one that saw A may replace it
        submitAs(attacker, b, bytes32(uint256(0xA1)));
        (bytes32 tip,,,,,,,) = relay.candidate();
        assertEq(tip, bytes32(uint256(0xB1)));
    }

    function testRaceNotHeavierTieExpired() public {
        bytes memory s;
        // O5's A and B (1,274 / 1,435 counted), with attesters above the v2 floor of 100
        bytes memory a = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 1274, 171, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        bytes memory b = journal(K0, bytes32(uint256(0xB1)), K0_DAA + 1100, 1435, 195, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        submitAs(honest, a, 0);
        (,,,, uint64 d1,,,) = relay.candidate();
        vm.warp(d1 - 36);
        submitAs(attacker, b, bytes32(uint256(0xA1)));
        (,,,, uint64 d2,,,) = relay.candidate();
        assertEq(d2, block.timestamp + 1836, "window restarted");
        s = seal(a);
        vm.expectRevert("relay: not heavier than the candidate");
        relay.submit(s, a, bytes32(uint256(0xB1)));
        s = seal(b);
        vm.expectRevert("relay: not heavier than the candidate");
        relay.submit(s, b, bytes32(uint256(0xB1))); // the tie goes to the defender
        vm.warp(d2);
        vm.expectRevert("relay: finalize the expired candidate first");
        relay.submit(s, b, bytes32(uint256(0xB1)));
        relay.finalize(b);
        assertEq(relay.checkpoint(), bytes32(uint256(0xB1)));
    }

    function testReplacementNeverShortensTheWindow() public {
        // a big exit ($10k: 90 min window) is the candidate
        bytes memory big = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 700, address(relay), one(bytes32(uint256(1)), 10_000e6, 0));
        // first the vault must hold it
        vm.warp(block.timestamp + 6 * DOUBLING);
        vm.prank(alice);
        vault.deposit(10_000e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        submitAs(honest, big, 0);
        (,,,,, uint64 w1,,) = relay.candidate();
        assertEq(w1, 5400);
        // a heavier $20 journal replaces it; the window stays 90 min, not 30
        bytes memory small = journal(K0, bytes32(uint256(0xB1)), K0_DAA + 1100, 301, 200, address(relay), one(bytes32(uint256(2)), 20e6, 0));
        vm.warp(block.timestamp + 60);
        submitAs(attacker, small, bytes32(uint256(0xA1)));
        (,,,, uint64 d2, uint64 w2,,) = relay.candidate();
        assertEq(w2, 5400, "kept the longer window");
        assertEq(d2, block.timestamp + 5400);
    }

    function testVerifierDownStallsNothingElse() public {
        bytes memory s;
        verifier.setRejectAll(true);
        bytes memory a = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        s = seal(a);
        vm.expectRevert("verifier: rejected");
        relay.submit(s, a, 0);
        assertEq(relay.checkpoint(), K0);
    }

    function testSixteenBurnsSumAmount() public {
        Burn[] memory b = new Burn[](16);
        for (uint256 i = 0; i < 16; i++) b[i] = Burn(bytes32(uint256(0x100 + i)), 25e6, 0, bob);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), b);
        KaspaRelayV2.Journal memory jn = relay.parseJournal(j);
        assertEq(jn.amount, 400e6);
        assertEq(jn.nBurns, 16);
        submitAs(honest, j, 0);
        vm.warp(block.timestamp + 2000);
        relay.finalize(j);
        assertEq(token.balanceOf(bob), 400e6);
        assertEq(vault.outstanding(), 100e6);
    }
}
