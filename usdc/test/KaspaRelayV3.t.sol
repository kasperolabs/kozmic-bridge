// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UsdcVaultV2, IERC20} from "../src/UsdcVaultV2.sol";
import {KaspaRelayV3} from "../src/KaspaRelayV3.sol";
import {RelayFactoryV2, VaultDeployerV2, RelayDeployerV3} from "../src/RelayFactoryV2.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {MockFiatToken} from "./MockFiatToken.sol";
import {MockVerifier} from "./MockVerifier.sol";

/// Tipsy.k (REHEARSAL-2-PLAN section 4): the v2 relay suite ported to v3 through the v2 factory, plus the owed path:
/// bucket refill over time, the exact BUCKET_MAX boundary, a burn of 2.5 x BUCKET_MAX in three installments, claim by
/// a stranger, claim on a fully paid burn, a blacklisted recipient owed then claimed with no re-proof, the tip paid
/// first and only once, a journal repeating an owed burn, the MAX_DEPOSIT boundary with nothing moved, sixteen burns
/// against an empty bucket, and the gas of a sixteen-burn finalize.
contract KaspaRelayV3Test is Test {
    // USDC.k #1 numbers (REHEARSAL-2-PLAN section 3)
    uint64 constant CAP0 = 500e6;
    uint64 constant CEILING = 50_000e6;
    uint64 constant DOUBLING = 7 days;
    uint64 constant MIN_DEPOSIT = 10e6;
    uint64 constant BUCKET_MAX = 10_000e6;
    uint64 constant REFILL_PER_DAY = 25_000e6;
    uint64 constant MAX_DEPOSIT = 10_000e6;
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
    RelayFactoryV2 factory;
    UsdcVaultV2 vault;
    KaspaRelayV3 relay;
    address alice = address(0xA1);
    address bob = address(0xB0B);
    address honest = address(0x401);
    address attacker = address(0xBAD);
    address stranger = address(0x5712);

    function setUp() public {
        vm.warp(1_800_000_000);
        token = new MockFiatToken();
        verifier = new MockVerifier();
        factory = new RelayFactoryV2(
            IRiscZeroVerifier(address(verifier)),
            IMAGE,
            INBOUND,
            IERC20(address(token)),
            CMP,
            RelayFactoryV2.Limits({
                knownDaa: 566_000_000,
                maxCeiling: CEILING,
                maxCap0: CAP0,
                minDoubling: DOUBLING,
                minMinDeposit: MIN_DEPOSIT,
                minFloor: FLOOR,
                minAttestFloor: ATTEST_FLOOR,
                maxAttestUnit: ATTEST_UNIT,
                minWindowFloor: WINDOW_FLOOR,
                maxWindowUnit: WINDOW_UNIT,
                maxBucketMax: BUCKET_MAX,
                maxRefillPerDay: REFILL_PER_DAY
            })
        );
        (address v, address r) = factory.create(bytes32(uint256(1)), vaultParams(), relayParams());
        vault = UsdcVaultV2(v);
        relay = KaspaRelayV3(r);
        token.mint(alice, 1_000_000e6);
        vm.prank(alice);
        token.approve(address(vault), type(uint256).max);
        // something to release
        vm.prank(alice);
        vault.deposit(500e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
    }

    function vaultParams() internal pure returns (RelayFactoryV2.VaultParams memory) {
        return RelayFactoryV2.VaultParams({
            cap0: CAP0, ceiling: CEILING, doubling: DOUBLING, minDeposit: MIN_DEPOSIT, bucketMax: BUCKET_MAX, refillPerDay: REFILL_PER_DAY, maxDeposit: MAX_DEPOSIT
        });
    }

    function relayParams() internal pure returns (KaspaRelayV3.Params memory) {
        return KaspaRelayV3.Params({
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

    /// Grow the cap (6 doublings: 32,000) and put `amount` more in the vault, so big exits have something to release.
    function fund(uint64 amount) internal {
        vm.warp(block.timestamp + 6 * DOUBLING);
        vm.prank(alice);
        vault.deposit(amount > MAX_DEPOSIT ? MAX_DEPOSIT : amount, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        for (uint64 left = amount > MAX_DEPOSIT ? amount - MAX_DEPOSIT : 0; left > 0;) {
            uint64 d = left > MAX_DEPOSIT ? MAX_DEPOSIT : left;
            vm.prank(alice);
            vault.deposit(d, abi.encodePacked(uint8(0), bytes32(uint256(1))));
            left -= d;
        }
    }

    // ------------------------------------------------------------------ journal builder (KZO3, as the v2 tests)

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
        j = abi.encodePacked(bytes4(0x4b5a4f33), k, t, tDaa, bytes32(uint256(0xB)), tDaa - 500, uint32(600), uint8(1), levels, target);
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

    /// Submit from the current checkpoint and finalize after the window; `tipHash` distinguishes journals.
    function cycle(Burn[] memory burns, uint256 tipHash) internal {
        bytes32 cp = relay.checkpoint();
        uint64 cpDaa = relay.checkpointDaa();
        uint32 attesting = relay.requiredAttest(sum(burns));
        if (attesting < 200) attesting = 200;
        bytes memory j = journal(cp, bytes32(tipHash), cpDaa + 1000, attesting + 100, attesting, address(relay), burns);
        submitAs(honest, j, 0);
        (,,,, uint64 deadline,,,) = relay.candidate();
        vm.warp(deadline);
        relay.finalize(j);
    }

    function sum(Burn[] memory b) internal pure returns (uint256 s) {
        for (uint256 i = 0; i < b.length; i++) s += b[i].amount;
    }

    /// The refill time is rounded up to the second against the spender, so a spend of x leaves the bucket within one
    /// second of refill (289,352 units) below BUCKET_MAX - x.
    function assertApprox(uint256 a, uint256 want, string memory why) internal pure {
        assertLe(a, want, why);
        assertGe(a + 300_000, want, why);
    }

    function remaining(bytes32 txId) internal view returns (uint64 r) {
        (, r,,,) = relay.owed(txId);
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
        assertEq(vault.FACTORY(), address(factory));
        assertEq(vault.BUCKET_MAX(), BUCKET_MAX);
        assertEq(vault.REFILL_PER_DAY(), REFILL_PER_DAY);
        assertEq(vault.MAX_DEPOSIT(), MAX_DEPOSIT);
        assertEq(factory.VAULT_DEPLOYER().FACTORY(), address(factory));
        assertEq(factory.RELAY_DEPLOYER().FACTORY(), address(factory));
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

    function testDeployersRefuseStrangers() public {
        // expectRevert arms the next call: read the deployers and the args first
        VaultDeployerV2 vd = factory.VAULT_DEPLOYER();
        RelayDeployerV3 rd = factory.RELAY_DEPLOYER();
        bytes memory va = factory.vaultArgs(vaultParams());
        bytes memory ra = factory.relayArgs(address(vault), relayParams());
        vm.expectRevert("deployer: not the factory");
        vd.deploy(bytes32(uint256(7)), va);
        vm.expectRevert("deployer: not the factory");
        rd.deploy(bytes32(uint256(7)), ra);
    }

    function testFactoryRefusesWeakConstants() public {
        RelayFactoryV2.VaultParams memory v = vaultParams();
        KaspaRelayV3.Params memory r = relayParams();
        v.ceiling = CEILING + 1;
        vm.expectRevert("factory: ceiling");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        v.bucketMax = BUCKET_MAX + 1;
        vm.expectRevert("factory: bucket");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        v.refillPerDay = REFILL_PER_DAY + 1;
        vm.expectRevert("factory: refill");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        v.maxDeposit = BUCKET_MAX + 1; // above the bucket: an honest deposit could not exit in one installment
        vm.expectRevert("factory: max deposit");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        v.maxDeposit = MIN_DEPOSIT - 1;
        vm.expectRevert("factory: max deposit");
        factory.create(bytes32(uint256(9)), v, r);
        v = vaultParams();
        r.attestUnit = ATTEST_UNIT + 1;
        vm.expectRevert("factory: attest unit");
        factory.create(bytes32(uint256(9)), v, r);
        r = relayParams();
        r.checkpointDaa = 565_000_000;
        vm.expectRevert("factory: checkpoint");
        factory.create(bytes32(uint256(9)), v, r);
        r = relayParams();
        v.bucketMax = 1_000e6; // a smaller bucket is stronger
        v.maxDeposit = 1_000e6;
        factory.create(bytes32(uint256(9)), v, r);
    }

    // ------------------------------------------------------------------ v2 suite, ported

    function testFormulas() public view {
        assertEq(relay.requiredAttest(20e6), 100);
        assertEq(relay.requiredAttest(1_501e6), 101);
        assertEq(relay.requiredAttest(10_000e6), 667);
        assertEq(relay.windowFor(20e6), 1800 + 7);
        assertEq(relay.windowFor(10_000e6), 5400);
    }

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
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 4958, 0, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        vm.expectRevert("relay: not enough attestation");
        relay.submit(hex"00", j, 0);
        j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        vm.expectRevert("verifier: bad seal");
        relay.submit(hex"00", j, 0);
    }

    function testWrongTokenRefused() public {
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        j[250] = bytes1(uint8(j[250]) ^ 1);
        bytes memory s = seal(j);
        vm.expectRevert("relay: not this token");
        relay.submit(s, j, 0);
    }

    function testCycleOwedAndPaidInFull() public {
        Burn[] memory b = one(bytes32(uint256(0x51)), 100e6, 1e6);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), b);
        submitAs(honest, j, 0);
        (bytes32 tip,,,, uint64 deadline, uint64 window,,) = relay.candidate();
        assertEq(tip, bytes32(uint256(0xA1)));
        assertEq(window, 1800 + 36);
        vm.expectRevert("relay: window still open");
        relay.finalize(j);
        vm.warp(deadline);
        relay.finalize(j);
        assertEq(relay.checkpoint(), bytes32(uint256(0xA1)));
        assertEq(token.balanceOf(bob), 99e6);
        assertEq(token.balanceOf(honest), 1e6);
        assertTrue(relay.settled(bytes32(uint256(0x51))));
        assertEq(remaining(bytes32(uint256(0x51))), 0);
        assertEq(vault.outstanding(), 400e6);
        assertApprox(vault.available(), BUCKET_MAX - 100e6, "the bucket paid 100");
        bytes memory s = seal(j);
        vm.expectRevert("relay: journal does not start at the checkpoint");
        relay.submit(s, j, 0);
    }

    function testCompareAndSwap() public {
        bytes memory s;
        bytes memory a = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        bytes memory b = journal(K0, bytes32(uint256(0xB1)), K0_DAA + 1100, 310, 210, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        submitAs(honest, a, 0);
        s = seal(b);
        vm.prank(attacker);
        vm.expectRevert("relay: candidate changed");
        relay.submit(s, b, 0);
        submitAs(attacker, b, bytes32(uint256(0xA1)));
        (bytes32 tip,,,,,,,) = relay.candidate();
        assertEq(tip, bytes32(uint256(0xB1)));
    }

    function testRaceNotHeavierTieExpired() public {
        bytes memory s;
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
        relay.submit(s, b, bytes32(uint256(0xB1)));
        vm.warp(d2);
        vm.expectRevert("relay: finalize the expired candidate first");
        relay.submit(s, b, bytes32(uint256(0xB1)));
        relay.finalize(b);
        assertEq(relay.checkpoint(), bytes32(uint256(0xB1)));
    }

    function testReplacementNeverShortensTheWindow() public {
        fund(10_000e6);
        bytes memory big = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 700, address(relay), one(bytes32(uint256(1)), 10_000e6, 0));
        submitAs(honest, big, 0);
        (,,,,, uint64 w1,,) = relay.candidate();
        assertEq(w1, 5400);
        bytes memory small = journal(K0, bytes32(uint256(0xB1)), K0_DAA + 1100, 301, 200, address(relay), one(bytes32(uint256(2)), 20e6, 0));
        vm.warp(block.timestamp + 60);
        submitAs(attacker, small, bytes32(uint256(0xA1)));
        (,,,, uint64 d2, uint64 w2,,) = relay.candidate();
        assertEq(w2, 5400, "kept the longer window");
        assertEq(d2, block.timestamp + 5400);
    }

    function testVerifierDownStallsNothingElse() public {
        verifier.setRejectAll(true);
        bytes memory a = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), one(bytes32(uint256(1)), 100e6, 0));
        bytes memory s = seal(a);
        vm.expectRevert("verifier: rejected");
        relay.submit(s, a, 0);
        assertEq(relay.checkpoint(), K0);
    }

    // ------------------------------------------------------------------ the bucket

    function testBucketRefillsOverTime() public {
        assertEq(vault.available(), BUCKET_MAX, "full at birth");
        fund(10_000e6);
        cycle(one(bytes32(uint256(0x70)), 10_000e6, 0), 0xA1);
        assertEq(token.balanceOf(bob), 10_000e6);
        assertEq(vault.available(), 0, "one bucket spent");
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 3600);
        // 25,000 a day is 1,041.67 an hour (the deficit is floored, the refill time was rounded up: within a few units)
        uint64 hour = REFILL_PER_DAY / 24;
        assertGe(vault.available(), hour - 1000);
        assertLe(vault.available(), hour + 1000);
        vm.warp(t0 + 0.2 days);
        assertGe(vault.available(), 5_000e6 - 1000);
        assertLe(vault.available(), 5_000e6 + 1000);
        vm.warp(t0 + 0.4 days + 1);
        assertEq(vault.available(), BUCKET_MAX, "10,000 takes 0.4 day to refill");
        vm.warp(t0 + 30 days);
        assertEq(vault.available(), BUCKET_MAX, "capped at the bucket");
    }

    function testExactBucketBoundary() public {
        fund(20_000e6);
        // exactly BUCKET_MAX: one installment
        cycle(one(bytes32(uint256(0x71)), BUCKET_MAX, 0), 0xA1);
        assertEq(remaining(bytes32(uint256(0x71))), 0);
        assertTrue(relay.settled(bytes32(uint256(0x71))));
        // BUCKET_MAX + 1 against a bucket that has refilled for a day: 1 unit stays owed
        vm.warp(block.timestamp + 1 days);
        cycle(one(bytes32(uint256(0x72)), BUCKET_MAX + 1, 0), 0xA2);
        assertEq(remaining(bytes32(uint256(0x72))), 1);
        assertFalse(relay.settled(bytes32(uint256(0x72))));
        assertEq(token.balanceOf(bob), 2 * BUCKET_MAX);
        vm.warp(block.timestamp + 60);
        relay.claim(bytes32(uint256(0x72)));
        assertEq(remaining(bytes32(uint256(0x72))), 0);
        assertEq(token.balanceOf(bob), 2 * BUCKET_MAX + 1);
    }

    function testBigBurnPaidInThreeInstallments() public {
        fund(25_000e6);
        uint64 big = 25_000e6; // 2.5 x BUCKET_MAX, but journal amounts are a single uint64 and requiredAttest grows: 1667
        cycle(one(bytes32(uint256(0x73)), big, 0), 0xA1);
        assertEq(token.balanceOf(bob), BUCKET_MAX, "first installment at finalize");
        assertEq(remaining(bytes32(uint256(0x73))), big - BUCKET_MAX);
        // a claim in the same second pays nothing (bucket empty), the burn stays owed
        uint64 paid = relay.claim(bytes32(uint256(0x73)));
        assertEq(paid, 0);
        // 0.4 day refills 10,000: second installment
        vm.warp(block.timestamp + 0.4 days + 5);
        paid = relay.claim(bytes32(uint256(0x73)));
        assertEq(paid, BUCKET_MAX);
        assertEq(remaining(bytes32(uint256(0x73))), 5_000e6);
        // 0.2 day refills 5,000: third installment, paid in full
        vm.warp(block.timestamp + 0.2 days + 5);
        paid = relay.claim(bytes32(uint256(0x73)));
        assertEq(paid, 5_000e6);
        assertEq(remaining(bytes32(uint256(0x73))), 0);
        assertTrue(relay.settled(bytes32(uint256(0x73))));
        assertEq(token.balanceOf(bob), big);
        assertEq(vault.outstanding(), 500e6, "only the setUp deposit is left");
    }

    function testClaimByStrangerAndOnPaidBurn() public {
        fund(15_000e6);
        cycle(one(bytes32(uint256(0x74)), 15_000e6, 0), 0xA1);
        assertEq(remaining(bytes32(uint256(0x74))), 5_000e6);
        vm.warp(block.timestamp + 0.2 days + 5);
        vm.prank(stranger);
        uint64 paid = relay.claim(bytes32(uint256(0x74)));
        assertEq(paid, 5_000e6, "anyone may pay the next installment");
        assertEq(token.balanceOf(stranger), 0, "and gets nothing for it");
        // claim on a fully paid burn: a no-op
        vm.prank(stranger);
        assertEq(relay.claim(bytes32(uint256(0x74))), 0);
        assertEq(token.balanceOf(bob), 15_000e6);
        // claim on a burn that was never proven: reverts
        vm.expectRevert("relay: not an owed burn");
        relay.claim(bytes32(uint256(0x7777)));
    }

    function testBlacklistedRecipientOwedThenClaimedWithoutReproof() public {
        token.blacklist(bob);
        Burn[] memory b = new Burn[](2);
        b[0] = Burn(bytes32(uint256(0x61)), 50e6, 0, bob);
        b[1] = Burn(bytes32(uint256(0x62)), 50e6, 0, alice);
        cycle(b, 0xA1);
        assertFalse(relay.settled(bytes32(uint256(0x61))), "bob's burn owed, unpaid");
        assertEq(remaining(bytes32(uint256(0x61))), 50e6);
        assertTrue(relay.settled(bytes32(uint256(0x62))), "alice's burn in the same journal paid");
        assertEq(vault.outstanding(), 450e6, "the refused installment did not touch outstanding");
        assertApprox(vault.available(), BUCKET_MAX - 50e6, "nor the bucket");
        // still blacklisted: claim pays nothing
        assertEq(relay.claim(bytes32(uint256(0x61))), 0);
        // Circle clears bob: anyone claims, no second proof, no new journal
        token.unBlacklist(bob);
        vm.prank(stranger);
        assertEq(relay.claim(bytes32(uint256(0x61))), 50e6);
        assertTrue(relay.settled(bytes32(uint256(0x61))));
        assertEq(token.balanceOf(bob), 50e6);
        assertEq(vault.outstanding(), 400e6);
    }

    function testTipPaidFirstAndOnce() public {
        fund(15_000e6);
        // 15,000 with a 100 tip: the first installment (10,000) carries the whole tip; the second carries none
        cycle(one(bytes32(uint256(0x75)), 15_000e6, 100e6), 0xA1);
        assertEq(token.balanceOf(honest), 100e6, "tip paid with the first installment");
        assertEq(token.balanceOf(bob), 9_900e6);
        (, uint64 rem, uint64 tipRem, address sub,) = relay.owed(bytes32(uint256(0x75)));
        assertEq(rem, 5_000e6);
        assertEq(tipRem, 0);
        assertEq(sub, honest);
        vm.warp(block.timestamp + 0.2 days + 5);
        relay.claim(bytes32(uint256(0x75)));
        assertEq(token.balanceOf(honest), 100e6, "no second tip");
        assertEq(token.balanceOf(bob), 14_900e6);
    }

    function testRepeatedBurnIsRecordedOnce() public {
        fund(15_000e6);
        cycle(one(bytes32(uint256(0x76)), 15_000e6, 0), 0xA1);
        assertEq(remaining(bytes32(uint256(0x76))), 5_000e6);
        uint256 bobBefore = token.balanceOf(bob);
        // a later journal carries the same burn again (the old re-proof path): skipped, nothing changes
        vm.warp(block.timestamp + 1 days);
        cycle(one(bytes32(uint256(0x76)), 15_000e6, 0), 0xA2);
        assertEq(remaining(bytes32(uint256(0x76))), 5_000e6, "not re-recorded, not paid by the repeat");
        assertEq(token.balanceOf(bob), bobBefore);
        // the owed record is paid by claim, as before
        relay.claim(bytes32(uint256(0x76)));
        assertEq(remaining(bytes32(uint256(0x76))), 0);
    }

    function testMaxDepositBoundary() public {
        vm.warp(block.timestamp + 6 * DOUBLING);
        uint256 aliceBefore = token.balanceOf(alice);
        vm.prank(alice);
        vault.deposit(MAX_DEPOSIT, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        assertEq(token.balanceOf(alice), aliceBefore - MAX_DEPOSIT);
        vm.prank(alice);
        vm.expectRevert("vault: above the maximum deposit");
        vault.deposit(MAX_DEPOSIT + 1, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        assertEq(token.balanceOf(alice), aliceBefore - MAX_DEPOSIT, "nothing moved on the revert");
        assertEq(vault.nonce(), 2);
    }

    function testSixteenBurnsAgainstAnEmptyBucket() public {
        fund(11_600e6);
        cycle(one(bytes32(uint256(0x77)), 10_000e6, 0), 0xA1);
        assertEq(vault.available(), 0, "emptied");
        // sixteen burns of 100 finalize ~40 min later (their window), when the bucket has refilled about 690:
        // the first six are paid, the seventh in part, the rest wait; every claim pays once the bucket is back
        Burn[] memory b = new Burn[](16);
        for (uint256 i = 0; i < 16; i++) b[i] = Burn(bytes32(uint256(0x100 + i)), 100e6, 0, bob);
        uint256 bobBefore = token.balanceOf(bob);
        cycle(b, 0xA2);
        uint256 paidAtFinalize = token.balanceOf(bob) - bobBefore;
        assertGt(paidAtFinalize, 0, "whatever had refilled was paid");
        assertLt(paidAtFinalize, 1_600e6, "not all of it");
        uint256 owedSum;
        uint256 unpaid;
        for (uint256 i = 0; i < 16; i++) {
            uint64 r = remaining(bytes32(uint256(0x100 + i)));
            owedSum += r;
            if (r == 100e6) unpaid++;
        }
        assertEq(owedSum + paidAtFinalize, 1_600e6, "paid plus owed is the journal");
        assertGe(unpaid, 9, "most of them wait");
        assertEq(vault.available(), 0, "the bucket is empty again");
        vm.warp(block.timestamp + 1 days);
        for (uint256 i = 0; i < 16; i++) relay.claim(bytes32(uint256(0x100 + i)));
        assertEq(token.balanceOf(bob), bobBefore + 1_600e6, "every burn paid in full by claims");
        for (uint256 i = 0; i < 16; i++) assertTrue(relay.settled(bytes32(uint256(0x100 + i))));
    }

    function testFinalizeGasWithSixteenOwedBurns() public {
        fund(400e6);
        Burn[] memory b = new Burn[](16);
        for (uint256 i = 0; i < 16; i++) b[i] = Burn(bytes32(uint256(0x200 + i)), 25e6, 1e6, bob);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, address(relay), b);
        submitAs(honest, j, 0);
        (,,,, uint64 deadline,,,) = relay.candidate();
        vm.warp(deadline);
        uint256 g0 = gasleft();
        relay.finalize(j);
        uint256 used = g0 - gasleft();
        emit log_named_uint("finalize with 16 owed burns, all paid: gas", used);
        assertLt(used, 6_000_000, "well under the block limit");
        assertEq(token.balanceOf(bob), 16 * 24e6);
        assertEq(token.balanceOf(honest), 16e6);
    }

    /// A forged journal (the only way a burn can exceed what the vault holds) is recorded for at most the vault's
    /// present backing minus what is already owed: it can drain what is there, never a deposit made after it.
    function testOwedIsCappedAtOutstanding() public {
        // the vault holds 500; a journal claims 50,000 for an attacker, then another 10 for bob
        Burn[] memory b = new Burn[](2);
        b[0] = Burn(bytes32(uint256(0x90)), 50_000e6, 0, attacker);
        b[1] = Burn(bytes32(uint256(0x91)), 10e6, 0, bob);
        cycle(b, 0xA1);
        (, uint64 rem0,,,) = relay.owed(bytes32(uint256(0x90)));
        (, uint64 rem1,,,) = relay.owed(bytes32(uint256(0x91)));
        assertEq(token.balanceOf(attacker), 500e6, "the attacker got what was there");
        assertEq(rem0, 0, "and is owed nothing more: recorded for 500, not 50,000");
        assertEq(rem1, 0, "bob's burn was recorded for 0 (no room) and closed");
        assertTrue(relay.settled(bytes32(uint256(0x91))));
        assertEq(relay.owedTotal(), 0);
        assertEq(vault.outstanding(), 0);
        // a deposit after the forgery is not reachable by it
        vm.warp(block.timestamp + 6 * DOUBLING);
        vm.prank(alice);
        vault.deposit(1_000e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        assertEq(relay.claim(bytes32(uint256(0x90))), 0, "nothing more to claim");
        assertEq(token.balanceOf(attacker), 500e6);
        assertEq(vault.outstanding(), 1_000e6);
        // honest burns never meet the cap: 1,000 outstanding, two burns of 500 are recorded in full
        Burn[] memory h = new Burn[](2);
        h[0] = Burn(bytes32(uint256(0x92)), 500e6, 0, bob);
        h[1] = Burn(bytes32(uint256(0x93)), 500e6, 0, bob);
        cycle(h, 0xA2);
        assertEq(token.balanceOf(bob), 1_000e6);
        assertEq(relay.owedTotal(), 0);
    }

    function testOwedTotalTracksInstallments() public {
        fund(15_000e6);
        cycle(one(bytes32(uint256(0x94)), 15_000e6, 0), 0xA1);
        assertEq(relay.owedTotal(), 5_000e6, "what is still to be paid");
        vm.warp(block.timestamp + 0.2 days + 5);
        relay.claim(bytes32(uint256(0x94)));
        assertEq(relay.owedTotal(), 0);
    }

    // ------------------------------------------------------------------ mainnet fork: the owed path through the relay

    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    /// Circle's real token and blacklister (run with ETH_RPC_URL set; skipped otherwise): a burn to a blacklisted
    /// recipient is owed at finalize (Deferred), paid by a stranger's claim after the unblacklist, no second proof.
    function testForkOwedPathThroughRelay() public {
        string memory rpc = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        vm.warp(block.timestamp + 1);
        MockVerifier v2 = new MockVerifier();
        RelayFactoryV2 f = new RelayFactoryV2(
            IRiscZeroVerifier(address(v2)), IMAGE, INBOUND, IERC20(USDC), CMP,
            RelayFactoryV2.Limits({
                knownDaa: 566_000_000, maxCeiling: CEILING, maxCap0: CAP0, minDoubling: DOUBLING, minMinDeposit: MIN_DEPOSIT, minFloor: FLOOR,
                minAttestFloor: ATTEST_FLOOR, maxAttestUnit: ATTEST_UNIT, minWindowFloor: WINDOW_FLOOR, maxWindowUnit: WINDOW_UNIT,
                maxBucketMax: BUCKET_MAX, maxRefillPerDay: REFILL_PER_DAY
            })
        );
        (address va, address ra) = f.create(bytes32(uint256(3)), vaultParams(), relayParams());
        UsdcVaultV2 fv = UsdcVaultV2(va);
        KaspaRelayV3 fr = KaspaRelayV3(ra);
        deal(USDC, alice, 1_000e6);
        vm.prank(alice);
        (bool ok,) = USDC.call(abi.encodeWithSignature("approve(address,uint256)", va, type(uint256).max));
        assertTrue(ok);
        vm.prank(alice);
        fv.deposit(200e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        (, bytes memory ret) = USDC.staticcall(abi.encodeWithSignature("blacklister()"));
        address blacklister = abi.decode(ret, (address));
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("blacklist(address)", bob));
        assertTrue(ok);
        // the journal: one burn of 50 with a 1 tip to bob (blacklisted), one of 20 to alice
        Burn[] memory b = new Burn[](2);
        b[0] = Burn(bytes32(uint256(0x61)), 50e6, 1e6, bob);
        b[1] = Burn(bytes32(uint256(0x62)), 20e6, 0, alice);
        bytes memory j = journal(K0, bytes32(uint256(0xA1)), K0_DAA + 1000, 300, 200, ra, b);
        bytes memory sl = seal(j);
        vm.prank(honest);
        fr.submit(sl, j, 0);
        (,,,, uint64 deadline,,,) = fr.candidate();
        vm.warp(deadline);
        fr.finalize(j);
        (, uint64 rem,,,) = fr.owed(bytes32(uint256(0x61)));
        assertEq(rem, 50e6, "bob's burn owed in full: the real USDC refused him");
        assertTrue(fr.settled(bytes32(uint256(0x62))), "alice's paid");
        assertEq(fv.outstanding(), 180e6);
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", honest));
        assertEq(abi.decode(ret, (uint256)), 0, "no tip before the recipient is paid");
        vm.prank(stranger);
        assertEq(fr.claim(bytes32(uint256(0x61))), 0, "still blacklisted");
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("unBlacklist(address)", bob));
        assertTrue(ok);
        vm.prank(stranger);
        assertEq(fr.claim(bytes32(uint256(0x61))), 50e6, "paid by a stranger's claim, no second proof");
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", bob));
        assertEq(abi.decode(ret, (uint256)), 49e6);
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", honest));
        assertEq(abi.decode(ret, (uint256)), 1e6, "the tip, once");
        assertTrue(fr.settled(bytes32(uint256(0x61))));
        assertEq(fv.outstanding(), 130e6);
    }

    function testReleaseOnlyByTheRelay() public {
        vm.expectRevert("vault: not the relay");
        vault.release(bytes32(uint256(1)), bob, 1e6, 0, honest);
        vm.prank(attacker);
        vm.expectRevert("vault: not the relay");
        vault.release(bytes32(uint256(1)), attacker, 500e6, 0, attacker);
    }
}
