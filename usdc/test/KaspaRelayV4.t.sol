// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {KaspaRelayV4} from "../src/KaspaRelayV4.sol";
import {UsdcVaultV3, IERC20} from "../src/UsdcVaultV3.sol";
import {ISettlementV3} from "../src/ISettlementV3.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {MockVerifier} from "./MockVerifier.sol";
import {MockFiatToken} from "./MockFiatToken.sol";

/// @notice EIP-2935 stand-in: answers the hashes a test sets, reverts for any other number (as the real one does
///         outside its window). Its code is etched at the HISTORY address; its storage lives there.
contract MockHistory {
    mapping(uint256 => bytes32) public h;

    function set(uint256 n, bytes32 x) external {
        h[n] = x;
    }

    fallback(bytes calldata d) external returns (bytes memory) {
        uint256 n = abi.decode(d, (uint256));
        bytes32 x = h[n];
        require(x != bytes32(0), "out of window");
        return abi.encode(x);
    }
}

/// @notice A token whose transfer calls back into the relay once (a hostile upgrade of the token, F7).
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    KaspaRelayV4 public relay;
    bytes32 public hookTx;
    bool public reentered;
    bool public reentryReverted;

    function setHook(KaspaRelayV4 r, bytes32 tx_) external {
        relay = r;
        hookTx = tx_;
    }

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }

    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a;
        balanceOf[f] -= a;
        balanceOf[t] += a;
        return true;
    }

    function transfer(address t, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[t] += a;
        if (address(relay) != address(0) && !reentered) {
            reentered = true;
            try relay.claim(hookTx) {} catch {
                reentryReverted = true;
            }
        }
        return true;
    }
}

contract KaspaRelayV4Test is Test {
    address constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    bytes32 constant IMAGE = bytes32(uint256(0x68f8b1cb));
    bytes32 constant TOKEN_ID = bytes32(uint256(0x13af6019));
    bytes32 constant TEMPLATE = 0x9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7;
    // measured mean hashrate 3.567e17 H/s at 10 BPS (V4-DESIGN 2.8): 9.28 level-30 superblocks a minute
    uint32 constant BITS = 0x1a020526;
    uint256 constant RATE0 = 35670114682903884;
    uint64 constant DAY_DAA = 864_000;
    uint64 constant USD = 1e6;

    MockVerifier verifier;
    MockFiatToken usdc;
    UsdcVaultV3 vault;
    KaspaRelayV4 relay;
    MockHistory hist;

    bytes32 constant K0 = bytes32(uint256(0xc0));
    uint64 constant K0_DAA = 583_741_202;
    uint192 constant K0_BW = uint192(1e30);

    address alice = address(0xA11CE);
    address robot = address(0xB0B);

    function setUp() public {
        vm.warp(1_793_800_000);
        vm.roll(12_063_000);
        verifier = new MockVerifier();
        usdc = new MockFiatToken();
        vault = new UsdcVaultV3(IERC20(address(usdc)), address(this), 5_000 * USD, 50_000 * USD, 7 days, 10 * USD, 10_000 * USD, 25_000 * USD, 10_000 * USD);
        relay = _relay(ISettlementV3(address(vault)), 0);
        vault.setRelay(address(relay));
        MockHistory impl = new MockHistory();
        vm.etch(HISTORY, address(impl).code);
        hist = MockHistory(HISTORY);
        // a depositor fills the vault to 5,000
        usdc.mint(alice, 100_000 * USD);
        vm.startPrank(alice);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(5_000 * USD, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.stopPrank();
    }

    function _relay(ISettlementV3 s, uint64 attestUnit) internal returns (KaspaRelayV4) {
        return new KaspaRelayV4(
            IRiscZeroVerifier(address(verifier)),
            IMAGE,
            s,
            KaspaRelayV4.Params({
                checkpoint: K0,
                checkpointDaa: K0_DAA,
                checkpointBlueWork: K0_BW,
                tokenCovId: TOKEN_ID,
                templateHash: TEMPLATE,
                cmpLevel: 30,
                floor: 300,
                alphaBps: 5_000,
                betaBps: 8_000,
                slowSpanDaa: DAY_DAA,
                rate0: RATE0,
                attestUnit: attestUnit,
                minBurn: 10 * USD,
                minInstallment: 1 * USD
            })
        );
    }

    // ------------------------------------------------------------------ RLP helpers

    function _rlpBytes(bytes memory b) internal pure returns (bytes memory) {
        if (b.length == 1 && uint8(b[0]) < 0x80) return b;
        if (b.length <= 55) return abi.encodePacked(uint8(0x80 + b.length), b);
        bytes memory l = _beMin(b.length);
        return abi.encodePacked(uint8(0xb7 + l.length), l, b);
    }

    function _beMin(uint256 v) internal pure returns (bytes memory out) {
        if (v == 0) return "";
        uint256 n;
        for (uint256 x = v; x != 0; x >>= 8) n++;
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) out[n - 1 - i] = bytes1(uint8(v >> (8 * i)));
    }

    function _rlpUint(uint256 v) internal pure returns (bytes memory) {
        return _rlpBytes(_beMin(v));
    }

    function _rlpList(bytes memory payload) internal pure returns (bytes memory) {
        if (payload.length <= 55) return abi.encodePacked(uint8(0xc0 + payload.length), payload);
        bytes memory l = _beMin(payload.length);
        return abi.encodePacked(uint8(0xf7 + l.length), l, payload);
    }

    /// A post-Prague-shaped execution header (21 fields) with the given number and timestamp.
    function _header(uint256 number, uint256 ts) internal pure returns (bytes memory) {
        bytes memory p = abi.encodePacked(_rlpBytes(abi.encodePacked(bytes32(uint256(1)))), _rlpBytes(abi.encodePacked(bytes32(uint256(2)))));
        p = abi.encodePacked(p, _rlpBytes(abi.encodePacked(bytes20(uint160(3)))), _rlpBytes(abi.encodePacked(bytes32(uint256(4)))));
        p = abi.encodePacked(p, _rlpBytes(abi.encodePacked(bytes32(uint256(5)))), _rlpBytes(abi.encodePacked(bytes32(uint256(6)))));
        p = abi.encodePacked(p, _rlpBytes(new bytes(256)), _rlpUint(0), _rlpUint(number));
        p = abi.encodePacked(p, _rlpUint(30_000_000), _rlpUint(12_345_678), _rlpUint(ts));
        p = abi.encodePacked(p, _rlpBytes(""), _rlpBytes(abi.encodePacked(bytes32(uint256(7)))), _rlpBytes(abi.encodePacked(bytes8(0))));
        p = abi.encodePacked(p, _rlpUint(7), _rlpBytes(abi.encodePacked(bytes32(uint256(8)))), _rlpUint(0), _rlpUint(0));
        p = abi.encodePacked(p, _rlpBytes(abi.encodePacked(bytes32(uint256(9)))), _rlpBytes(abi.encodePacked(bytes32(uint256(10)))));
        return _rlpList(p);
    }

    /// A beacon block `ageSec` seconds old, known to the history contract; returns (number, hash, rlp).
    function _beacon(uint256 ageSec) internal returns (uint64 n, bytes32 h, bytes memory rlp) {
        n = uint64(block.number - 1 - ageSec / 12);
        rlp = _header(n, block.timestamp - ageSec);
        h = keccak256(rlp);
        hist.set(n, h);
    }

    // ------------------------------------------------------------------ journal builder

    struct Burn {
        bytes32 txId;
        uint64 amount;
        uint64 tip;
        address recipient;
    }

    struct J {
        bytes32 k;
        uint64 kDaa;
        uint32 kBits;
        uint192 kBw;
        bytes32 t;
        uint64 tDaa;
        uint32 count;
        uint32 attesting;
        address target;
        uint64 anchorN;
        bytes32 anchorH;
        Burn[] burns;
    }

    function _journal(J memory j) internal pure returns (bytes memory out) {
        out = abi.encodePacked(bytes4("KZO4"), j.k, j.kDaa, j.kBits);
        out = abi.encodePacked(out, bytes24(j.kBw), j.t, j.tDaa);
        out = abi.encodePacked(out, bytes32(uint256(0xbb)), uint64(j.kDaa + 1), uint32(1500));
        out = abi.encodePacked(out, uint8(1), uint8(30), j.count, j.attesting);
        for (uint256 i = 1; i < 8; i++) out = abi.encodePacked(out, uint8(0), uint32(0), uint32(0));
        out = abi.encodePacked(out, bytes20(j.target), TOKEN_ID, TEMPLATE);
        out = abi.encodePacked(out, j.anchorN, j.anchorH, uint8(j.burns.length));
        for (uint256 i = 0; i < j.burns.length; i++) {
            Burn memory b = j.burns[i];
            out = abi.encodePacked(out, b.txId, b.amount, b.tip, bytes20(b.recipient));
        }
    }

    function _one(bytes32 txId, uint64 amount, uint64 tip, address to) internal pure returns (Burn[] memory b) {
        b = new Burn[](1);
        b[0] = Burn(txId, amount, tip, to);
    }

    /// An honest round from the current checkpoint: beacon `ageSec` old, `attesting` superblocks.
    function _round(uint256 ageSec, uint32 attesting, Burn[] memory burns) internal returns (bytes memory jn, bytes memory rlp, bytes memory seal) {
        (uint64 n, bytes32 h, bytes memory r) = _beacon(ageSec);
        J memory j;
        j.k = relay.checkpoint();
        j.kDaa = relay.checkpointDaa();
        j.kBits = BITS;
        j.kBw = _bwAt(j.kDaa);
        j.t = keccak256(abi.encode(j.k, "T"));
        j.tDaa = j.kDaa + 108_000; // 3 h
        j.count = 1700;
        j.attesting = attesting;
        j.target = address(relay);
        j.anchorN = n;
        j.anchorH = h;
        j.burns = burns;
        jn = _journal(j);
        rlp = r;
        seal = verifier.sealFor(IMAGE, sha256(jn));
    }

    /// Blue work along an honest chain at RATE0 hashes per DAA unit.
    function _bwAt(uint64 daa) internal pure returns (uint192) {
        return K0_BW + uint192(uint256(daa - K0_DAA) * RATE0);
    }

    // ------------------------------------------------------------------ the rule

    function test_requirement_matches_the_measured_rate() public view {
        // alpha 0.5, measured difficulty: 9.28 level-30 a minute, 4.64 at half: the floor F = 300 binds for the first
        // ~65 min after the beacon, then the rate term (557 at 2 h, 1,114 at 4 h)
        assertEq(relay.requiredAttest(1800, BITS, K0_DAA, K0_BW, 0), 300);
        assertEq(relay.requiredAttest(3600, BITS, K0_DAA, K0_BW, 0), 300);
        assertEq(relay.requiredAttest(3900, BITS, K0_DAA, K0_BW, 0), 302);
        assertEq(relay.requiredAttest(7200, BITS, K0_DAA, K0_BW, 0), 557);
        assertEq(relay.requiredAttest(14400, BITS, K0_DAA, K0_BW, 0), 1114);
    }

    function test_honest_round_settles_in_one_transaction() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 1 * USD, alice));
        bytes32 t = keccak256(abi.encode(K0, "T"));
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        assertEq(relay.checkpoint(), t);
        assertTrue(relay.settled(bytes32("tx1")));
        assertEq(usdc.balanceOf(robot), 1 * USD, "tip to the submitter");
        assertEq(vault.outstanding(), 4_900 * USD);
    }

    function test_too_few_attesters_for_the_beacon_age() public {
        // 4 h since the beacon needs 1,114 at alpha 0.5; 1,000 is not enough
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(4 hours, 1000, _one(bytes32("tx1"), 100 * USD, 0, alice));
        vm.expectRevert("relay: not enough attestation for the time since the beacon");
        relay.submit(seal, jn, rlp);
    }

    function test_borrowed_count_does_not_help() public {
        // the O5 forged ladder: thousands counted, 0 attesting
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(600, 0, _one(bytes32("tx1"), 100 * USD, 0, alice));
        vm.expectRevert("relay: not enough attestation for the time since the beacon");
        relay.submit(seal, jn, rlp);
    }

    function test_beacon_checks() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        // a header that is not the beacon block
        bytes memory other = _header(1, block.timestamp);
        vm.expectRevert("relay: header is not the beacon block");
        relay.submit(seal, jn, other);
        // Ethereum no longer (or never) knows the beacon number
        (uint64 n,,) = _beacon(3600);
        hist.set(n, bytes32(0));
        vm.expectRevert("relay: beacon block outside Ethereum's history window");
        relay.submit(seal, jn, rlp);
        // Ethereum has another block at that number (a forked beacon)
        hist.set(n, bytes32(uint256(0xdead)));
        vm.expectRevert("relay: beacon is not Ethereum's block at that number");
        relay.submit(seal, jn, rlp);
    }

    function test_header_number_must_match() public {
        // a real header of another number whose hash the forger registers under the anchor number
        bytes memory rlp = _header(5, block.timestamp - 60);
        uint64 n = uint64(block.number - 10);
        hist.set(n, keccak256(rlp));
        J memory j;
        j.k = K0;
        j.kDaa = K0_DAA;
        j.kBits = BITS;
        j.kBw = K0_BW;
        j.t = bytes32("T");
        j.tDaa = K0_DAA + 1000;
        j.count = 1000;
        j.attesting = 1000;
        j.target = address(relay);
        j.anchorN = n;
        j.anchorH = keccak256(rlp);
        j.burns = _one(bytes32("tx1"), 100 * USD, 0, alice);
        bytes memory jn = _journal(j);
        bytes memory seal = verifier.sealFor(IMAGE, sha256(jn));
        vm.expectRevert("relay: header number differs from the beacon");
        relay.submit(seal, jn, rlp);
    }

    function test_rlp_reader() public view {
        bytes memory h = _header(12_062_939, 1_793_801_616);
        (uint256 n, uint256 ts) = relay.headerNumberAndTime(h);
        assertEq(n, 12_062_939);
        assertEq(ts, 1_793_801_616);
    }

    function test_rlp_reader_refuses_malformed() public {
        bytes memory h = _header(12_062_939, 1_793_801_616);
        bytes memory trailing = abi.encodePacked(h, uint8(0));
        vm.expectRevert("relay: header length");
        relay.headerNumberAndTime(trailing);
        bytes memory shortList = _rlpList(abi.encodePacked(_rlpUint(1), _rlpUint(2)));
        vm.expectRevert("relay: header has too few fields");
        relay.headerNumberAndTime(shortList);
    }

    function test_second_robot_on_the_same_checkpoint_reverts_cheaply() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        vm.expectRevert("relay: journal does not start at the checkpoint");
        relay.submit(seal, jn, rlp);
    }

    function test_journal_k_daa_must_match() public {
        (bytes memory jn, bytes memory rlp,) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        jn[43] = bytes1(uint8(jn[43]) ^ 1); // K.daa
        bytes memory seal = verifier.sealFor(IMAGE, sha256(jn));
        vm.expectRevert("relay: journal does not start at the checkpoint");
        relay.submit(seal, jn, rlp);
    }

    function test_forged_seal_refused() public {
        (bytes memory jn, bytes memory rlp,) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        vm.expectRevert("verifier: bad seal");
        relay.submit(abi.encodePacked(bytes32(0)), jn, rlp);
    }

    // ------------------------------------------------------------------ the rate reference

    function test_fast_reading_follows_difficulty() public view {
        // twice the hashrate (difficulty doubles, target halves): twice the requirement
        uint32 twice = 0x1a010293; // target of BITS halved
        uint256 a = relay.requiredAttest(7200, BITS, K0_DAA, K0_BW, 0);
        uint256 b = relay.requiredAttest(7200, twice, K0_DAA, K0_BW, 0);
        assertApproxEqRel(b, 2 * a, 0.01e18);
    }

    function test_slow_floor_resists_a_difficulty_drop() public view {
        // a miner who stops publishing pulls the difficulty to a quarter; with no day of history yet the floor is
        // beta x RATE0 = 0.8 of the genesis rate
        uint32 quarter = 0x1a081498; // target of BITS x 4
        uint256 normal = relay.requiredAttest(7200, BITS, K0_DAA, K0_BW, 0);
        uint256 low = relay.requiredAttest(7200, quarter, K0_DAA, K0_BW, 0);
        assertApproxEqRel(low, normal * 8 / 10, 0.01e18);
    }

    function test_slow_reading_uses_a_day_of_checkpoints() public {
        // settle rounds every 3 h for 27 h along an honest chain at RATE0; then the slow reading is the measured one
        for (uint256 i = 0; i < 9; i++) {
            (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 600, _one(keccak256(abi.encode(i)), 10 * USD, 0, alice));
            relay.submit(seal, jn, rlp);
            vm.warp(block.timestamp + 3 hours);
            vm.roll(block.number + 900);
        }
        (uint256 rate,) = relay.slowRate(relay.checkpointDaa(), _bwAt(relay.checkpointDaa()));
        assertEq(rate, RATE0, "a day of honest work at RATE0 reads back as RATE0");
        // and a miner who then halves the difficulty only lowers the requirement to beta of the day's average
        uint32 half = 0x1a040a4c; // target of BITS x 2
        uint256 normal = relay.requiredAttest(7200, BITS, relay.checkpointDaa(), _bwAt(relay.checkpointDaa()), 0);
        uint256 low = relay.requiredAttest(7200, half, relay.checkpointDaa(), _bwAt(relay.checkpointDaa()), 0);
        assertApproxEqRel(low, normal * 8 / 10, 0.01e18);
        (uint64 d8,) = relay.points(8);
        assertGt(d8, 0);
    }

    // ------------------------------------------------------------------ payouts (F6, F7)

    function _fill(uint64 amount) internal {
        vm.prank(alice);
        vault.deposit(amount, abi.encodePacked(uint8(0), bytes32(uint256(2))));
    }

    function test_installments_split_pro_rata_and_sum_exactly() public {
        // 25,000 owed with a 1,000 tip against a 10,000 bucket refilling 25,000 a day
        vm.warp(block.timestamp + 21 days); // cap 40,000
        _fill(10_000 * USD);
        _fill(10_000 * USD);
        _fill(10_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("big"), 25_000 * USD, 1_000 * USD, alice));
        uint256 aliceBefore = usdc.balanceOf(alice);
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        // first installment: 10,000 of 25,000, tip 400 of 1,000
        assertEq(usdc.balanceOf(robot), 400 * USD);
        assertEq(usdc.balanceOf(alice) - aliceBefore, 9_600 * USD);
        vm.warp(block.timestamp + 1 days);
        relay.claim(bytes32("big"));
        vm.warp(block.timestamp + 1 days);
        relay.claim(bytes32("big"));
        assertTrue(relay.settled(bytes32("big")));
        assertEq(usdc.balanceOf(robot), 1_000 * USD, "the whole tip, exactly");
        assertEq(usdc.balanceOf(alice) - aliceBefore, 24_000 * USD, "the whole remainder, exactly");
    }

    function test_tip_near_the_amount_is_never_a_deadlock() public {
        // tip = amount - 1 unit (the largest the guest allows) and a bucket smaller than the tip
        vm.warp(block.timestamp + 14 days);
        _fill(10_000 * USD);
        _fill(5_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tippy"), 12_000 * USD, 12_000 * USD - 1, alice));
        uint256 aliceBefore = usdc.balanceOf(alice);
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        vm.warp(block.timestamp + 1 days);
        relay.claim(bytes32("tippy"));
        assertTrue(relay.settled(bytes32("tippy")));
        assertEq(usdc.balanceOf(robot), 12_000 * USD - 1);
        assertEq(usdc.balanceOf(alice) - aliceBefore, 1);
    }

    function test_dust_installments_wait() public {
        vm.warp(block.timestamp + 14 days);
        _fill(10_000 * USD);
        _fill(5_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("a"), 10_000 * USD, 0, alice));
        relay.submit(seal, jn, rlp); // empties the bucket
        // seconds later the bucket holds a few units; a 1,000 burn must not pay them out as dust
        (jn, rlp, seal) = _round(3600, 500, _one(bytes32("b"), 1_000 * USD, 0, alice));
        vm.warp(block.timestamp + 2);
        relay.submit(seal, jn, rlp);
        (,,, uint64 paid,,) = relay.owed(bytes32("b"));
        assertEq(paid, 0, "no dust installment");
        vm.warp(block.timestamp + 1 hours);
        relay.claim(bytes32("b"));
        (,,, paid,,) = relay.owed(bytes32("b"));
        assertEq(paid, 1_000 * USD);
    }

    function test_blacklisted_recipient_waits_without_spending_the_bucket() public {
        usdc.blacklist(address(0xBAD));
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("bl"), 100 * USD, 1 * USD, address(0xBAD)));
        uint64 availBefore = vault.available();
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        assertEq(vault.available(), availBefore, "the bucket is untouched");
        assertEq(vault.outstanding(), 5_000 * USD);
        assertEq(usdc.balanceOf(robot), 0, "no tip while the recipient is refused");
        usdc.unBlacklist(address(0xBAD));
        relay.claim(bytes32("bl"));
        assertTrue(relay.settled(bytes32("bl")));
        assertEq(usdc.balanceOf(address(0xBAD)), 99 * USD);
        assertEq(usdc.balanceOf(robot), 1 * USD);
    }

    function test_below_min_burn_is_skipped_for_good() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("dust"), 9 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        (,,,,, bool rec) = relay.owed(bytes32("dust"));
        assertTrue(rec);
        assertEq(relay.owedTotal(), 0);
        assertEq(vault.outstanding(), 5_000 * USD);
    }

    function test_a_burn_is_recorded_once() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        (jn, rlp, seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertEq(vault.outstanding(), 4_900 * USD, "paid once");
    }

    function test_forged_journal_is_capped_by_the_vault() public {
        // a forger who meets the rule (a majority) records at most what the vault holds and drains at the bucket's rate
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("forged"), 1_000_000 * USD, 0, address(0xF0)));
        relay.submit(seal, jn, rlp);
        (,uint64 amount,,,,) = relay.owed(bytes32("forged"));
        assertEq(amount, 5_000 * USD);
    }

    function test_reentry_from_the_token_is_blocked() public {
        ReentrantToken tok = new ReentrantToken();
        UsdcVaultV3 v = new UsdcVaultV3(IERC20(address(tok)), address(this), 5_000 * USD, 50_000 * USD, 7 days, 10 * USD, 10_000 * USD, 25_000 * USD, 10_000 * USD);
        relay = _relay(ISettlementV3(address(v)), 0);
        v.setRelay(address(relay));
        tok.mint(alice, 5_000 * USD);
        vm.startPrank(alice);
        tok.approve(address(v), type(uint256).max);
        v.deposit(5_000 * USD, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.stopPrank();
        tok.setHook(relay, bytes32("r1"));
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("r1"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertTrue(tok.reentered());
        assertTrue(tok.reentryReverted(), "the lock refuses the nested claim");
        assertEq(tok.balanceOf(alice), 100 * USD, "paid once");
        assertEq(v.outstanding(), 4_900 * USD);
    }

    function test_amount_term_when_enabled() public {
        relay = _relay(ISettlementV3(address(vault)), 15 * USD);
        // $10,000 at $15 per attester needs 667, above the rate term for a fresh beacon
        assertEq(relay.requiredAttest(600, BITS, K0_DAA, K0_BW, 10_000 * USD), 667);
    }
}
