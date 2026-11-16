// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {KaspaRelayV5} from "../src/KaspaRelayV5.sol";
import {UsdcVaultV4, IERC20} from "../src/UsdcVaultV4.sol";
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
    KaspaRelayV5 public relay;
    bytes32 public hookTx;
    bool public reentered;
    bool public reentryReverted;

    function setHook(KaspaRelayV5 r, bytes32 tx_) external {
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

contract KaspaRelayV5Test is Test {
    address constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    bytes32 constant IMAGE = bytes32(uint256(0x090ea092));
    bytes32 constant TOKEN_ID = bytes32(uint256(0x13af6019));
    bytes32 constant TEMPLATE = 0x9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7;
    // measured mean hashrate 3.567e17 H/s at 10 BPS (V4-DESIGN 2.8): 9.28 level-30 superblocks a minute
    uint32 constant BITS = 0x1a020526;
    uint32 constant TWICE = 0x1a010293; // target halved: twice the work
    uint32 constant QUARTER = 0x1a081498; // target x 4: a quarter of the work
    uint64 constant USD = 1e6;
    /// D4: $2 per attester (sprint 3 record): forgery costs about 2x its take at KAS = $0.032
    uint64 constant ATTEST_UNIT = 2 * USD;
    address constant FEE_TO = address(0xFEE);
    bytes constant PREIMAGE = "open sesame, once";

    MockVerifier verifier;
    MockFiatToken usdc;
    UsdcVaultV4 vault;
    KaspaRelayV5 relay;
    MockHistory hist;

    address alice = address(0xA11CE);
    address robot = address(0xB0B);
    uint64 bDaaNext = 587_235_457;

    function setUp() public {
        vm.warp(1_794_000_000);
        vm.roll(12_100_000);
        verifier = new MockVerifier();
        usdc = new MockFiatToken();
        vault = _vault(IERC20(address(usdc)));
        relay = _relay(ISettlementV3(address(vault)));
        vault.setRelay(address(relay));
        MockHistory impl = new MockHistory();
        vm.etch(HISTORY, address(impl).code);
        hist = MockHistory(HISTORY);
        // a depositor fills the vault to 5,000
        usdc.mint(alice, 1_000_000 * USD);
        vm.startPrank(alice);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(5_000 * USD, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.stopPrank();
    }

    function _vault(IERC20 t) internal returns (UsdcVaultV4) {
        return new UsdcVaultV4(t, address(this), 5_000 * USD, 1_000_000 * USD, 7 days, 10 * USD, 10_000 * USD, 25_000 * USD, 10_000 * USD, 10, FEE_TO, sha256(PREIMAGE));
    }

    function _relay(ISettlementV3 s) internal returns (KaspaRelayV5) {
        return new KaspaRelayV5(
            IRiscZeroVerifier(address(verifier)),
            IMAGE,
            s,
            KaspaRelayV5.Params({
                genesisBits: BITS,
                tokenCovId: TOKEN_ID,
                templateHash: TEMPLATE,
                cmpLevel: 30,
                floor: 450,
                alphaBps: 5_000,
                slowSpan: 7 days,
                attestUnit: ATTEST_UNIT,
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

    // ------------------------------------------------------------------ journal builder (KZO6)

    struct Burn {
        bytes32 txId;
        uint64 amount;
        uint64 tip;
        address recipient;
    }

    struct J {
        bytes32 t;
        uint64 tDaa;
        bytes32 b;
        uint64 bDaa;
        uint32 rBits;
        uint32 count;
        uint32 attesting;
        address target;
        uint64 anchorN;
        bytes32 anchorH;
        Burn[] burns;
    }

    function _journal(J memory j) internal view returns (bytes memory out) {
        return _journalFor(j, robot);
    }

    /// KZO6: the prover (the tips' address) sits between the anchor hash and the burn count.
    function _journalFor(J memory j, address prover) internal pure returns (bytes memory out) {
        out = abi.encodePacked(bytes4("KZO6"), j.t, j.tDaa, j.b, j.bDaa, j.rBits, uint32(600));
        out = abi.encodePacked(out, uint8(1), uint8(30), j.count, j.attesting);
        for (uint256 i = 1; i < 8; i++) out = abi.encodePacked(out, uint8(0), uint32(0), uint32(0));
        out = abi.encodePacked(out, bytes20(j.target), TOKEN_ID, TEMPLATE);
        out = abi.encodePacked(out, j.anchorN, j.anchorH, bytes20(prover), uint8(j.burns.length));
        for (uint256 i = 0; i < j.burns.length; i++) {
            Burn memory b = j.burns[i];
            out = abi.encodePacked(out, b.txId, b.amount, b.tip, bytes20(b.recipient));
        }
    }

    function _one(bytes32 txId, uint64 amount, uint64 tip, address to) internal pure returns (Burn[] memory b) {
        b = new Burn[](1);
        b[0] = Burn(txId, amount, tip, to);
    }

    // ------------------------------------------------------------------ 11-08 review: F16, F18

    /// F16: the tip follows the journal's prover, not the sender. A front-runner who copies a proof from the mempool
    /// settles it for the honest prover and earns nothing.
    function test_tip_goes_to_the_journals_prover_not_the_sender() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("fr"), 100 * USD, 1 * USD, alice));
        address frontRunner = address(0xF00);
        vm.prank(frontRunner);
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("fr")));
        assertEq(usdc.balanceOf(frontRunner), 0, "the sender earns nothing");
        assertEq(usdc.balanceOf(robot), 1 * USD, "the journal's prover gets the tip");
        (,,,, address submitter,) = relay.owed(bytes32("fr"));
        assertEq(submitter, robot);
    }

    /// F16: a journal with a zero prover is refused before the proof is checked (the guest refuses it too).
    function test_a_journal_without_a_prover_is_refused() public {
        (uint64 n, bytes32 h, bytes memory rlp) = _beacon(3600);
        J memory j;
        j.bDaa = bDaaNext;
        j.b = keccak256("B0");
        j.tDaa = j.bDaa + 18_000;
        j.t = keccak256("T0");
        j.rBits = BITS;
        j.count = 510;
        j.attesting = 500;
        j.target = address(relay);
        j.anchorN = n;
        j.anchorH = h;
        j.burns = _one(bytes32("np"), 100 * USD, 0, alice);
        bytes memory jn = _journalFor(j, address(0));
        bytes memory seal = verifier.sealFor(IMAGE, sha256(jn));
        vm.expectRevert("relay: no prover");
        relay.submit(seal, jn, rlp);
    }

    /// F18: a tip the prover cannot receive (blacklisted) is not stranded in the vault: it accrues to the fees, so
    /// the vault's balance stays outstanding + feeOwed.
    function test_refused_tip_accrues_to_the_fees() public {
        usdc.blacklist(robot);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("rt"), 100 * USD, 1 * USD, alice));
        uint256 aliceBefore = usdc.balanceOf(alice);
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("rt")), "the recipient's installment is paid in full");
        assertEq(usdc.balanceOf(alice) - aliceBefore, 99 * USD - 99_000, "99 minus the fee");
        assertEq(usdc.balanceOf(robot), 0, "the blacklisted prover gets nothing");
        assertEq(vault.feeOwed(), 99_000 + 1 * USD, "the fee plus the refused tip");
        assertEq(usdc.balanceOf(address(vault)), uint256(vault.outstanding()) + vault.feeOwed(), "nothing stranded");
        usdc.unBlacklist(robot);
        assertTrue(vault.claimFees());
        assertEq(usdc.balanceOf(address(vault)), uint256(vault.outstanding()), "swept");
    }

    /// An honest round: beacon `ageSec` old, `attesting` superblocks, the proof's own reading `rBits`.
    function _roundR(uint256 ageSec, uint32 attesting, uint32 rBits, Burn[] memory burns) internal returns (bytes memory jn, bytes memory rlp, bytes memory seal) {
        (uint64 n, bytes32 h, bytes memory r) = _beacon(ageSec);
        J memory j;
        j.bDaa = bDaaNext;
        bDaaNext += 30_000;
        j.b = keccak256(abi.encode(j.bDaa, "B"));
        j.tDaa = j.bDaa + 18_000; // 30 min of chain after B
        j.t = keccak256(abi.encode(j.bDaa, "T"));
        j.rBits = rBits;
        j.count = attesting + 10;
        j.attesting = attesting;
        j.target = address(relay);
        j.anchorN = n;
        j.anchorH = h;
        j.burns = burns;
        jn = _journal(j);
        rlp = r;
        seal = verifier.sealFor(IMAGE, sha256(jn));
    }

    function _round(uint256 ageSec, uint32 attesting, Burn[] memory burns) internal returns (bytes memory, bytes memory, bytes memory) {
        return _roundR(ageSec, attesting, BITS, burns);
    }

    // ------------------------------------------------------------------ the rule

    function test_requirement_matches_the_measured_rate() public view {
        // alpha 0.5 at the measured difficulty: 9.28 level-30 a minute, 4.64 at half. F = 450 binds for the first
        // ~97 min after the beacon, then the rate term (557 at 2 h, 1,114 at 4 h). Small amounts add nothing.
        assertEq(relay.requiredAttest(1800, BITS, 100 * USD), 450);
        assertEq(relay.requiredAttest(3600, BITS, 100 * USD), 450);
        assertEq(relay.requiredAttest(5800, BITS, 100 * USD), 450);
        assertEq(relay.requiredAttest(7200, BITS, 100 * USD), 557);
        assertEq(relay.requiredAttest(14400, BITS, 100 * USD), 1114);
    }

    function test_amount_term_prices_each_dollar() public view {
        // D4 at $2 per attester: a $1,000 exit sits under the floor, $5,000 needs 2,500 (about 4.5 h), $10,000 5,000
        assertEq(relay.requiredAttest(600, BITS, 1_000 * USD), 500);
        assertEq(relay.requiredAttest(600, BITS, 900 * USD), 450);
        assertEq(relay.requiredAttest(600, BITS, 5_000 * USD), 2_500);
        assertEq(relay.requiredAttest(600, BITS, 10_000 * USD), 5_000);
        // and the rate term wins when the wait has been long enough anyway
        assertEq(relay.requiredAttest(40_000, BITS, 5_000 * USD), 3_094);
    }

    function test_honest_round_settles_in_one_transaction() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 1 * USD, alice));
        uint256 aliceBefore = usdc.balanceOf(alice);
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("tx1")));
        assertEq(usdc.balanceOf(robot), 1 * USD, "tip to the submitter");
        // the recipient's 99 less the 0.1% fee on it
        assertEq(usdc.balanceOf(alice) - aliceBefore, 99 * USD - 99_000, "99 minus the fee");
        assertEq(vault.feeOwed(), 99_000);
        assertEq(vault.outstanding(), 4_900 * USD);
        assertTrue(relay.seen(sha256(jn)));
    }

    function test_a_journal_settles_once() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        vm.expectRevert("relay: journal already settled");
        relay.submit(seal, jn, rlp);
    }

    function test_no_checkpoint_a_burn_after_silence_settles() public {
        // nothing settled for 40 days: the next honest proof still settles (the beacon is fresh; the memory holds
        // the newest reading)
        vm.warp(block.timestamp + 40 days);
        vm.roll(block.number + 40 days / 12);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("late"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("late")));
    }

    function test_too_few_attesters_for_the_beacon_age() public {
        // 4 h since the beacon needs 1,114 at alpha 0.5; 1,000 is not enough
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(4 hours, 1000, _one(bytes32("tx1"), 100 * USD, 0, alice));
        vm.expectRevert("relay: not enough attestation for the time since the beacon");
        relay.submit(seal, jn, rlp);
    }

    function test_too_few_attesters_for_the_amount() public {
        // a $5,000 exit needs 2,500 attesters whatever the clock says
        vm.warp(block.timestamp + 14 days);
        _fill(10_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(600, 2_000, _one(bytes32("big"), 5_000 * USD, 0, alice));
        vm.expectRevert("relay: not enough attestation for the time since the beacon");
        relay.submit(seal, jn, rlp);
        (jn, rlp, seal) = _round(600, 2_500, _one(bytes32("big"), 5_000 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("big")));
    }

    function test_borrowed_count_does_not_help() public {
        // the O5 forged ladder: thousands counted, 0 attesting
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(600, 0, _one(bytes32("tx1"), 100 * USD, 0, alice));
        vm.expectRevert("relay: not enough attestation for the time since the beacon");
        relay.submit(seal, jn, rlp);
    }

    function test_tip_must_be_past_b() public {
        (bytes memory jn, bytes memory rlp,) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        // T.daa := B.daa
        for (uint256 i = 0; i < 8; i++) jn[36 + i] = jn[76 + i];
        bytes memory seal = verifier.sealFor(IMAGE, sha256(jn));
        vm.expectRevert("relay: tip is not past B");
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
        j.b = bytes32("B");
        j.bDaa = 1000;
        j.t = bytes32("T");
        j.tDaa = 2000;
        j.rBits = BITS;
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

    function test_forged_seal_refused() public {
        (bytes memory jn, bytes memory rlp,) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        vm.expectRevert("verifier: bad seal");
        relay.submit(abi.encodePacked(bytes32(0)), jn, rlp);
    }

    function test_wrong_target_or_token_refused() public {
        (bytes memory jn, bytes memory rlp,) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        jn[170] = bytes1(uint8(jn[170]) ^ 1); // target
        bytes memory seal = verifier.sealFor(IMAGE, sha256(jn));
        vm.expectRevert("relay: journal target is not this relay");
        relay.submit(seal, jn, rlp);
        (jn, rlp,) = _round(3600, 500, _one(bytes32("tx1"), 100 * USD, 0, alice));
        jn[200] = bytes1(uint8(jn[200]) ^ 1); // token covenant id
        seal = verifier.sealFor(IMAGE, sha256(jn));
        vm.expectRevert("relay: not this token");
        relay.submit(seal, jn, rlp);
    }

    // ------------------------------------------------------------------ the difficulty memory (2.11.4)

    function test_own_reading_raises_the_reference_and_is_remembered() public {
        // a proof whose ladder read twice the difficulty: its own requirement doubles, and from then on so does
        // everyone's, for a week
        assertEq(relay.requiredAttest(7200, TWICE, 0), 1114, "own reading above the memory");
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _roundR(3600, 600, TWICE, _one(bytes32("hi"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertEq(relay.lastWork(), relay.workOfBits(TWICE));
        assertEq(relay.requiredAttest(7200, BITS, 0), 1114, "the memory now holds the higher reading");
        // a later proof reading a quarter of the difficulty lowers nothing
        (jn, rlp, seal) = _roundR(3600, 600, QUARTER, _one(bytes32("lo"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertEq(relay.requiredAttest(7200, QUARTER, 0), 1114, "a low reading cannot lower the reference");
        assertEq(relay.lastWork(), relay.workOfBits(QUARTER), "but it is the newest reading");
    }

    function test_memory_window_is_seven_days_then_the_newest_reading() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _roundR(3600, 600, TWICE, _one(bytes32("d0"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        // day 1: an ordinary reading settles; the reference is still the week's maximum
        vm.warp(block.timestamp + 1 days);
        vm.roll(block.number + 7200);
        (jn, rlp, seal) = _roundR(3600, 600, BITS, _one(bytes32("d1"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertEq(relay.requiredAttest(7200, BITS, 0), 1114);
        // day 6 (from day 0): still inside the window
        vm.warp(block.timestamp + 5 days);
        assertEq(relay.requiredAttest(7200, BITS, 0), 1114);
        // day 9: both readings have aged out; the newest reading (day 1's) is the reference
        vm.warp(block.timestamp + 3 days);
        assertEq(relay.historyWork(block.timestamp), relay.workOfBits(BITS));
        assertEq(relay.requiredAttest(7200, BITS, 0), 557);
    }

    function test_memory_keeps_the_hardest_reading_of_each_day() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _roundR(3600, 600, TWICE, _one(bytes32("a"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        (jn, rlp, seal) = _roundR(3600, 600, BITS, _one(bytes32("b"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        (uint64 day, uint192 work) = relay.slots((block.timestamp / 1 days) % 8);
        assertEq(day, block.timestamp / 1 days);
        assertEq(work, relay.workOfBits(TWICE), "the day's slot keeps the harder reading");
    }

    // ------------------------------------------------------------------ payouts (F6, F7)

    function _fill(uint64 amount) internal {
        vm.prank(alice);
        vault.deposit(amount, abi.encodePacked(uint8(0), bytes32(uint256(2))));
    }

    /// The recipient's part of an installment after the 0.1% fee.
    function _net(uint64 toRecipient) internal pure returns (uint64) {
        return toRecipient - uint64(uint256(toRecipient) * 10 / 10_000);
    }

    function test_installments_split_pro_rata_and_sum_exactly() public {
        // 25,000 owed with a 1,000 tip against a 10,000 bucket refilling 25,000 a day (attestation priced: 12,500)
        vm.warp(block.timestamp + 21 days); // cap 40,000
        _fill(10_000 * USD);
        _fill(10_000 * USD);
        _fill(10_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 13_000, _one(bytes32("big"), 25_000 * USD, 1_000 * USD, alice));
        uint256 aliceBefore = usdc.balanceOf(alice);
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        // first installment: 10,000 of 25,000, tip 400 of 1,000, the recipient 9,600 less the fee on it
        assertEq(usdc.balanceOf(robot), 400 * USD);
        assertEq(usdc.balanceOf(alice) - aliceBefore, _net(9_600 * USD));
        vm.warp(block.timestamp + 1 days);
        relay.claim(bytes32("big"));
        vm.warp(block.timestamp + 1 days);
        relay.claim(bytes32("big"));
        assertTrue(relay.settled(bytes32("big")));
        assertEq(usdc.balanceOf(robot), 1_000 * USD, "the whole tip, exactly");
        assertEq(usdc.balanceOf(alice) - aliceBefore, _net(9_600 * USD) + _net(9_600 * USD) + _net(4_800 * USD), "the whole remainder less fees, exactly");
        assertEq(vault.feeOwed(), 24 * USD, "0.1% of the 24,000 paid to the recipient");
    }

    function test_tip_near_the_amount_is_never_a_deadlock() public {
        // tip = amount - 1 unit (the largest the guest allows) and a bucket smaller than the tip
        vm.warp(block.timestamp + 14 days);
        _fill(10_000 * USD);
        _fill(5_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 6_000, _one(bytes32("tippy"), 12_000 * USD, 12_000 * USD - 1, alice));
        uint256 aliceBefore = usdc.balanceOf(alice);
        vm.prank(robot);
        relay.submit(seal, jn, rlp);
        vm.warp(block.timestamp + 1 days);
        relay.claim(bytes32("tippy"));
        assertTrue(relay.settled(bytes32("tippy")));
        assertEq(usdc.balanceOf(robot), 12_000 * USD - 1);
        assertEq(usdc.balanceOf(alice) - aliceBefore, 1, "one unit, too small for a fee");
    }

    function test_dust_installments_wait() public {
        vm.warp(block.timestamp + 14 days);
        _fill(10_000 * USD);
        _fill(5_000 * USD);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 5_000, _one(bytes32("a"), 10_000 * USD, 0, alice));
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
        assertEq(vault.feeOwed(), 0, "no fee on a refused installment");
        assertEq(usdc.balanceOf(robot), 0, "no tip while the recipient is refused");
        usdc.unBlacklist(address(0xBAD));
        relay.claim(bytes32("bl"));
        assertTrue(relay.settled(bytes32("bl")));
        assertEq(usdc.balanceOf(address(0xBAD)), _net(99 * USD));
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
        // a forger who meets the rule (a majority, and 500,000 attesters for $1M at $2 each) records at most what
        // the vault holds and drains at the bucket's rate
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500_000, _one(bytes32("forged"), 1_000_000 * USD, 0, address(0xF0)));
        relay.submit(seal, jn, rlp);
        (, uint64 amount,,,,) = relay.owed(bytes32("forged"));
        assertEq(amount, 5_000 * USD);
    }

    function test_reentry_from_the_token_is_blocked() public {
        ReentrantToken tok = new ReentrantToken();
        UsdcVaultV4 v = _vault(IERC20(address(tok)));
        relay = _relay(ISettlementV3(address(v)));
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
        assertEq(tok.balanceOf(alice), _net(100 * USD), "paid once");
        assertEq(v.outstanding(), 4_900 * USD);
    }

    // ------------------------------------------------------------------ the fee (sprint 3)

    function test_fee_accrues_and_anyone_sweeps_it() public {
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("f1"), 1_000 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertEq(vault.feeOwed(), 1 * USD, "0.1% of 1,000");
        assertEq(usdc.balanceOf(FEE_TO), 0, "nothing paid inside the release");
        vm.prank(address(0xCA11));
        assertTrue(vault.claimFees());
        assertEq(usdc.balanceOf(FEE_TO), 1 * USD);
        assertEq(vault.feeOwed(), 0);
        assertTrue(vault.claimFees(), "nothing to claim is fine");
    }

    function test_an_untransferable_fee_address_stops_nothing_but_the_fee() public {
        usdc.blacklist(FEE_TO);
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("f2"), 1_000 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("f2")), "the release went through");
        assertFalse(vault.claimFees(), "the sweep is refused");
        assertEq(vault.feeOwed(), 1 * USD, "and the fee stays accrued");
        usdc.unBlacklist(FEE_TO);
        assertTrue(vault.claimFees());
        assertEq(usdc.balanceOf(FEE_TO), 1 * USD);
    }

    // ------------------------------------------------------------------ the one-way close (sprint 3)

    function test_close_takes_the_preimage_once_and_stops_only_deposits() public {
        vm.warp(block.timestamp + 7 days); // cap 10,000: room exists before the close
        vm.expectRevert("vault: not the close preimage");
        vault.closeDeposits("wrong");
        assertGt(vault.room(), 0);
        vm.prank(address(0xC105E));
        vault.closeDeposits(PREIMAGE);
        assertTrue(vault.depositsClosed());
        assertEq(vault.room(), 0);
        vm.prank(alice);
        vm.expectRevert("vault: deposits are closed");
        vault.deposit(100 * USD, abi.encodePacked(uint8(0), bytes32(uint256(3))));
        vm.expectRevert("vault: already closed");
        vault.closeDeposits(PREIMAGE);
        // exits are untouched: a burn settles and pays after the close
        (bytes memory jn, bytes memory rlp, bytes memory seal) = _round(3600, 500, _one(bytes32("exit"), 100 * USD, 0, alice));
        relay.submit(seal, jn, rlp);
        assertTrue(relay.settled(bytes32("exit")));
        assertEq(vault.outstanding(), 4_900 * USD);
    }
}
