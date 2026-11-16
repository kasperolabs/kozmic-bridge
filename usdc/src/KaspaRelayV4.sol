// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlementV3} from "./ISettlementV3.sol";

/// @title KaspaRelayV4: Ethereum verifies Kaspa proof-of-work and settles burns of a KCC-20 token on Kaspa L1.
/// @notice No owner, no pause, no upgrade. The v4 design (docs/V4-DESIGN.md section 2): burn-anchored freshness.
///
///   Every proof carries burns, and the freshest burn carries an Ethereum beacon (block number and hash) that did not
///   exist before the burn was built. The guest (v3, journal KZO4) proves that `attesting` level-30 superblocks were
///   mined on top of every burn, so all of them after the beacon. This contract checks the beacon against Ethereum's
///   own history (EIP-2935), reads its time from the block header, and accepts the proof only when
///
///       attesting >= max(FLOOR, alpha x r x tau [, amount / ATTEST_UNIT])
///
///   with tau the seconds since the beacon block (plus one slot) and r the rate of level-30 superblocks Kaspa's
///   hashrate produces, read from trusted headers with no timer:
///     r_fast  from the checkpoint K's own difficulty bits (Kaspa's difficulty follows hashrate within minutes);
///     r_slow  from the blue work between K and the checkpoint about SLOW_SPAN_DAA earlier (exact, from headers this
///             contract trusted when it settled them), or RATE0 until that much history exists;
///     r     = max(r_fast, beta x r_slow): the fast reading tracks growth, the slow floor stops a miner who goes quiet
///             from pulling the requirement down without hiding for a whole day.
///   A forger must keep pace with alpha of Kaspa's hashrate from the moment the beacon existed; waiting does not help
///   because the requirement grows with the clock. Borrowed honest superblocks never attest a forged burn (F1).
///
///   There is no challenge window: a proof that meets the rule settles in the same transaction. A forger who meets it
///   already holds about alpha of Kaspa; against a majority nothing here helps (V4-DESIGN 4.5). So there is no
///   candidate to replace and no deadline to extend (F4 cannot exist). Two honest robots racing: the second finds the
///   checkpoint moved and reverts before the verifier, for little gas.
///
///   Settlement (V3's, with F6 and F7): every burn is recorded once as owed, then paid in installments from the
///   vault's bucket. Each installment pays the recipient and the tip pro rata of the burn's cumulative entitlement,
///   so a tip near the amount is never a deadlock; installments under MIN_INSTALLMENT wait unless they finish the
///   burn (dust). The relay's accounting moves before the vault's transfer; a refused transfer restores it. A
///   transient lock blocks re-entry. Burns under MIN_BURN are recorded as skipped (they stay burned).
///
/// Journal (KZO4, big-endian, 354 + 68 n bytes; outbound/kaspa-prover/primitives/src/relay.rs, guest v3):
///   "KZO4"(4) | K(32) | K.daa(8) | K.bits(4) | K.blue_work(24) | T(32) | T.daa(8) | B(32) | B.daa(8) | headers(4) |
///   n_levels(1) | 8 x (level(1), count(4), attesting(4)) | target(20) | token_cov_id(32) | template_hash(32) |
///   anchor number(8) | anchor hash(32) | n_burns(1) | n x (tx id(32), amount(8), tip(8), recipient(20))
contract KaspaRelayV4 {
    bytes4 private constant MAGIC = 0x4b5a4f34; // "KZO4"
    uint256 private constant HEADER_LEN = 354;
    uint256 private constant BURN_LEN = 68;
    /// @notice EIP-2935 history contract (Pectra): the hash of any of the last 8,191 blocks, by number.
    address public constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    /// @notice Kaspa DAA units per second (10 BPS mainnet; measured 9.9968 over 30.9 h, V4-DESIGN 2.8).
    uint256 public constant DAA_PER_SECOND = 10;
    /// @notice The most a proposer can see its own block hash before it is public.
    uint256 public constant SLOT_SLACK = 12;

    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable IMAGE_ID;
    ISettlementV3 public immutable SETTLEMENT;
    bytes32 public immutable TOKEN_COV_ID;
    bytes32 public immutable TEMPLATE_HASH;
    uint8 public immutable CMP_LEVEL;
    /// @notice F: the least attesting superblocks any proof needs.
    uint32 public immutable FLOOR;
    /// @notice alpha, in basis points of Kaspa's level-CMP_LEVEL rate.
    uint32 public immutable ALPHA_BPS;
    /// @notice beta, in basis points: the slow reading's floor under the fast one.
    uint32 public immutable BETA_BPS;
    /// @notice How far back the slow reading looks (DAA units; 864,000 is a day).
    uint64 public immutable SLOW_SPAN_DAA;
    /// @notice Expected hashes per DAA unit at genesis (S1b), the slow reading until SLOW_SPAN_DAA of history exists.
    uint256 public immutable RATE0;
    /// @notice Value per attester for the optional amount term (D4); 0 = off.
    uint64 public immutable ATTEST_UNIT;
    /// @notice Burns under this many base units are skipped (they stay burned).
    uint64 public immutable MIN_BURN;
    /// @notice Installments under this wait for the bucket unless they finish the burn.
    uint64 public immutable MIN_INSTALLMENT;

    bytes32 public checkpoint;
    uint64 public checkpointDaa;

    /// @notice Every checkpoint a settled proof started from, with its blue work: the slow reading's history.
    struct Point {
        uint64 daa;
        uint192 blueWork;
    }

    Point[] public points;
    /// @notice Index of the newest point at least SLOW_SPAN_DAA behind the last settled K.
    uint256 public slowIdx;

    struct Debt {
        address recipient;
        uint64 amount; // recorded amount, tip included
        uint64 tip;
        uint64 paid; // cumulative, tip included
        address submitter;
        bool recorded;
    }

    mapping(bytes32 => Debt) public owed;
    uint64 public owedTotal;

    event Settled(bytes32 indexed checkpoint, uint64 checkpointDaa, uint32 count, uint32 attesting, uint256 required, uint256 tau, uint64 anchorNumber, address indexed submitter);
    event Owed(bytes32 indexed txId, address indexed recipient, uint64 amount, uint64 tip, address indexed submitter);
    event Paid(bytes32 indexed txId, uint64 paid, uint64 tip, uint64 remaining);
    event PaidInFull(bytes32 indexed txId);
    event Deferred(bytes32 indexed txId, uint64 remaining, string reason);
    event Capped(bytes32 indexed txId, uint64 requested, uint64 recorded);
    event Skipped(bytes32 indexed txId, string reason);

    struct Params {
        bytes32 checkpoint;
        uint64 checkpointDaa;
        uint192 checkpointBlueWork;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint8 cmpLevel;
        uint32 floor;
        uint32 alphaBps;
        uint32 betaBps;
        uint64 slowSpanDaa;
        uint256 rate0;
        uint64 attestUnit;
        uint64 minBurn;
        uint64 minInstallment;
    }

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, ISettlementV3 settlement, Params memory p) {
        require(address(verifier) != address(0) && address(settlement) != address(0), "relay: zero address");
        require(imageId != bytes32(0) && p.checkpoint != bytes32(0), "relay: zero id");
        require(p.tokenCovId != bytes32(0) && p.templateHash != bytes32(0), "relay: zero token");
        require(p.cmpLevel != 0 && p.floor != 0 && p.slowSpanDaa != 0 && p.rate0 != 0 && p.minBurn != 0, "relay: zero param");
        require(p.alphaBps > 0 && p.alphaBps < 10_000 && p.betaBps <= 10_000, "relay: bad alpha or beta");
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        SETTLEMENT = settlement;
        TOKEN_COV_ID = p.tokenCovId;
        TEMPLATE_HASH = p.templateHash;
        CMP_LEVEL = p.cmpLevel;
        FLOOR = p.floor;
        ALPHA_BPS = p.alphaBps;
        BETA_BPS = p.betaBps;
        SLOW_SPAN_DAA = p.slowSpanDaa;
        RATE0 = p.rate0;
        ATTEST_UNIT = p.attestUnit;
        MIN_BURN = p.minBurn;
        MIN_INSTALLMENT = p.minInstallment;
        checkpoint = p.checkpoint;
        checkpointDaa = p.checkpointDaa;
        points.push(Point({daa: p.checkpointDaa, blueWork: p.checkpointBlueWork}));
    }

    // ------------------------------------------------------------------ re-entry lock (transient, cancun)

    modifier locked() {
        assembly {
            if tload(0) { revert(0, 0) }
            tstore(0, 1)
        }
        _;
        assembly {
            tstore(0, 0)
        }
    }

    // ------------------------------------------------------------------ the rate reference (V4-DESIGN 2.4)

    /// @notice Expected hashes per block at compact difficulty `bits` (Kaspa's `from_compact_target_bits`).
    function workOfBits(uint32 bits) public pure returns (uint256) {
        uint256 mant = bits & 0xFFFFFF;
        uint256 expt = bits >> 24;
        require(mant <= 0x7FFFFF, "relay: negative target");
        uint256 target = expt <= 3 ? mant >> (8 * (3 - expt)) : (expt >= 35 ? 0 : mant << (8 * (expt - 3)));
        require(target != 0, "relay: zero target");
        return type(uint256).max / (target + 1);
    }

    /// @notice The slow reading at K: hashes per DAA unit between K and the newest point at least SLOW_SPAN_DAA
    ///         behind it, or RATE0 when the history is younger than that.
    function slowRate(uint64 kDaa, uint192 kBlueWork) public view returns (uint256 rate, uint256 idx) {
        idx = slowIdx;
        uint256 n = points.length;
        while (idx + 1 < n && uint256(points[idx + 1].daa) + SLOW_SPAN_DAA <= kDaa) idx++;
        Point memory p = points[idx];
        if (uint256(p.daa) + SLOW_SPAN_DAA <= kDaa && kBlueWork > p.blueWork) {
            rate = uint256(kBlueWork - p.blueWork) / (kDaa - p.daa);
        } else {
            rate = RATE0;
        }
    }

    /// @notice The attesting superblocks a proof needs: max(FLOOR, alpha x max(r_fast, beta x r_slow) x tau, amount
    ///         term), with r in hashes per DAA unit converted to level-CMP_LEVEL superblocks (2^(31+L) hashes each).
    function requiredAttest(uint256 tau, uint32 kBits, uint64 kDaa, uint192 kBlueWork, uint256 amount) public view returns (uint256 req) {
        uint256 fast = workOfBits(kBits);
        (uint256 slow,) = slowRate(kDaa, kBlueWork);
        uint256 slowFloor = slow * BETA_BPS / 10_000;
        uint256 ref = fast > slowFloor ? fast : slowFloor;
        uint256 den = 10_000 << (31 + uint256(CMP_LEVEL));
        uint256 num = uint256(ALPHA_BPS) * ref * DAA_PER_SECOND * tau;
        req = (num + den - 1) / den;
        if (req < FLOOR) req = FLOOR;
        if (ATTEST_UNIT != 0) {
            uint256 byAmount = (amount + ATTEST_UNIT - 1) / ATTEST_UNIT;
            if (byAmount > req) req = byAmount;
        }
    }

    // ------------------------------------------------------------------ the beacon (V4-DESIGN 2.2)

    /// @notice (number, timestamp) of an Ethereum block header given as its RLP. Reads list items 8 and 11.
    function headerNumberAndTime(bytes calldata h) public pure returns (uint256 number, uint256 timestamp) {
        require(h.length > 2, "relay: header too short");
        uint256 b0 = uint8(h[0]);
        uint256 pos;
        uint256 end;
        if (b0 >= 0xf8) {
            uint256 ll = b0 - 0xf7;
            pos = 1 + ll;
            end = pos + _be(h, 1, ll);
        } else {
            require(b0 >= 0xc0, "relay: header is not an RLP list");
            pos = 1;
            end = 1 + (b0 - 0xc0);
        }
        require(end == h.length, "relay: header length");
        for (uint256 i = 0; i <= 11; i++) {
            require(pos < end, "relay: header has too few fields");
            uint256 p = uint8(h[pos]);
            uint256 dataAt;
            uint256 dataLen;
            if (p < 0x80) {
                dataAt = pos;
                dataLen = 1;
            } else if (p <= 0xb7) {
                dataAt = pos + 1;
                dataLen = p - 0x80;
            } else if (p <= 0xbf) {
                uint256 ll = p - 0xb7;
                dataAt = pos + 1 + ll;
                dataLen = _be(h, pos + 1, ll);
            } else {
                revert("relay: list inside a header field");
            }
            require(dataAt + dataLen <= end, "relay: header field overruns");
            if (i == 8) number = _be(h, dataAt, dataLen);
            if (i == 11) timestamp = _be(h, dataAt, dataLen);
            pos = dataAt + dataLen;
        }
    }

    function _be(bytes calldata b, uint256 at, uint256 len) private pure returns (uint256 v) {
        require(len <= 32 && at + len <= b.length, "relay: integer field");
        for (uint256 i = 0; i < len; i++) v = (v << 8) | uint8(b[at + i]);
    }

    /// @notice The beacon block's timestamp, after checking that `headerRlp` is the block Ethereum has at `number`.
    function beaconTime(uint64 number, bytes32 hash, bytes calldata headerRlp) public view returns (uint256) {
        require(number != 0 && number < block.number, "relay: beacon block is not in the past");
        (bool ok, bytes memory ret) = HISTORY.staticcall(abi.encode(uint256(number)));
        require(ok && ret.length == 32, "relay: beacon block outside Ethereum's history window");
        require(abi.decode(ret, (bytes32)) == hash, "relay: beacon is not Ethereum's block at that number");
        require(keccak256(headerRlp) == hash, "relay: header is not the beacon block");
        (uint256 hn, uint256 ts) = headerNumberAndTime(headerRlp);
        require(hn == number, "relay: header number differs from the beacon");
        require(ts <= block.timestamp, "relay: beacon in the future");
        return ts;
    }

    // ------------------------------------------------------------------ journal

    struct Journal {
        bytes32 k;
        uint64 kDaa;
        uint32 kBits;
        uint192 kBlueWork;
        bytes32 t;
        uint64 tDaa;
        uint32 count;
        uint32 attesting;
        address target;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint64 anchorNumber;
        bytes32 anchorHash;
        uint8 nBurns;
        uint256 amount;
    }

    function parseJournal(bytes calldata j) public view returns (Journal memory out) {
        require(j.length >= HEADER_LEN && (j.length - HEADER_LEN) % BURN_LEN == 0, "relay: journal length");
        require(bytes4(j[0:4]) == MAGIC, "relay: journal magic");
        out.k = bytes32(j[4:36]);
        out.kDaa = uint64(bytes8(j[36:44]));
        out.kBits = uint32(bytes4(j[44:48]));
        out.kBlueWork = uint192(bytes24(j[48:72]));
        out.t = bytes32(j[72:104]);
        out.tDaa = uint64(bytes8(j[104:112]));
        uint8 nLevels = uint8(j[156]);
        require(nLevels >= 1 && nLevels <= 8, "relay: levels");
        bool found;
        for (uint256 i = 0; i < nLevels; i++) {
            uint256 o = 157 + 9 * i;
            if (uint8(j[o]) == CMP_LEVEL) {
                out.count = uint32(bytes4(j[o + 1:o + 5]));
                out.attesting = uint32(bytes4(j[o + 5:o + 9]));
                found = true;
            }
        }
        require(found, "relay: no count at CMP_LEVEL");
        out.target = address(bytes20(j[229:249]));
        out.tokenCovId = bytes32(j[249:281]);
        out.templateHash = bytes32(j[281:313]);
        out.anchorNumber = uint64(bytes8(j[313:321]));
        out.anchorHash = bytes32(j[321:353]);
        out.nBurns = uint8(j[353]);
        require(out.nBurns >= 1 && uint256(out.nBurns) == (j.length - HEADER_LEN) / BURN_LEN, "relay: burn count");
        for (uint256 i = 0; i < out.nBurns; i++) {
            (, uint64 amount,,) = burnAt(j, i);
            out.amount += amount;
        }
    }

    function burnAt(bytes calldata j, uint256 i) internal pure returns (bytes32 txId, uint64 amount, uint64 tip, address recipient) {
        uint256 o = HEADER_LEN + BURN_LEN * i;
        txId = bytes32(j[o:o + 32]);
        amount = uint64(bytes8(j[o + 32:o + 40]));
        tip = uint64(bytes8(j[o + 40:o + 48]));
        recipient = address(bytes20(j[o + 48:o + 68]));
    }

    // ------------------------------------------------------------------ submit: check, verify, settle

    /// @param headerRlp the RLP of the Ethereum block the journal's anchor names
    function submit(bytes calldata seal, bytes calldata journal, bytes calldata headerRlp) external locked {
        Journal memory jn = parseJournal(journal);
        require(jn.k == checkpoint && jn.kDaa == checkpointDaa, "relay: journal does not start at the checkpoint");
        require(jn.target == address(this), "relay: journal target is not this relay");
        require(jn.tokenCovId == TOKEN_COV_ID && jn.templateHash == TEMPLATE_HASH, "relay: not this token");
        require(jn.tDaa > checkpointDaa, "relay: tip is not past the checkpoint");
        uint256 tau = block.timestamp - beaconTime(jn.anchorNumber, jn.anchorHash, headerRlp) + SLOT_SLACK;
        uint256 required = requiredAttest(tau, jn.kBits, jn.kDaa, jn.kBlueWork, jn.amount);
        require(jn.attesting >= required, "relay: not enough attestation for the time since the beacon");
        VERIFIER.verify(seal, IMAGE_ID, sha256(journal));

        // the slow reading's history: K is trusted now (it is the checkpoint), so record it
        (, uint256 idx) = slowRate(jn.kDaa, jn.kBlueWork);
        slowIdx = idx;
        if (points[points.length - 1].daa < jn.kDaa) points.push(Point({daa: jn.kDaa, blueWork: jn.kBlueWork}));
        checkpoint = jn.t;
        checkpointDaa = jn.tDaa;
        emit Settled(jn.t, jn.tDaa, jn.count, jn.attesting, required, tau, jn.anchorNumber, msg.sender);

        for (uint256 i = 0; i < jn.nBurns; i++) {
            (bytes32 txId, uint64 amount, uint64 tip, address recipient) = burnAt(journal, i);
            _record(txId, amount, tip, recipient);
        }
    }

    function _record(bytes32 txId, uint64 amount, uint64 tip, address recipient) internal {
        Debt storage d = owed[txId];
        if (d.recorded) {
            emit Skipped(txId, "already recorded");
            return;
        }
        if (amount < MIN_BURN) {
            d.recorded = true; // never recorded again; the burn stays burned
            emit Skipped(txId, "below MIN_BURN");
            return;
        }
        // what the relay may ever owe is what the vault holds and does not owe yet (V3)
        uint64 out = SETTLEMENT.outstanding();
        uint64 room = out > owedTotal ? out - owedTotal : 0;
        uint64 rec = amount > room ? room : amount;
        if (rec != amount) {
            emit Capped(txId, amount, rec);
            tip = uint64(uint256(tip) * rec / amount); // keep the ratio; the guest guarantees tip < amount
        }
        owed[txId] = Debt({recipient: recipient, amount: rec, tip: tip, paid: 0, submitter: msg.sender, recorded: true});
        owedTotal += rec;
        emit Owed(txId, recipient, rec, tip, msg.sender);
        if (rec == 0) emit PaidInFull(txId);
        else _pay(txId);
    }

    /// @notice Pay the next installment of an owed burn. Anyone may call; a burn paid in full is a no-op.
    function claim(bytes32 txId) external locked returns (uint64 paid) {
        require(owed[txId].recorded, "relay: not an owed burn");
        return _pay(txId);
    }

    function settled(bytes32 txId) external view returns (bool) {
        Debt storage d = owed[txId];
        return d.recorded && d.paid == d.amount;
    }

    /// @notice The tip part of the first `paid` units of a burn: floor(tip x paid / amount).
    function tipEntitled(uint64 tip, uint64 amount, uint64 paid) public pure returns (uint64) {
        return amount == 0 ? 0 : uint64(uint256(tip) * paid / amount);
    }

    function _pay(bytes32 txId) internal returns (uint64 p) {
        Debt storage d = owed[txId];
        uint64 remaining = d.amount - d.paid;
        if (remaining == 0) return 0;
        uint64 avail = SETTLEMENT.available();
        uint64 out = SETTLEMENT.outstanding();
        p = remaining;
        if (p > avail) p = avail;
        if (p > out) p = out;
        if (p == 0) {
            emit Deferred(txId, remaining, avail == 0 ? "bucket empty" : "nothing outstanding");
            return 0;
        }
        if (p < remaining && p < MIN_INSTALLMENT) {
            emit Deferred(txId, remaining, "installment below the minimum");
            return 0;
        }
        uint64 before = d.paid;
        uint64 after_ = before + p;
        uint64 toTip = tipEntitled(d.tip, d.amount, after_) - tipEntitled(d.tip, d.amount, before);
        // F7: debit first
        d.paid = after_;
        owedTotal -= p;
        if (!SETTLEMENT.release(txId, d.recipient, p - toTip, d.submitter, toTip)) {
            d.paid = before;
            owedTotal += p;
            emit Deferred(txId, remaining, "recipient refused");
            return 0;
        }
        emit Paid(txId, p, toTip, d.amount - after_);
        if (after_ == d.amount) emit PaidInFull(txId);
    }
}
