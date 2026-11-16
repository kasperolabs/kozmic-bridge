// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlementV3} from "./ISettlementV3.sol";

/// @title KaspaRelayV5: Ethereum verifies Kaspa proof-of-work and settles burns of a KCC-20 token on Kaspa L1.
/// @notice No owner, no pause, no upgrade, no checkpoint. The burn-anchored design (docs/V4-DESIGN.md 2.11):
///
///   Every proof carries burns, and the freshest burn carries an Ethereum beacon (block number and hash) that did not
///   exist before the burn was built. The guest (v4, journal KZO6) proves that `attesting` level-CMP_LEVEL superblocks
///   were mined on top of B, the Kaspa chain block that accepted every burn in the proof, so all of them after the
///   beacon. This contract checks the beacon against Ethereum's own history (EIP-2935), reads its time from the block
///   header, and accepts the proof only when
///
///       attesting >= max(FLOOR, alpha x r x tau, amount / ATTEST_UNIT)
///
///   with tau the seconds since the beacon block (plus one slot) and r the rate of level-CMP_LEVEL superblocks
///   Kaspa's hashrate produces. r has no timer and no checkpoint: it is the larger of
///     r_hist  the highest difficulty reading this contract has settled in the last SLOW_SPAN (7 days), or the newest
///             one it has when none is that recent (the relay's own memory of Kaspa's hashrate, 2.11.4);
///     r_own   the reading the proof carries about its own ladder: the median compact target over the superblocks it
///             expanded (2.11.3; a median, so a forger moves it only with a majority of the ladder).
///   A proof can only raise the reference, never lower it, and the reference is read from Ethereum's clock, so a
///   forger cannot shrink the window by his choice of Kaspa blocks. The amount term (D4) prices each dollar in
///   attesters, so a forged release costs more in forgone block rewards than it pays (2.11.8, sprint 3 record).
///
///   Nothing chains one proof to the next. A burn after a month of silence settles. The relay is live as long as
///   Ethereum keeps the beacon's block hash (about 27 hours from the beacon); a burn whose beacon is older than that
///   is settled by any later proof that batches it with a fresher burn, because every attester follows every burn
///   in the batch (2.11.6).
///
///   Settlement (V4's, with F6 and F7): every burn is recorded once as owed, then paid in installments from the
///   vault's bucket. Each installment pays the recipient and the tip pro rata of the burn's cumulative entitlement;
///   installments under MIN_INSTALLMENT wait unless they finish the burn. The relay's accounting moves before the
///   vault's transfer; a refused transfer restores it. A transient lock blocks re-entry. Burns under MIN_BURN are
///   recorded as skipped (they stay burned). A journal settles once: its digest is remembered.
///
/// Journal (KZO6, big-endian, 310 + 68 n bytes; outbound/kaspa-prover/primitives/src/relay.rs, guest v4 after the
/// 11-08 review: r_bits over the attesters, the prover named):
///   "KZO6"(4) | T(32) | T.daa(8) | B(32) | B.daa(8) | r_bits(4) | headers(4) | n_levels(1) |
///   8 x (level(1), count(4), attesting(4)) | target(20) | token_cov_id(32) | template_hash(32) |
///   anchor number(8) | anchor hash(32) | prover(20) | n_burns(1) | n x (tx id(32), amount(8), tip(8), recipient(20))
///   The tips of a proof go to its prover (in the journal, so a copied proof cannot take them; F16), not to the
///   sender of the settling transaction.
contract KaspaRelayV5 {
    bytes4 private constant MAGIC = 0x4b5a4f36; // "KZO6"
    uint256 private constant HEADER_LEN = 310;
    uint256 private constant BURN_LEN = 68;
    /// @notice EIP-2935 history contract (Pectra): the hash of any of the last 8,191 blocks, by number.
    address public constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    /// @notice Kaspa blocks per second (10 BPS mainnet; the hourly DAA rate measured 9.41 to 11.18, V4-DESIGN 2.11.2).
    uint256 public constant DAA_PER_SECOND = 10;
    /// @notice The most a proposer can see its own block hash before it is public.
    uint256 public constant SLOT_SLACK = 12;
    /// @notice Daily slots of the difficulty memory: a 7-day window needs 8 slots.
    uint256 private constant DAYS = 8;

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
    /// @notice How long a settled difficulty reading stays in the reference (seconds; 604,800 is a week).
    uint64 public immutable SLOW_SPAN;
    /// @notice Base units of the token per attesting superblock (D4). A release of A units needs at least
    ///         A / ATTEST_UNIT attesters, so a forged release costs more in forgone block rewards than it pays.
    uint64 public immutable ATTEST_UNIT;
    /// @notice Burns under this many base units are skipped (they stay burned).
    uint64 public immutable MIN_BURN;
    /// @notice Installments under this wait for the bucket unless they finish the burn.
    uint64 public immutable MIN_INSTALLMENT;

    /// @notice The difficulty memory: the hardest reading settled on each of the last DAYS UTC days (work in
    ///         expected hashes per block, `workOfBits`), and the newest reading of all.
    struct Slot {
        uint64 day;
        uint192 work;
    }

    Slot[DAYS] public slots;
    uint192 public lastWork;
    uint64 public lastTime;

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
    /// @notice sha256 of every journal that settled: a journal settles once.
    mapping(bytes32 => bool) public seen;

    event Settled(bytes32 indexed b, uint64 bDaa, bytes32 t, uint32 count, uint32 attesting, uint256 required, uint256 tau, uint64 anchorNumber, uint32 rBits, address indexed submitter);
    event Owed(bytes32 indexed txId, address indexed recipient, uint64 amount, uint64 tip, address indexed submitter);
    event Paid(bytes32 indexed txId, uint64 paid, uint64 tip, uint64 remaining);
    event PaidInFull(bytes32 indexed txId);
    event Deferred(bytes32 indexed txId, uint64 remaining, string reason);
    event Capped(bytes32 indexed txId, uint64 requested, uint64 recorded);
    event Skipped(bytes32 indexed txId, string reason);

    struct Params {
        /// a recent Kaspa header's compact difficulty at deployment: the memory's first reading
        uint32 genesisBits;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint8 cmpLevel;
        uint32 floor;
        uint32 alphaBps;
        uint64 slowSpan;
        uint64 attestUnit;
        uint64 minBurn;
        uint64 minInstallment;
    }

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, ISettlementV3 settlement, Params memory p) {
        require(address(verifier) != address(0) && address(settlement) != address(0), "relay: zero address");
        require(imageId != bytes32(0), "relay: zero id");
        require(p.tokenCovId != bytes32(0) && p.templateHash != bytes32(0), "relay: zero token");
        require(p.cmpLevel != 0 && p.floor != 0 && p.slowSpan != 0 && p.attestUnit != 0 && p.minBurn != 0, "relay: zero param");
        require(p.alphaBps > 0 && p.alphaBps < 10_000, "relay: bad alpha");
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        SETTLEMENT = settlement;
        TOKEN_COV_ID = p.tokenCovId;
        TEMPLATE_HASH = p.templateHash;
        CMP_LEVEL = p.cmpLevel;
        FLOOR = p.floor;
        ALPHA_BPS = p.alphaBps;
        SLOW_SPAN = p.slowSpan;
        ATTEST_UNIT = p.attestUnit;
        MIN_BURN = p.minBurn;
        MIN_INSTALLMENT = p.minInstallment;
        _remember(workOfBits(p.genesisBits));
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

    // ------------------------------------------------------------------ the rate reference (V4-DESIGN 2.11.4)

    /// @notice Expected hashes per block at compact difficulty `bits` (Kaspa's `from_compact_target_bits`).
    function workOfBits(uint32 bits) public pure returns (uint192) {
        uint256 mant = bits & 0xFFFFFF;
        uint256 expt = bits >> 24;
        require(mant <= 0x7FFFFF, "relay: negative target");
        uint256 target = expt <= 3 ? mant >> (8 * (3 - expt)) : (expt >= 35 ? 0 : mant << (8 * (expt - 3)));
        require(target != 0, "relay: zero target");
        uint256 w = type(uint256).max / (target + 1);
        require(w <= type(uint192).max, "relay: difficulty out of range");
        return uint192(w);
    }

    /// @notice The reference at time `t`: the hardest reading settled within SLOW_SPAN of `t`, else the newest one.
    function historyWork(uint256 t) public view returns (uint192 w) {
        uint256 fromDay = (t > SLOW_SPAN ? t - SLOW_SPAN : 0) / 1 days;
        for (uint256 i = 0; i < DAYS; i++) {
            Slot memory s = slots[i];
            if (s.work != 0 && s.day >= fromDay && s.day <= t / 1 days && s.work > w) w = s.work;
        }
        if (w == 0) w = lastWork;
    }

    function _remember(uint192 work) internal {
        uint64 d = uint64(block.timestamp / 1 days);
        Slot storage s = slots[d % DAYS];
        if (s.day != d) {
            s.day = d;
            s.work = work;
        } else if (work > s.work) {
            s.work = work;
        }
        lastWork = work;
        lastTime = uint64(block.timestamp);
    }

    /// @notice The attesting superblocks a proof with reading `rBits` and total `amount` needs after `tau` seconds:
    ///         max(FLOOR, alpha x max(r_hist, r_own) x tau, amount / ATTEST_UNIT), the rate in hashes per block
    ///         converted to level-CMP_LEVEL superblocks (2^(31+L) hashes each) at DAA_PER_SECOND blocks a second.
    function requiredAttest(uint256 tau, uint32 rBits, uint256 amount) public view returns (uint256 req) {
        uint256 own = workOfBits(rBits);
        uint256 hist = historyWork(block.timestamp);
        uint256 ref = own > hist ? own : hist;
        uint256 den = 10_000 << (31 + uint256(CMP_LEVEL));
        uint256 num = uint256(ALPHA_BPS) * ref * DAA_PER_SECOND * tau;
        req = (num + den - 1) / den;
        if (req < FLOOR) req = FLOOR;
        uint256 byAmount = (amount + ATTEST_UNIT - 1) / ATTEST_UNIT;
        if (byAmount > req) req = byAmount;
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
        bytes32 t;
        uint64 tDaa;
        bytes32 b;
        uint64 bDaa;
        uint32 rBits;
        uint32 count;
        uint32 attesting;
        address target;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint64 anchorNumber;
        bytes32 anchorHash;
        address prover;
        uint8 nBurns;
        uint256 amount;
    }

    function parseJournal(bytes calldata j) public view returns (Journal memory out) {
        require(j.length >= HEADER_LEN && (j.length - HEADER_LEN) % BURN_LEN == 0, "relay: journal length");
        require(bytes4(j[0:4]) == MAGIC, "relay: journal magic");
        out.t = bytes32(j[4:36]);
        out.tDaa = uint64(bytes8(j[36:44]));
        out.b = bytes32(j[44:76]);
        out.bDaa = uint64(bytes8(j[76:84]));
        out.rBits = uint32(bytes4(j[84:88]));
        uint8 nLevels = uint8(j[92]);
        require(nLevels >= 1 && nLevels <= 8, "relay: levels");
        bool found;
        for (uint256 i = 0; i < nLevels; i++) {
            uint256 o = 93 + 9 * i;
            if (uint8(j[o]) == CMP_LEVEL) {
                out.count = uint32(bytes4(j[o + 1:o + 5]));
                out.attesting = uint32(bytes4(j[o + 5:o + 9]));
                found = true;
            }
        }
        require(found, "relay: no count at CMP_LEVEL");
        out.target = address(bytes20(j[165:185]));
        out.tokenCovId = bytes32(j[185:217]);
        out.templateHash = bytes32(j[217:249]);
        out.anchorNumber = uint64(bytes8(j[249:257]));
        out.anchorHash = bytes32(j[257:289]);
        out.prover = address(bytes20(j[289:309]));
        out.nBurns = uint8(j[309]);
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
        require(jn.target == address(this), "relay: journal target is not this relay");
        require(jn.tokenCovId == TOKEN_COV_ID && jn.templateHash == TEMPLATE_HASH, "relay: not this token");
        require(jn.tDaa > jn.bDaa, "relay: tip is not past B");
        require(jn.prover != address(0), "relay: no prover");
        bytes32 digest = sha256(journal);
        require(!seen[digest], "relay: journal already settled");
        uint256 tau = block.timestamp - beaconTime(jn.anchorNumber, jn.anchorHash, headerRlp) + SLOT_SLACK;
        uint256 required = requiredAttest(tau, jn.rBits, jn.amount);
        require(jn.attesting >= required, "relay: not enough attestation for the time since the beacon");
        VERIFIER.verify(seal, IMAGE_ID, digest);

        seen[digest] = true;
        _remember(workOfBits(jn.rBits));
        emit Settled(jn.b, jn.bDaa, jn.t, jn.count, jn.attesting, required, tau, jn.anchorNumber, jn.rBits, msg.sender);

        for (uint256 i = 0; i < jn.nBurns; i++) {
            (bytes32 txId, uint64 amount, uint64 tip, address recipient) = burnAt(journal, i);
            _record(txId, amount, tip, recipient, jn.prover);
        }
    }

    /// @dev `prover` is the journal's: the address the guest was told the tips go to (F16).
    function _record(bytes32 txId, uint64 amount, uint64 tip, address recipient, address prover) internal {
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
        owed[txId] = Debt({recipient: recipient, amount: rec, tip: tip, paid: 0, submitter: prover, recorded: true});
        owedTotal += rec;
        emit Owed(txId, recipient, rec, tip, prover);
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
