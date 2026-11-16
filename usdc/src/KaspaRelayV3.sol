// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlementV2} from "./ISettlementV2.sol";

/// @title KaspaRelayV3: Ethereum verifies Kaspa proof-of-work and settles burns of a KCC-20 token on Kaspa L1.
/// @notice No owner, no pause, no upgrade. KaspaRelayV2 with one change (REHEARSAL-2-PLAN section 2.2): a burn is
///         proven once and paid over time.
///
///   `finalize` records every burn of the journal as OWED: {recipient, remaining, tipRemaining, submitter}, keyed
///   by the burn's Kaspa tx id (a burn already recorded is `Skipped("already recorded")`), then pays each from the
///   vault's release bucket. What the bucket cannot pay now stays owed. `claim(txId)`, which anyone may call, pays
///   the next installment. One mechanism covers an exit above the bucket (paid in installments), an empty bucket
///   (paid as it refills) and a blacklisted recipient (paid by `claim` once Circle clears the address). No case
///   ever needs a second proof of the same burn, so the cost of settling a burn does not grow with its age and
///   does not depend on blocks the node will prune.
///
///   What the relay may owe in total is capped at what the vault holds and does not owe yet (`owedTotal`,
///   `SETTLEMENT.outstanding()`): honest burns never reach the cap, a forged journal is recorded for at most the
///   vault's present backing and never for deposits made after it (the bucket then rate-limits the drain).
///
///   Unchanged from v2: the journal (KZO3), K/T/B, the ladders and floors, `requiredAttest` and `windowFor`
///   (kept as the second layer under the bucket), compare-and-swap submit, ties to the defender, an expired
///   candidate finalized before any new submission.
///
/// Journal (KZO3, big-endian, 278 + 68 n bytes; outbound/kaspa-prover/primitives/src/relay.rs, U4):
///   "KZO3"(4) | K(32) | T(32) | T.daa(8) | B(32) | B.daa(8) | headers(4) | n_levels(1) |
///   8 x (level(1), count(4), attesting(4)) | target(20) | token_cov_id(32) | template_hash(32) | n_burns(1) |
///   n x (tx id(32), amount(8), tip(8), recipient(20))
contract KaspaRelayV3 {
    bytes4 private constant MAGIC = 0x4b5a4f33; // "KZO3"
    uint256 private constant HEADER_LEN = 278;
    uint256 private constant BURN_LEN = 68;

    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable IMAGE_ID;
    ISettlementV2 public immutable SETTLEMENT;
    bytes32 public immutable TOKEN_COV_ID;
    bytes32 public immutable TEMPLATE_HASH;
    uint8 public immutable CMP_LEVEL;
    uint32 public immutable FLOOR;
    uint32 public immutable ATTEST_FLOOR;
    uint64 public immutable ATTEST_UNIT;
    uint64 public immutable WINDOW_FLOOR;
    uint64 public immutable WINDOW_UNIT;

    bytes32 public checkpoint;
    uint64 public checkpointDaa;

    struct Candidate {
        bytes32 tip;
        uint64 tipDaa;
        uint32 count;
        uint32 attesting;
        uint64 deadline;
        uint64 window;
        bytes32 journalHash;
        address submitter;
    }

    Candidate public candidate;

    /// @notice A burn the relay owes: recorded once by `finalize`, paid down by `release` calls.
    struct Debt {
        address recipient;
        uint64 remaining; // amount not yet paid, tip included
        uint64 tipRemaining;
        address submitter;
        bool recorded;
    }

    mapping(bytes32 => Debt) public owed;
    /// @notice Sum of `remaining` over every owed burn: what the relay still has to pay out.
    uint64 public owedTotal;

    event Submitted(bytes32 indexed tip, uint64 tipDaa, uint32 count, uint32 attesting, uint64 amount, address indexed submitter, uint64 deadline, bytes journal);
    event Finalized(bytes32 indexed checkpoint, uint64 checkpointDaa, uint32 count, uint32 attesting, address indexed submitter);
    /// @notice A burn recorded as owed (once per burn, in the finalize of the journal that carried it).
    event Owed(bytes32 indexed txId, address indexed recipient, uint64 amount, uint64 tip, address indexed submitter);
    /// @notice An installment paid; `remaining` is what is still owed after it.
    event Paid(bytes32 indexed txId, uint64 paid, uint64 remaining);
    event PaidInFull(bytes32 indexed txId);
    /// @notice An installment attempted and nothing paid (bucket empty, recipient refused); still owed.
    event Deferred(bytes32 indexed txId, uint64 remaining);
    /// @notice A burn recorded for less than its journal amount: the vault holds less than the journal claims.
    ///         Honest burns never trigger this (tokens exist only for deposits); a forged journal is bounded by it.
    event Capped(bytes32 indexed txId, uint64 requested, uint64 recorded);
    event Skipped(bytes32 indexed txId, string reason);

    struct Params {
        bytes32 checkpoint;
        uint64 checkpointDaa;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint8 cmpLevel;
        uint32 floor;
        uint32 attestFloor;
        uint64 attestUnit;
        uint64 windowFloor;
        uint64 windowUnit;
    }

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, ISettlementV2 settlement, Params memory p) {
        require(address(verifier) != address(0) && address(settlement) != address(0), "relay: zero address");
        require(imageId != bytes32(0) && p.checkpoint != bytes32(0), "relay: zero id");
        require(p.tokenCovId != bytes32(0) && p.templateHash != bytes32(0), "relay: zero token");
        require(
            p.cmpLevel != 0 && p.floor != 0 && p.attestFloor != 0 && p.attestUnit != 0 && p.windowFloor != 0 && p.windowUnit != 0,
            "relay: zero param"
        );
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        SETTLEMENT = settlement;
        checkpoint = p.checkpoint;
        checkpointDaa = p.checkpointDaa;
        TOKEN_COV_ID = p.tokenCovId;
        TEMPLATE_HASH = p.templateHash;
        CMP_LEVEL = p.cmpLevel;
        FLOOR = p.floor;
        ATTEST_FLOOR = p.attestFloor;
        ATTEST_UNIT = p.attestUnit;
        WINDOW_FLOOR = p.windowFloor;
        WINDOW_UNIT = p.windowUnit;
    }

    // ------------------------------------------------------------------ the two formulas (v2, unchanged)

    function requiredAttest(uint256 amount) public view returns (uint32) {
        uint256 byAmount = (amount + ATTEST_UNIT - 1) / ATTEST_UNIT;
        uint256 r = byAmount > ATTEST_FLOOR ? byAmount : ATTEST_FLOOR;
        return r > type(uint32).max ? type(uint32).max : uint32(r);
    }

    function windowFor(uint256 amount) public view returns (uint64) {
        uint256 w = uint256(WINDOW_FLOOR) + amount * 3600 / WINDOW_UNIT;
        return w > type(uint64).max ? type(uint64).max : uint64(w);
    }

    // ------------------------------------------------------------------ journal (v2, unchanged)

    struct Journal {
        bytes32 k;
        bytes32 t;
        uint64 tDaa;
        bytes32 b;
        uint64 bDaa;
        uint32 headers;
        uint32 count;
        uint32 attesting;
        address target;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint8 nBurns;
        uint256 amount;
    }

    function parseJournal(bytes calldata j) public view returns (Journal memory out) {
        require(j.length >= HEADER_LEN && (j.length - HEADER_LEN) % BURN_LEN == 0, "relay: journal length");
        require(bytes4(j[0:4]) == MAGIC, "relay: journal magic");
        out.k = bytes32(j[4:36]);
        out.t = bytes32(j[36:68]);
        out.tDaa = uint64(bytes8(j[68:76]));
        out.b = bytes32(j[76:108]);
        out.bDaa = uint64(bytes8(j[108:116]));
        out.headers = uint32(bytes4(j[116:120]));
        uint8 nLevels = uint8(j[120]);
        require(nLevels >= 1 && nLevels <= 8, "relay: levels");
        bool found;
        for (uint256 i = 0; i < nLevels; i++) {
            uint256 o = 121 + 9 * i;
            if (uint8(j[o]) == CMP_LEVEL) {
                out.count = uint32(bytes4(j[o + 1:o + 5]));
                out.attesting = uint32(bytes4(j[o + 5:o + 9]));
                found = true;
            }
        }
        require(found, "relay: no count at CMP_LEVEL");
        out.target = address(bytes20(j[193:213]));
        out.tokenCovId = bytes32(j[213:245]);
        out.templateHash = bytes32(j[245:277]);
        out.nBurns = uint8(j[277]);
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

    // ------------------------------------------------------------------ submit (v2, unchanged)

    /// @param expectTip the tip of the candidate the caller saw (zero for none); the call reverts if it has changed
    function submit(bytes calldata seal, bytes calldata journal, bytes32 expectTip) external {
        Journal memory jn = parseJournal(journal);
        require(jn.k == checkpoint, "relay: journal does not start at the checkpoint");
        require(jn.target == address(this), "relay: journal target is not this relay");
        require(jn.tokenCovId == TOKEN_COV_ID && jn.templateHash == TEMPLATE_HASH, "relay: not this token");
        require(jn.tDaa > checkpointDaa, "relay: tip is not past the checkpoint");
        require(jn.count >= FLOOR, "relay: below the floor");
        require(jn.attesting >= requiredAttest(jn.amount), "relay: not enough attestation");
        VERIFIER.verify(seal, IMAGE_ID, sha256(journal));

        Candidate memory c = candidate;
        require(c.tip == expectTip, "relay: candidate changed");
        uint64 window = windowFor(jn.amount);
        if (c.tip != bytes32(0)) {
            require(block.timestamp < c.deadline, "relay: finalize the expired candidate first");
            require(jn.count > c.count, "relay: not heavier than the candidate");
            if (c.window > window) window = c.window;
        }
        uint64 deadline = uint64(block.timestamp) + window;
        candidate = Candidate({
            tip: jn.t,
            tipDaa: jn.tDaa,
            count: jn.count,
            attesting: jn.attesting,
            deadline: deadline,
            window: window,
            journalHash: sha256(journal),
            submitter: msg.sender
        });
        emit Submitted(jn.t, jn.tDaa, jn.count, jn.attesting, uint64(jn.amount), msg.sender, deadline, journal);
    }

    // ------------------------------------------------------------------ finalize: record as owed, then pay

    function finalize(bytes calldata journal) external {
        Candidate memory c = candidate;
        require(c.tip != bytes32(0), "relay: no candidate");
        require(block.timestamp >= c.deadline, "relay: window still open");
        require(sha256(journal) == c.journalHash, "relay: not the candidate's journal");
        Journal memory jn = parseJournal(journal);

        delete candidate;
        checkpoint = jn.t;
        checkpointDaa = jn.tDaa;
        emit Finalized(jn.t, jn.tDaa, jn.count, jn.attesting, c.submitter);

        for (uint256 i = 0; i < jn.nBurns; i++) {
            (bytes32 txId, uint64 amount, uint64 tip, address recipient) = burnAt(journal, i);
            if (owed[txId].recorded) {
                emit Skipped(txId, "already recorded");
                continue;
            }
            // What the relay may ever owe is what the vault holds and does not owe yet: every honest token is
            // backed by a deposit still outstanding, so for honest burns the room is never short. A forged
            // journal (an attacker who out-hashes Kaspa) is recorded for at most that room, so it can drain the
            // vault's present backing at the bucket's rate and never a deposit made after it.
            uint64 out = SETTLEMENT.outstanding();
            uint64 room = out > owedTotal ? out - owedTotal : 0;
            uint64 recorded = amount > room ? room : amount;
            if (recorded != amount) emit Capped(txId, amount, recorded);
            // tip <= amount is enforced by the guest; capped here too, so a burn can never pay more than its amount
            if (tip > recorded) tip = recorded;
            owed[txId] = Debt({recipient: recipient, remaining: recorded, tipRemaining: tip, submitter: c.submitter, recorded: true});
            owedTotal += recorded;
            emit Owed(txId, recipient, recorded, tip, c.submitter);
            if (recorded == 0) emit PaidInFull(txId);
            else _pay(txId);
        }
    }

    /// @notice Pay the next installment of an owed burn. Anyone may call; a burn paid in full is a no-op.
    function claim(bytes32 txId) external returns (uint64 paid) {
        require(owed[txId].recorded, "relay: not an owed burn");
        return _pay(txId);
    }

    /// @notice True once the burn is recorded and fully paid (the v2 meaning of settled).
    function settled(bytes32 txId) external view returns (bool) {
        Debt storage o = owed[txId];
        return o.recorded && o.remaining == 0;
    }

    function _pay(bytes32 txId) internal returns (uint64 paid) {
        Debt storage o = owed[txId];
        if (o.remaining == 0) return 0;
        paid = SETTLEMENT.release(txId, o.recipient, o.remaining, o.tipRemaining, o.submitter);
        if (paid == 0) {
            emit Deferred(txId, o.remaining);
            return 0;
        }
        require(paid <= o.remaining, "relay: overpaid");
        uint64 tipNow = paid < o.tipRemaining ? paid : o.tipRemaining;
        o.tipRemaining -= tipNow;
        o.remaining -= paid;
        owedTotal -= paid;
        emit Paid(txId, paid, o.remaining);
        if (o.remaining == 0) emit PaidInFull(txId);
    }
}
