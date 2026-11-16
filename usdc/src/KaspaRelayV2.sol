// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlement} from "./ISettlement.sol";

/// @title KaspaRelayV2: Ethereum verifies Kaspa proof-of-work and settles burns of a KCC-20 token on Kaspa L1.
/// @notice No owner, no pause, no upgrade. Built from v1 (relay/src/KaspaRelay.sol, relay/README.md) with four
///         changes decided in docs/USDC-PARAMETERS.md and docs/RELAY-V2-BRIEF.md:
///
///   1. Settlement target. The relay does not mint; it hands each finalized burn to an immutable `ISettlement`
///      (UsdcVault releases USDC; a WrappedKAS would mint). A target that cannot settle a burn returns false
///      and the burn stays claimable; the rest of the journal settles.
///   2. Protection follows the money. Depth and window are computed per submission from A, the sum of the
///      journal's burn amounts: attesting >= max(ATTEST_FLOOR, ceil(A / ATTEST_UNIT)) and
///      window = WINDOW_FLOOR + A * 3600 / WINDOW_UNIT. Linear in A, so splitting a fake burn buys nothing.
///      A replacement restarts the deadline at now + max(its window, the displaced window): a smaller heavier
///      journal can never shorten a big exit's window.
///   3. Compare-and-swap submit. `submit(seal, journal, expectTip)` reverts unless the live candidate's tip is
///      `expectTip` (zero for none), so honest robots cannot leapfrog each other by accident.
///   4. Token burns. The journal (KZO3) carries the burned token's covenant id and template hash; the relay
///      pins both, so a burn of another token cannot be presented here.
///
/// Journal (KZO3, big-endian, 278 + 68 n bytes; outbound/kaspa-prover/primitives/src/relay.rs, U4):
///   "KZO3"(4) | K(32) | T(32) | T.daa(8) | B(32) | B.daa(8) | headers(4) | n_levels(1) |
///   8 x (level(1), count(4), attesting(4)) | target(20) | token_cov_id(32) | template_hash(32) | n_burns(1) |
///   n x (tx id(32), amount(8), tip(8), recipient(20))
///
/// Everything else is v1: K, T, B, the ladders, the attestation, the floor, ties to the defender, an expired
/// candidate finalized before any new submission, burns settled once per tx id.
contract KaspaRelayV2 {
    bytes4 private constant MAGIC = 0x4b5a4f33; // "KZO3"
    uint256 private constant HEADER_LEN = 278;
    uint256 private constant BURN_LEN = 68;

    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable IMAGE_ID;
    ISettlement public immutable SETTLEMENT;
    /// @notice KCC-20 covenant id of the token whose burns this relay settles.
    bytes32 public immutable TOKEN_COV_ID;
    /// @notice KCC-20 template hash of that token (the token class).
    bytes32 public immutable TEMPLATE_HASH;
    uint8 public immutable CMP_LEVEL;
    /// @notice Minimum superblocks at CMP_LEVEL since the checkpoint (rate limit, not security).
    uint32 public immutable FLOOR;
    /// @notice Fewest attesting superblocks any submission needs.
    uint32 public immutable ATTEST_FLOOR;
    /// @notice Asset base units of release per required attester above the floor.
    uint64 public immutable ATTEST_UNIT;
    /// @notice Shortest window, seconds.
    uint64 public immutable WINDOW_FLOOR;
    /// @notice Asset base units of release per extra hour of window.
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
    /// @notice Burn tx ids this relay has settled (the settlement target keeps its own record too).
    mapping(bytes32 => bool) public settled;

    event Submitted(bytes32 indexed tip, uint64 tipDaa, uint32 count, uint32 attesting, uint64 amount, address indexed submitter, uint64 deadline, bytes journal);
    event Finalized(bytes32 indexed checkpoint, uint64 checkpointDaa, uint32 count, uint32 attesting, address indexed submitter);
    event Settled(bytes32 indexed txId, address indexed recipient, uint64 amount, uint64 tip, address indexed submitter);
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

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, ISettlement settlement, Params memory p) {
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

    // ------------------------------------------------------------------ the two formulas

    /// @notice Attesting superblocks a journal releasing `amount` base units must carry.
    function requiredAttest(uint256 amount) public view returns (uint32) {
        uint256 byAmount = (amount + ATTEST_UNIT - 1) / ATTEST_UNIT;
        uint256 r = byAmount > ATTEST_FLOOR ? byAmount : ATTEST_FLOOR;
        return r > type(uint32).max ? type(uint32).max : uint32(r);
    }

    /// @notice Window, in seconds, for a journal releasing `amount` base units.
    function windowFor(uint256 amount) public view returns (uint64) {
        uint256 w = uint256(WINDOW_FLOOR) + amount * 3600 / WINDOW_UNIT;
        return w > type(uint64).max ? type(uint64).max : uint64(w);
    }

    // ------------------------------------------------------------------ journal

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
        uint256 amount; // sum of the burns, base units
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

    // ------------------------------------------------------------------ submit / finalize

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
            if (settled[txId]) {
                emit Skipped(txId, "already settled");
                continue;
            }
            // tip <= amount is enforced by the guest
            if (!SETTLEMENT.settle(txId, recipient, amount, tip, c.submitter)) {
                emit Skipped(txId, "settlement refused");
                continue;
            }
            settled[txId] = true;
            emit Settled(txId, recipient, amount, tip, c.submitter);
        }
    }
}
