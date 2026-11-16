// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISettlementV2} from "./ISettlementV2.sol";

/// @notice The ERC-20 surface the vault uses. USDC's `transfer`/`transferFrom` revert when either side is
///         blacklisted; the vault relies on that (it never checks the blacklist itself).
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title UsdcVaultV2: the Ethereum side of Kaspero Labs' USDC <-> Kaspa L1 bridge, rehearsal #2 (Tipsy.k).
/// @notice No owner, no pause, no upgrade. UsdcVault (U2) plus the two changes of REHEARSAL-2-PLAN section 2.1:
///
///   1. A release bucket. `BUCKET_MAX` is the most any one proof can move out of the vault; the bucket refills
///      continuously at `REFILL_PER_DAY` per day, so that is the most a day of proofs can move. A forged journal
///      (an attacker who out-hashes Kaspa) wins at most `BUCKET_MAX` per proof and `REFILL_PER_DAY` per day,
///      whatever the vault holds. One storage word: the time the bucket will be full again (`bucketFullAt`);
///      a release pushes it forward by the seconds its amount takes to refill (rounded up). No calendar
///      boundary, so no double day at midnight, and no accumulated rounding.
///   2. `MAX_DEPOSIT`: a deposit above it reverts before `transferFrom`, so nothing moves. The Kaspa covenant
///      pins the same number as `max_mint`, so a forged inbound journal mints at most 4 x MAX_DEPOSIT per proof.
///
/// `release` (relay only) replaces `settle`: it pays `min(amount, available, outstanding)` and returns what it
/// paid, tip first to the submitter, the rest to the recipient; a recipient whose USDC transfer reverts
/// (blacklisted) is paid nothing and the bucket is not spent. The relay (KaspaRelayV3) records every burn as owed
/// and pays it in installments through `release`, so no burn ever needs a second proof.
///
/// Storage layout (the inbound guest hardcodes slots 0 and 1; they are byte-identical to UsdcVault's, see
/// usdc/LAYOUT.md; `test/UsdcVaultV2.t.sol` asserts it with vm.load):
///
///   slot 0            nonce        uint64, low 8 bytes of the word
///   slot 1            deposits     mapping(uint64 => Deposit) base slot (holds nothing itself)
///   k0 = keccak256(abi.encode(uint256(n), uint256(1)))     deposits[n] word 0: amount | kaspaVersion | depositor
///   k0 + 1                                                  deposits[n] word 1: kaspaPayload
///   slot 2            bucketFullAt (uint256): the timestamp at which the bucket is full again
///   slot 3            bits 0..63   outstanding (uint64), bits 64..223 relay (address): as UsdcVault slot 3
///
/// Unchanged from UsdcVault: the cap schedule (CAP0 x 2^weeks up to CEILING, a balance cap), MIN_DEPOSIT, the
/// deposit record, `setRelay` by the factory once in the deployment transaction.
contract UsdcVaultV2 is ISettlementV2 {
    struct Deposit {
        uint64 amount;
        uint8 kaspaVersion;
        address depositor;
        bytes32 kaspaPayload;
    }

    IERC20 public immutable TOKEN;
    address public immutable FACTORY;
    uint64 public immutable DEPLOY_TIME;
    /// @notice Cap at deployment, token base units.
    uint64 public immutable CAP0;
    /// @notice The cap never exceeds this, token base units.
    uint64 public immutable CEILING;
    /// @notice Seconds per doubling of the cap.
    uint64 public immutable DOUBLING;
    /// @notice Smallest deposit, token base units.
    uint64 public immutable MIN_DEPOSIT;
    /// @notice The most one release (one proof) can pay, token base units; the bucket's size.
    uint64 public immutable BUCKET_MAX;
    /// @notice The bucket refills by this much per day, token base units; the daily cap on releases.
    uint64 public immutable REFILL_PER_DAY;
    /// @notice Largest deposit, token base units; the covenant's `max_mint`. At most BUCKET_MAX, so any honest
    ///         deposit can exit in one installment.
    uint64 public immutable MAX_DEPOSIT;

    /// @notice Number of deposits so far. The first deposit has nonce 1; nonce 0 never exists.
    uint64 public nonce;
    mapping(uint64 => Deposit) public deposits;
    /// @notice When the bucket is full again (a timestamp). In the past, or now, means full. A whole word, so
    ///         `outstanding` and `relay` stay packed in slot 3 exactly as in UsdcVault.
    uint256 public bucketFullAt;
    uint64 public outstanding;
    address public relay;

    event Deposited(uint64 indexed nonce, address indexed from, uint64 amount, bytes kaspaSpk);
    /// @notice An installment paid: `paid` base units left the vault, `tip` of them to the submitter.
    event Released(bytes32 indexed txId, address indexed recipient, uint64 paid, uint64 tip, address indexed submitter, bool tipPaid);
    /// @notice Nothing paid this time; the relay keeps the burn owed.
    event Refused(bytes32 indexed txId, address indexed recipient, uint64 amount, string reason);

    constructor(
        IERC20 token,
        address factory,
        uint64 cap0,
        uint64 ceiling,
        uint64 doubling,
        uint64 minDeposit,
        uint64 bucketMax,
        uint64 refillPerDay,
        uint64 maxDeposit
    ) {
        require(address(token) != address(0) && factory != address(0), "vault: zero address");
        require(cap0 != 0 && ceiling >= cap0 && doubling != 0 && minDeposit != 0, "vault: bad parameter");
        require(bucketMax != 0 && refillPerDay != 0, "vault: bad bucket");
        require(maxDeposit >= minDeposit && maxDeposit <= bucketMax, "vault: bad max deposit");
        TOKEN = token;
        FACTORY = factory;
        DEPLOY_TIME = uint64(block.timestamp);
        CAP0 = cap0;
        CEILING = ceiling;
        DOUBLING = doubling;
        MIN_DEPOSIT = minDeposit;
        BUCKET_MAX = bucketMax;
        REFILL_PER_DAY = refillPerDay;
        MAX_DEPOSIT = maxDeposit;
        bucketFullAt = block.timestamp; // full at birth
    }

    /// @notice Called by the factory once, in the transaction that deploys the pair. Frozen afterwards.
    function setRelay(address relay_) external {
        require(msg.sender == FACTORY, "vault: not the factory");
        require(relay == address(0) && relay_ != address(0), "vault: relay already set");
        relay = relay_;
    }

    // ------------------------------------------------------------------ cap

    /// @notice The cap at time `t`: CAP0 doubled once per DOUBLING since deployment, never above CEILING.
    function capAt(uint64 t) public view returns (uint64) {
        if (t < DEPLOY_TIME) return CAP0;
        uint256 periods = (t - DEPLOY_TIME) / DOUBLING;
        if (periods >= 64) return CEILING;
        uint256 c = uint256(CAP0) << periods;
        return c >= CEILING ? CEILING : uint64(c);
    }

    function cap() external view returns (uint64) {
        return capAt(uint64(block.timestamp));
    }

    /// @notice Room left under the cap right now.
    function room() external view returns (uint64) {
        uint64 c = capAt(uint64(block.timestamp));
        return c > outstanding ? c - outstanding : 0;
    }

    // ------------------------------------------------------------------ the bucket

    /// @notice What the bucket can release at time `t`: BUCKET_MAX minus the deficit still refilling.
    function availableAt(uint64 t) public view returns (uint64) {
        uint256 fullAt = bucketFullAt;
        if (t >= fullAt) return BUCKET_MAX;
        uint256 deficit = (fullAt - t) * REFILL_PER_DAY / 86400;
        return deficit >= BUCKET_MAX ? 0 : BUCKET_MAX - uint64(deficit);
    }

    /// @notice What the bucket can release right now.
    function available() public view returns (uint64) {
        return availableAt(uint64(block.timestamp));
    }

    /// @dev Spend `amount` from the bucket: push the full-again time forward by the seconds that amount takes
    ///      to refill, rounded up (the rounding is against the spender, at most one second of refill).
    function _spend(uint64 amount) internal {
        uint256 base = bucketFullAt > block.timestamp ? bucketFullAt : block.timestamp;
        uint256 secs = (uint256(amount) * 86400 + REFILL_PER_DAY - 1) / REFILL_PER_DAY;
        bucketFullAt = base + secs;
    }

    // ------------------------------------------------------------------ deposit

    /// @param amount   token base units (6 decimals for USDC); MIN_DEPOSIT <= amount <= MAX_DEPOSIT
    /// @param kaspaSpk 33 bytes: version byte (0 = P2PK Schnorr, 8 = P2SH) + 32-byte payload
    function deposit(uint64 amount, bytes calldata kaspaSpk) external returns (uint64 n) {
        require(amount >= MIN_DEPOSIT, "vault: below the minimum deposit");
        require(amount <= MAX_DEPOSIT, "vault: above the maximum deposit");
        require(kaspaSpk.length == 33, "vault: kaspaSpk must be 33 bytes");
        uint8 version = uint8(kaspaSpk[0]);
        require(version == 0 || version == 8, "vault: kaspa version must be 0 or 8");
        bytes32 payload = bytes32(kaspaSpk[1:33]);
        require(payload != bytes32(0), "vault: zero kaspa payload");
        uint256 newOutstanding = uint256(outstanding) + amount;
        require(newOutstanding <= capAt(uint64(block.timestamp)), "vault: over the cap");

        // USDC reverts here if msg.sender is blacklisted (FiatTokenV2_2 notBlacklisted on transferFrom).
        require(TOKEN.transferFrom(msg.sender, address(this), amount), "vault: transferFrom failed");

        outstanding = uint64(newOutstanding);
        n = ++nonce;
        deposits[n] = Deposit({amount: amount, kaspaVersion: version, depositor: msg.sender, kaspaPayload: payload});
        emit Deposited(n, msg.sender, amount, kaspaSpk);
    }

    // ------------------------------------------------------------------ release (relay only)

    /// @inheritdoc ISettlementV2
    /// @dev Pays `paid = min(amount, available(), outstanding)`: the tip (at most `paid`) to the submitter, the
    ///      rest to the recipient, and only when the rest is more than zero (an installment that would be all
    ///      tip is refused: the recipient is paid before anyone else). A recipient transfer that reverts (USDC's
    ///      blacklist) pays nothing, spends nothing and returns 0: the relay keeps the burn owed and `claim`
    ///      retries later. A refused tip transfer (blacklisted submitter) forfeits the tip, which stays in the
    ///      vault; the installment still counts as paid, since the recipient has been paid.
    function release(bytes32 txId, address recipient, uint64 amount, uint64 tip, address submitter)
        external
        returns (uint64 paid)
    {
        require(msg.sender == relay && relay != address(0), "vault: not the relay");
        if (amount == 0 || tip > amount) {
            emit Refused(txId, recipient, amount, "amount");
            return 0;
        }
        uint64 avail = available();
        paid = amount;
        if (paid > avail) paid = avail;
        if (paid > outstanding) paid = outstanding;
        if (paid == 0) {
            emit Refused(txId, recipient, amount, avail == 0 ? "bucket empty" : "nothing outstanding");
            return 0;
        }
        uint64 tipNow = tip > paid ? paid : tip;
        uint64 toRecipient = paid - tipNow;
        if (toRecipient == 0) {
            // the bucket holds less than the tip: an installment must reach the recipient before any tip is paid
            emit Refused(txId, recipient, amount, "bucket below the tip");
            return 0;
        }
        if (!_pay(recipient, toRecipient)) {
            emit Refused(txId, recipient, amount, "recipient refused");
            return 0;
        }
        bool tipPaid = tipNow == 0 || _pay(submitter, tipNow);
        outstanding -= paid;
        _spend(paid);
        emit Released(txId, recipient, paid, tipNow, submitter, tipPaid);
    }

    /// @dev A transfer that reverts (blacklist, paused token) or returns false is reported as false, never
    ///      bubbled, so one bad burn cannot block a journal.
    function _pay(address to, uint64 amount) internal returns (bool) {
        if (amount == 0) return true;
        (bool ok, bytes memory ret) = address(TOKEN).call(abi.encodeCall(IERC20.transfer, (to, uint256(amount))));
        return ok && (ret.length == 0 || abi.decode(ret, (bool)));
    }
}
