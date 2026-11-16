// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {ISettlementV3} from "./ISettlementV3.sol";

/// @notice The ERC-20 surface the vault uses. USDC's `transfer`/`transferFrom` revert when either side is
///         blacklisted; the vault relies on that (it never checks the blacklist itself).
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title UsdcVaultV4: the Ethereum side of Kaspero Labs' USDC <-> Kaspa L1 bridge, the USDC.k #1 vault.
/// @notice No owner, no pause, no upgrade, and nothing that can touch a release. UsdcVaultV3 with two additions
///   (sprint 3, 2026-11-08) and nothing else:
///
///   - a fee of FEE_BPS on every release, taken from the recipient's part and accrued in `feeOwed`; anyone may
///     sweep it to FEE_ADDRESS with `claimFees`. The fee is never paid inside a release, so a fee address that
///     cannot receive (blacklisted, or a contract that refuses) stops nothing but the fee;
///   - a one-way close of deposits: whoever knows the preimage of CLOSE_HASH may call `closeDeposits` once; from
///     then on `deposit` refuses and `room` is 0. Releases, the bucket and `claim` are untouched by it. It can only
///     shrink the bridge: a stolen preimage forces a wind-down of this instance, nothing else.
///
///   Deposits, the cap schedule, MAX_DEPOSIT, the release bucket and `release` (recipient part and tip part as the
///   relay computed them, F6; its own accounting debited before any transfer, F7) are V3's, and so is the storage
///   layout of slots 0 to 3 (the inbound guest reads slots 0 and 1):
///
///   slot 0            nonce        uint64, low 8 bytes of the word
///   slot 1            deposits     mapping(uint64 => Deposit) base slot
///   slot 2            bucketFullAt (uint256): the timestamp at which the bucket is full again
///   slot 3            bits 0..63   outstanding (uint64), bits 64..223 relay (address), bit 224 depositsClosed
///   slot 4            feeOwed      uint64
contract UsdcVaultV4 is ISettlementV3 {
    struct Deposit {
        uint64 amount;
        uint8 kaspaVersion;
        address depositor;
        bytes32 kaspaPayload;
    }

    IERC20 public immutable TOKEN;
    address public immutable FACTORY;
    uint64 public immutable DEPLOY_TIME;
    uint64 public immutable CAP0;
    uint64 public immutable CEILING;
    uint64 public immutable DOUBLING;
    uint64 public immutable MIN_DEPOSIT;
    uint64 public immutable BUCKET_MAX;
    uint64 public immutable REFILL_PER_DAY;
    uint64 public immutable MAX_DEPOSIT;
    /// @notice The release fee, in basis points of the recipient's part of each installment.
    uint16 public immutable FEE_BPS;
    /// @notice Where `claimFees` sends the accrued fees. Fixed forever; choose it once.
    address public immutable FEE_ADDRESS;
    /// @notice sha256 of the preimage that closes deposits for good.
    bytes32 public immutable CLOSE_HASH;

    uint64 public nonce;
    mapping(uint64 => Deposit) public deposits;
    uint256 public bucketFullAt;
    uint64 public outstanding;
    address public relay;
    bool public depositsClosed;
    uint64 public feeOwed;

    event Deposited(uint64 indexed nonce, address indexed from, uint64 amount, bytes kaspaSpk);
    /// @notice An installment paid: `paid` base units left the backing, `tip` of them to the submitter, `fee` of them
    ///         accrued for FEE_ADDRESS, the rest to the recipient.
    event Released(bytes32 indexed txId, address indexed recipient, uint64 paid, uint64 tip, uint64 fee, address indexed submitter, bool tipPaid);
    /// @notice Nothing paid this time; the relay keeps the burn owed.
    event Refused(bytes32 indexed txId, address indexed recipient, uint64 amount, string reason);
    event FeesClaimed(address indexed to, uint64 amount);
    event DepositsClosed(address indexed by);

    constructor(
        IERC20 token,
        address factory,
        uint64 cap0,
        uint64 ceiling,
        uint64 doubling,
        uint64 minDeposit,
        uint64 bucketMax,
        uint64 refillPerDay,
        uint64 maxDeposit,
        uint16 feeBps,
        address feeAddress,
        bytes32 closeHash
    ) {
        require(address(token) != address(0) && factory != address(0), "vault: zero address");
        require(cap0 != 0 && ceiling >= cap0 && doubling != 0 && minDeposit != 0, "vault: bad parameter");
        require(bucketMax != 0 && refillPerDay != 0, "vault: bad bucket");
        require(maxDeposit >= minDeposit && maxDeposit <= bucketMax, "vault: bad max deposit");
        require(feeBps <= 1_000 && (feeBps == 0 || feeAddress != address(0)), "vault: bad fee");
        require(closeHash != bytes32(0), "vault: zero close hash");
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
        FEE_BPS = feeBps;
        FEE_ADDRESS = feeAddress;
        CLOSE_HASH = closeHash;
        bucketFullAt = block.timestamp;
    }

    /// @notice Called by the factory once, in the transaction that deploys the pair. Frozen afterwards.
    function setRelay(address relay_) external {
        require(msg.sender == FACTORY, "vault: not the factory");
        require(relay == address(0) && relay_ != address(0), "vault: relay already set");
        relay = relay_;
    }

    // ------------------------------------------------------------------ cap (V2)

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

    /// @notice What may still be deposited now; 0 once deposits are closed.
    function room() external view returns (uint64) {
        if (depositsClosed) return 0;
        uint64 c = capAt(uint64(block.timestamp));
        return c > outstanding ? c - outstanding : 0;
    }

    // ------------------------------------------------------------------ the bucket (V2)

    function availableAt(uint64 t) public view returns (uint64) {
        uint256 fullAt = bucketFullAt;
        if (t >= fullAt) return BUCKET_MAX;
        uint256 deficit = (fullAt - t) * REFILL_PER_DAY / 86400;
        return deficit >= BUCKET_MAX ? 0 : BUCKET_MAX - uint64(deficit);
    }

    function available() public view returns (uint64) {
        return availableAt(uint64(block.timestamp));
    }

    function _spend(uint64 amount) internal {
        uint256 base = bucketFullAt > block.timestamp ? bucketFullAt : block.timestamp;
        uint256 secs = (uint256(amount) * 86400 + REFILL_PER_DAY - 1) / REFILL_PER_DAY;
        bucketFullAt = base + secs;
    }

    // ------------------------------------------------------------------ deposit (V2, plus the close)

    function deposit(uint64 amount, bytes calldata kaspaSpk) external returns (uint64 n) {
        require(!depositsClosed, "vault: deposits are closed");
        require(amount >= MIN_DEPOSIT, "vault: below the minimum deposit");
        require(amount <= MAX_DEPOSIT, "vault: above the maximum deposit");
        require(kaspaSpk.length == 33, "vault: kaspaSpk must be 33 bytes");
        uint8 version = uint8(kaspaSpk[0]);
        require(version == 0 || version == 8, "vault: kaspa version must be 0 or 8");
        bytes32 payload = bytes32(kaspaSpk[1:33]);
        require(payload != bytes32(0), "vault: zero kaspa payload");
        uint256 newOutstanding = uint256(outstanding) + amount;
        require(newOutstanding <= capAt(uint64(block.timestamp)), "vault: over the cap");

        require(TOKEN.transferFrom(msg.sender, address(this), amount), "vault: transferFrom failed");

        outstanding = uint64(newOutstanding);
        n = ++nonce;
        deposits[n] = Deposit({amount: amount, kaspaVersion: version, depositor: msg.sender, kaspaPayload: payload});
        emit Deposited(n, msg.sender, amount, kaspaSpk);
    }

    /// @notice Close deposits for good. Whoever presents the preimage of CLOSE_HASH; once.
    function closeDeposits(bytes calldata preimage) external {
        require(!depositsClosed, "vault: already closed");
        require(sha256(preimage) == CLOSE_HASH, "vault: not the close preimage");
        depositsClosed = true;
        emit DepositsClosed(msg.sender);
    }

    // ------------------------------------------------------------------ release (relay only), v3 plus the fee

    /// @inheritdoc ISettlementV3
    function release(bytes32 txId, address recipient, uint64 toRecipient, address submitter, uint64 toTip) external returns (bool) {
        require(msg.sender == relay && relay != address(0), "vault: not the relay");
        uint64 p = toRecipient + toTip;
        require(p > 0, "vault: empty installment");
        require(p <= available() && p <= outstanding, "vault: installment above the bucket or outstanding");
        uint64 fee = uint64(uint256(toRecipient) * FEE_BPS / 10_000);
        // F7: the accounting moves first; a transfer that calls back finds it already done
        uint256 fullAtBefore = bucketFullAt;
        outstanding -= p;
        _spend(p);
        feeOwed += fee;
        if (!_pay(recipient, toRecipient - fee)) {
            outstanding += p;
            bucketFullAt = fullAtBefore;
            feeOwed -= fee;
            emit Refused(txId, recipient, p, "recipient refused");
            return false;
        }
        bool tipPaid = _pay(submitter, toTip);
        if (!tipPaid) feeOwed += toTip; // F18: a refused tip (blacklisted prover) is not stranded; balance == outstanding + feeOwed
        emit Released(txId, recipient, p, toTip, fee, submitter, tipPaid);
        return true;
    }

    /// @notice Send the accrued fees to FEE_ADDRESS. Anyone may call; false (and nothing moved) when the transfer
    ///         is refused, in which case the fees stay accrued and releases go on regardless.
    function claimFees() external returns (bool) {
        uint64 f = feeOwed;
        if (f == 0) return true;
        feeOwed = 0;
        if (!_pay(FEE_ADDRESS, f)) {
            feeOwed = f;
            return false;
        }
        emit FeesClaimed(FEE_ADDRESS, f);
        return true;
    }

    /// @dev A transfer that reverts (blacklist, paused token) or returns false is reported as false, never bubbled.
    function _pay(address to, uint64 amount) internal returns (bool) {
        if (amount == 0) return true;
        (bool ok, bytes memory ret) = address(TOKEN).call(abi.encodeCall(IERC20.transfer, (to, uint256(amount))));
        return ok && (ret.length == 0 || abi.decode(ret, (bool)));
    }
}
