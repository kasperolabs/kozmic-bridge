// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISettlement} from "./ISettlement.sol";

/// @notice The ERC-20 surface the vault uses. USDC's `transfer`/`transferFrom` revert when either side is
///         blacklisted; the vault relies on that (it never checks the blacklist itself).
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title UsdcVault: the Ethereum side of Kaspero Labs' USDC <-> Kaspa L1 bridge (U2, 2026-10-16).
/// @notice No owner, no pause, no upgrade. Two entries: `deposit` by anyone, `settle` by the relay only.
///         The deposit records are read by a RISC Zero guest (eth-prover v2, U3) that proves them against the
///         state root of a light-client-finalized block, together with the depositor's blacklist bit in the
///         token's own storage. The relay (KaspaRelay v2) calls `settle` from `finalize` for burns proven on
///         Kaspa (outbound guest v2, U4). Parameters: docs/USDC-PARAMETERS.md.
///
/// Storage layout (the guest hardcodes it; `forge inspect UsdcVault storage-layout` reproduces it;
/// `test/UsdcVault.t.sol` asserts it with vm.load):
///
///   slot 0            nonce        uint64, low 8 bytes of the word
///   slot 1            deposits     mapping(uint64 => Deposit) base slot (holds nothing itself)
///   k0 = keccak256(abi.encode(uint256(n), uint256(1)))     deposits[n] word 0:
///                                                            bits 0..63    amount        (uint64, token base units)
///                                                            bits 64..71   kaspaVersion  (uint8: 0 P2PK, 8 P2SH)
///                                                            bits 72..231  depositor     (address)
///                                                            bits 232..255 zero
///   k0 + 1                                                  deposits[n] word 1: kaspaPayload (bytes32, whole word)
///   slot 2            settled      mapping(bytes32 => bool): Kaspa burn tx ids already paid
///   slot 3            bits 0..63   outstanding (uint64): deposited minus settled, what the cap compares against
///                     bits 64..223 relay (address): set once by the factory in the deployment tx, then frozen
///                     (the compiler packs the two; there is no slot 4)
///
/// Immutables (in code, no slot): TOKEN, FACTORY, DEPLOY_TIME, CAP0, CEILING, DOUBLING, MIN_DEPOSIT.
///
/// Why `relay` is storage and not an immutable: the vault and the relay each need the other's address, and
/// under CREATE2 an address depends on the init code that would carry it. The factory deploys the vault, then
/// the relay (whose init code carries the vault's address), then calls `setRelay` once, all in one transaction.
/// Only the factory can call it and only while the slot is zero, so after that transaction nothing can change it.
///
/// The guest refuses a record whose bits 232..255 are nonzero, whose amount is zero, whose version is not 0 or 8,
/// or whose payload is zero; `deposit` enforces the same, so every record the contract writes is provable.
///
/// Cap: `outstanding + amount <= cap(block.timestamp)` with
///   cap(t) = min(CEILING, CAP0 * 2^((t - DEPLOY_TIME) / DOUBLING)).
/// It is a balance cap (exits free room), on a schedule nobody can change. `outstanding` is tracked, not read
/// from the token, so USDC sent here directly (or frozen inside by Circle after a skipped deposit) never alters
/// the room; a deposit the guest skips (depositor blacklisted at the finalized block) is never settled and holds
/// its room forever, which is the correct accounting: that USDC is in the vault backing nothing.
contract UsdcVault is ISettlement {
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
    /// @notice Smallest deposit, token base units (griefing bound on the Kaspa-side mint cost).
    uint64 public immutable MIN_DEPOSIT;

    /// @notice Number of deposits so far. The first deposit has nonce 1; nonce 0 never exists.
    uint64 public nonce;
    mapping(uint64 => Deposit) public deposits;
    mapping(bytes32 => bool) public settled;
    uint64 public outstanding;
    address public relay;

    event Deposited(uint64 indexed nonce, address indexed from, uint64 amount, bytes kaspaSpk);
    event Settled(bytes32 indexed txId, address indexed recipient, uint64 amount, uint64 tip, address indexed submitter, bool tipPaid);
    event SettleRefused(bytes32 indexed txId, address indexed recipient, uint64 amount, string reason);

    constructor(IERC20 token, address factory, uint64 cap0, uint64 ceiling, uint64 doubling, uint64 minDeposit) {
        require(address(token) != address(0) && factory != address(0), "vault: zero address");
        require(cap0 != 0 && ceiling >= cap0 && doubling != 0 && minDeposit != 0, "vault: bad parameter");
        TOKEN = token;
        FACTORY = factory;
        DEPLOY_TIME = uint64(block.timestamp);
        CAP0 = cap0;
        CEILING = ceiling;
        DOUBLING = doubling;
        MIN_DEPOSIT = minDeposit;
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

    // ------------------------------------------------------------------ deposit

    /// @param amount   token base units (6 decimals for USDC)
    /// @param kaspaSpk 33 bytes: version byte (0 = P2PK Schnorr, 8 = P2SH) + 32-byte payload
    function deposit(uint64 amount, bytes calldata kaspaSpk) external returns (uint64 n) {
        require(amount >= MIN_DEPOSIT, "vault: below the minimum deposit");
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

    // ------------------------------------------------------------------ settle (relay only)

    /// @inheritdoc ISettlement
    /// @dev Pays `amount - tip` to the recipient and `tip` to the submitter. A refused recipient transfer (USDC
    ///      reverts for a blacklisted `to`) returns false and changes nothing, so the burn stays claimable. A
    ///      refused tip transfer (blacklisted submitter) forfeits the tip, which stays in the vault; the burn is
    ///      still settled, since the recipient has been paid.
    function settle(bytes32 txId, address recipient, uint64 amount, uint64 tip, address submitter)
        external
        returns (bool)
    {
        require(msg.sender == relay && relay != address(0), "vault: not the relay");
        if (settled[txId]) {
            emit SettleRefused(txId, recipient, amount, "already settled");
            return false;
        }
        if (tip > amount || amount > outstanding) {
            emit SettleRefused(txId, recipient, amount, "amount");
            return false;
        }
        settled[txId] = true;
        outstanding -= amount;

        if (!_pay(recipient, amount - tip)) {
            settled[txId] = false;
            outstanding += amount;
            emit SettleRefused(txId, recipient, amount, "recipient refused");
            return false;
        }
        bool tipPaid = tip == 0 || _pay(submitter, tip);
        emit Settled(txId, recipient, amount, tip, submitter, tipPaid);
        return true;
    }

    /// @dev A transfer that reverts (blacklist, paused token) or returns false is reported as false, never
    ///      bubbled, so one bad burn cannot block a journal.
    function _pay(address to, uint64 amount) internal returns (bool) {
        if (amount == 0) return true;
        (bool ok, bytes memory ret) =
            address(TOKEN).call(abi.encodeCall(IERC20.transfer, (to, uint256(amount))));
        return ok && (ret.length == 0 || abi.decode(ret, (bool)));
    }
}
