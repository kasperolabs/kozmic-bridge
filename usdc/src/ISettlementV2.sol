// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ISettlementV2: what a KaspaRelay v3 does with a burn it owes (Tipsy.k, REHEARSAL-2-PLAN section 2.2).
/// @notice One call per installment. `release` pays as much of `amount` as the target can pay right now (its
///         release bucket, what is outstanding, the recipient's blacklist bit) and RETURNS WHAT IT PAID, tip
///         included; the relay keeps the remainder owed and tries again on `claim`. It must NOT revert for a burn
///         it cannot pay: it returns 0 and changes nothing. The tip is paid first, out of the first installment
///         that has room for it, to `submitter`; `tip <= amount` is guaranteed by the relay.
interface ISettlementV2 {
    function release(bytes32 txId, address recipient, uint64 amount, uint64 tip, address submitter)
        external
        returns (uint64 paid);
    /// @notice Base units deposited and not yet released: the most that honest burns, all together, can ever be owed.
    function outstanding() external view returns (uint64);
}
