// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

/// @title ISettlementV3: what a KaspaRelay v4 does with a burn it owes (docs/V4-DESIGN.md sections 7 and 8).
/// @notice The relay decides each installment and its split; the settlement only checks it fits and moves the money.
///   `release` pays `toRecipient` to the recipient and `toTip` to the submitter as one installment of
///   `toRecipient + toTip`. It debits its own accounting before any transfer (F7). If the recipient's transfer fails
///   (USDC's blacklist), it restores that accounting and returns false: nothing moved, nothing spent. A refused tip
///   transfer forfeits the tip (it stays in the vault) and the installment still counts. It reverts when the
///   installment is larger than the bucket or what is outstanding; the relay reads both first, so an honest relay
///   never meets that.
interface ISettlementV3 {
    function release(bytes32 txId, address recipient, uint64 toRecipient, address submitter, uint64 toTip) external returns (bool);
    /// @notice Base units deposited and not yet released.
    function outstanding() external view returns (uint64);
    /// @notice What the release bucket can pay right now.
    function available() external view returns (uint64);
}
