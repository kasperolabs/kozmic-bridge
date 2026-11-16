// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ISettlement: what a KaspaRelay v2 does with a finalized burn.
/// @notice One call per burn. The implementation decides what "settling" means: WrappedKAS mints, UsdcVault
///         releases. It must NOT revert for a burn it cannot settle (a blacklisted recipient, say): it returns
///         false and the relay leaves that burn unmarked, so it stays claimable by a later journal while every
///         other burn in the same journal settles. `tip <= amount` is guaranteed by the guest.
interface ISettlement {
    function settle(bytes32 txId, address recipient, uint64 amount, uint64 tip, address submitter)
        external
        returns (bool ok);
}
