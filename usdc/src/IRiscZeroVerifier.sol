// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

/// @notice The one call the relay makes on RISC Zero's verifier (router or Groth16 verifier, same ABI).
///         Reverts on an invalid seal.
interface IRiscZeroVerifier {
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}
