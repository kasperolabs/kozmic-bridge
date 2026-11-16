// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";

/// @notice Accepts a seal iff it equals keccak256(imageId, journalDigest) (so tests can forge "valid" seals and
///         tampered ones), unless `rejectAll` is set.
contract MockVerifier is IRiscZeroVerifier {
    bool public rejectAll;

    function setRejectAll(bool r) external {
        rejectAll = r;
    }

    function sealFor(bytes32 imageId, bytes32 journalDigest) external pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(imageId, journalDigest)));
    }

    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view {
        require(!rejectAll, "verifier: rejected");
        require(seal.length == 32 && bytes32(seal) == keccak256(abi.encodePacked(imageId, journalDigest)), "verifier: bad seal");
    }
}
