// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Minimal ERC-20 surface the vault needs.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Vault: deposit side of the Kaspa ZK bridge (Kaspero Labs), CP-3.
/// @notice One-way. Tokens sent here stay here. There is no owner, no withdraw,
///         no pause, no upgrade. The only state transition is `deposit`, and the
///         only reader is a RISC Zero guest that proves `deposits[nonce]` against
///         the Ethereum state root of a finalized block (eth-prover, CP-2).
///
/// Storage layout (the guest hardcodes it; `forge inspect Vault storage-layout`
/// reproduces it; `test/Vault.t.sol` asserts it):
///
///   slot 0            nonce            uint64, low 8 bytes of the word
///   slot 1            deposits         mapping(uint64 => Deposit) base slot (holds nothing itself)
///   keccak256(abi.encode(uint256(n), uint256(1)))       deposits[n] word 0:
///                                                        bits 0..63  amount   (uint64)
///                                                        bits 64..71 kaspaVersion (uint8)
///                                                        bits 72..255 zero
///   keccak256(abi.encode(uint256(n), uint256(1))) + 1   deposits[n] word 1: kaspaPayload (bytes32, whole word)
///
/// `token` is immutable (lives in code, not storage), so it occupies no slot.
///
/// Kaspa recipient encoding: `kaspaSpk` is 33 bytes, address version byte followed by
/// the 32-byte address payload. Version 0 is a Schnorr P2PK address (payload = x-only
/// pubkey, output script 20<payload>ac); version 8 is P2SH (payload = blake2b script hash,
/// output script aa20<payload>87). ECDSA addresses (version 1, 33-byte payload) are not
/// accepted. The journal carries these 33 bytes verbatim and the Kaspa covenant builds
/// the output script from them (CP-6). Never a bech32 string.
contract Vault {
    struct Deposit {
        uint64 amount;
        uint8 kaspaVersion;
        bytes32 kaspaPayload;
    }

    IERC20 public immutable token;

    /// @notice Number of deposits so far. The first deposit has nonce 1; nonce 0 never exists,
    ///         so a zero storage word can never be mistaken for a deposit.
    uint64 public nonce;

    mapping(uint64 => Deposit) public deposits;

    event Deposited(uint64 indexed nonce, address indexed from, uint64 amount, bytes kaspaSpk);

    constructor(IERC20 token_) {
        require(address(token_) != address(0), "Vault: zero token");
        token = token_;
    }

    /// @param amount   token base units (uint64; for a 6-decimal token that is 18.4e12 units max)
    /// @param kaspaSpk 33 bytes: version byte (0 = P2PK Schnorr, 8 = P2SH) + 32-byte payload
    function deposit(uint64 amount, bytes calldata kaspaSpk) external returns (uint64 n) {
        require(amount != 0, "Vault: zero amount");
        require(kaspaSpk.length == 33, "Vault: kaspaSpk must be 33 bytes");
        uint8 version = uint8(kaspaSpk[0]);
        require(version == 0 || version == 8, "Vault: kaspa version must be 0 or 8");
        bytes32 payload = bytes32(kaspaSpk[1:33]);
        require(payload != bytes32(0), "Vault: zero kaspa payload");

        require(token.transferFrom(msg.sender, address(this), amount), "Vault: transferFrom failed");

        n = ++nonce;
        deposits[n] = Deposit({amount: amount, kaspaVersion: version, kaspaPayload: payload});
        emit Deposited(n, msg.sender, amount, kaspaSpk);
    }
}
