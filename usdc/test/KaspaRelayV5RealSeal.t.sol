// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {KaspaRelayV5} from "../src/KaspaRelayV5.sol";
import {UsdcVaultV4, IERC20} from "../src/UsdcVaultV4.sol";
import {ISettlementV3} from "../src/ISettlementV3.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";

interface IBalance {
    function balanceOf(address) external view returns (uint256);
}

/// @notice Sprint 6 (2026-11-12): the real Groth16 seal of the pinned outbound guest (V4-DESIGN 2.15.4, bundle
///         out-s2b-pin) settles on KaspaRelayV5 through the real RISC Zero router and a real EIP-2935 read, on a
///         fork of the chain the burn's beacon lives on (Sepolia: burn 83167eff… is a Sepia.k burn), pinned inside
///         the 8,191-block window after that beacon. No mocks on the proof path. Skips itself unless FORK_RPC_URL
///         is set. Env:
///           FORK_RPC_URL   the fork (anvil at 127.0.0.1:8545, pinned; never a URL with a key)
///           FORK_VERIFIER  RiscZeroVerifierRouter on that chain (eth-net.json)
///           FORK_TOKEN     a FiatToken on that chain (Sepia.k's; the depositor is funded with `deal`)
///           JOURNAL_HEX, SEAL_HEX   0x-prefixed, from the bundle's journal.hex and eth-seal.hex
///           BEACON_RLP     the anchor block's header RLP (`cast block N --raw` on that chain)
///           FORK_FLOOR     the test relay's F (default 250: the s2b ladder has 274 attesters, #1's F 450 would
///                          refuse it, which is logged, not asserted)
///         The relay is deployed with the journal's own token id, template hash and r_bits, then its code is
///         etched at the journal's target address (the proof names the relay it was made for), with its memory
///         slots copied; the vault is told that address. MIN_BURN is the burn's 10,000 units (#1 uses $10).
contract KaspaRelayV5RealSealTest is Test {
    bytes32 constant IMAGE_ID = 0x1b86827695b06ef38f4e31a36b995b52011fad678e9fc856e637163dc804dbb1; // guest-v4 86bb869, 2.15.1
    uint64 constant USD = 1e6;
    address constant FEE_TO = address(0xFEE);
    address constant ALICE = address(0xA11CE);

    // the journal's fields (KZO6 offsets, V4-DESIGN 2.13.1 and 2.14.1)
    struct J {
        uint32 rBits;
        address target;
        bytes32 tokenCovId;
        bytes32 templateHash;
        uint64 anchorNumber;
        bytes32 anchorHash;
        address prover;
        bytes32 txId;
        uint64 amount;
        uint64 tip;
        address recipient;
    }

    J j;
    bytes journal;
    bytes seal;
    bytes rlp;
    address verifier;
    address token;
    UsdcVaultV4 vault;
    KaspaRelayV5 relay;

    function _b32(bytes memory b, uint256 o) internal pure returns (bytes32 x) {
        require(o < b.length, "slice"); // fields shorter than 32 bytes: the leading bytes are the field, the rest is ignored
        assembly {
            x := mload(add(add(b, 32), o))
        }
    }

    function _readEnv() internal {
        journal = vm.envBytes("JOURNAL_HEX");
        seal = vm.envBytes("SEAL_HEX");
        rlp = vm.envBytes("BEACON_RLP");
        verifier = vm.envAddress("FORK_VERIFIER");
        token = vm.envAddress("FORK_TOKEN");
        bytes memory jb = journal;
        require(jb.length == 378 && bytes4(_b32(jb, 0)) == 0x4b5a4f36, "not the KZO6 one-burn journal");
        j.rBits = uint32(bytes4(_b32(jb, 84)));
        j.target = address(bytes20(_b32(jb, 165)));
        j.tokenCovId = _b32(jb, 185);
        j.templateHash = _b32(jb, 217);
        j.anchorNumber = uint64(bytes8(_b32(jb, 249)));
        j.anchorHash = _b32(jb, 257);
        j.prover = address(bytes20(_b32(jb, 289)));
        j.txId = _b32(jb, 310);
        j.amount = uint64(bytes8(_b32(jb, 342)));
        j.tip = uint64(bytes8(_b32(jb, 350)));
        j.recipient = address(bytes20(_b32(jb, 358)));
        emit log_named_bytes32("journal sha256", sha256(jb));
        emit log_named_address("journal target (the relay is etched here)", j.target);
        emit log_named_address("journal prover", j.prover);
        emit log_named_bytes32("burn", j.txId);
        emit log_named_uint("burn amount (units)", j.amount);
        emit log_named_uint("burn tip (units)", j.tip);
        emit log_named_address("burn recipient", j.recipient);
        emit log_named_uint("anchor number", j.anchorNumber);
        emit log_named_bytes32("anchor hash", j.anchorHash);
        emit log_named_uint("fork block", block.number);
        emit log_named_uint("fork time", block.timestamp);
    }

    /// the real code, test parameters where the s2b proof needs them (floor, MIN_BURN), etched at the journal's target
    function _deploy() internal {
        uint32 floor = uint32(vm.envOr("FORK_FLOOR", uint256(250)));
        vault = new UsdcVaultV4(IERC20(token), address(this), 5_000 * USD, 1_000_000 * USD, 7 days, 10 * USD, 10_000 * USD, 25_000 * USD, 10_000 * USD, 10, FEE_TO, sha256("fork test"));
        vault.setRelay(j.target);
        KaspaRelayV5 impl = new KaspaRelayV5(
            IRiscZeroVerifier(verifier),
            IMAGE_ID,
            ISettlementV3(address(vault)),
            KaspaRelayV5.Params({
                genesisBits: j.rBits,
                tokenCovId: j.tokenCovId,
                templateHash: j.templateHash,
                cmpLevel: 30,
                floor: floor,
                alphaBps: 5_000,
                slowSpan: 7 days,
                attestUnit: 2 * USD,
                minBurn: j.amount,
                minInstallment: 1 * USD
            })
        );
        vm.etch(j.target, address(impl).code);
        for (uint256 i = 0; i < 9; i++) vm.store(j.target, bytes32(i), vm.load(address(impl), bytes32(i))); // slots[8] + lastWork/lastTime
        relay = KaspaRelayV5(j.target);
        assertEq(address(relay.VERIFIER()), verifier, "router");
        assertEq(relay.IMAGE_ID(), IMAGE_ID, "image id");
        assertEq(address(relay.SETTLEMENT()), address(vault), "vault");
        assertEq(relay.FLOOR(), floor, "floor");
        assertEq(uint256(relay.lastWork()), uint256(relay.workOfBits(j.rBits)), "memory copied");
        emit log_named_uint("router code bytes", verifier.code.length);
        emit log_named_uint("token code bytes", token.code.length);
    }

    /// the vault is funded by a depositor (the real token on the fork, balance set with deal)
    function _fund() internal {
        deal(token, ALICE, 5_000 * USD);
        vm.startPrank(ALICE);
        (bool ok,) = token.call(abi.encodeWithSignature("approve(address,uint256)", address(vault), type(uint256).max));
        require(ok, "approve");
        vault.deposit(5_000 * USD, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.stopPrank();
        assertEq(vault.outstanding(), 5_000 * USD, "vault funded");
    }

    /// the rule, before the call: tau from the real history read, required at this floor, the alpha term alone
    function _rule() internal {
        KaspaRelayV5.Journal memory jn = relay.parseJournal(journal);
        uint256 bt = relay.beaconTime(j.anchorNumber, j.anchorHash, rlp);
        uint256 tau = block.timestamp - bt + relay.SLOT_SLACK();
        uint256 required = relay.requiredAttest(tau, j.rBits, j.amount);
        emit log_named_uint("beacon time (real EIP-2935 read + header)", bt);
        emit log_named_uint("tau (s)", tau);
        emit log_named_uint("attesting", jn.attesting);
        emit log_named_uint("count", jn.count);
        emit log_named_uint("required at this floor", required);
        emit log_named_uint("alpha term alone (what F 450 would compare against)", _alphaTerm(tau));
        assertGe(jn.attesting, required, "the rule must pass for the real submit below");
    }

    function _alphaTerm(uint256 tau) internal view returns (uint256) {
        uint256 own = relay.workOfBits(j.rBits);
        uint256 den = 10_000 << (31 + uint256(relay.CMP_LEVEL()));
        uint256 num = uint256(relay.ALPHA_BPS()) * own * relay.DAA_PER_SECOND() * tau;
        return (num + den - 1) / den;
    }

    function test_real_seal_real_router_real_history() public {
        string memory url = vm.envOr("FORK_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        _readEnv();
        _deploy();
        _fund();
        _rule();

        uint256 recBefore = IBalance(token).balanceOf(j.recipient);
        uint256 provBefore = IBalance(token).balanceOf(j.prover);

        // 1. a tampered seal: every relay gate passes, the real router refuses (its error, not a "relay:" string)
        bytes memory bad = bytes.concat(seal);
        bad[bad.length - 1] = bytes1(uint8(bad[bad.length - 1]) ^ 0x01);
        try relay.submit(bad, journal, rlp) {
            fail("a tampered seal verified");
        } catch (bytes memory err) {
            emit log_named_bytes("tampered seal: router revert data", err);
            assertTrue(bytes4(err) != bytes4(keccak256("Error(string)")), "the revert came from the router, not from a relay require");
        }
        // 2. a wrong header for a right anchor
        vm.expectRevert("relay: header is not the beacon block");
        relay.submit(seal, journal, hex"c0");

        // 3. the real submit: Owed names the journal's prover; the recipient is paid less the fee, in this transaction
        uint64 fee = uint64(uint256(j.amount - j.tip) * 10 / 10_000);
        vm.expectEmit(true, true, true, true, j.target);
        emit KaspaRelayV5.Owed(j.txId, j.recipient, j.amount, j.tip, j.prover);
        vm.expectEmit(true, true, true, true, address(vault));
        emit UsdcVaultV4.Released(j.txId, j.recipient, j.amount, j.tip, fee, j.prover, true);
        vm.expectEmit(true, true, true, true, j.target);
        emit KaspaRelayV5.PaidInFull(j.txId);
        uint256 g = gasleft();
        relay.submit(seal, journal, rlp);
        emit log_named_uint("submit gas (real router, one burn)", g - gasleft());
        assertEq(IBalance(token).balanceOf(j.recipient) - recBefore, j.amount - fee, "recipient got amount less the fee");
        assertEq(IBalance(token).balanceOf(j.prover), provBefore, "tip 0: the prover got nothing");
        assertEq(vault.feeOwed(), fee, "fee accrued");
        assertEq(vault.outstanding(), 5_000 * USD - j.amount, "outstanding debited");
        assertTrue(relay.settled(j.txId), "settled");
        assertTrue(relay.seen(sha256(journal)), "journal remembered");
        emit log_named_uint("recipient received (units)", j.amount - fee);
        emit log_named_uint("fee owed (units)", fee);

        // 4. the same journal again
        vm.expectRevert("relay: journal already settled");
        relay.submit(seal, journal, rlp);
    }
}
