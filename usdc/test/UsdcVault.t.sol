// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UsdcVault, IERC20} from "../src/UsdcVault.sol";
import {MockFiatToken} from "./MockFiatToken.sol";

/// Unit tests against the mock, then the same rules on a mainnet fork against the real USDC with Circle's
/// blacklister impersonated (run with ETH_RPC_URL set; skipped otherwise).
contract UsdcVaultTest is Test {
    uint64 constant CAP0 = 500e6;
    uint64 constant CEILING = 50_000e6;
    uint64 constant DOUBLING = 7 days;
    uint64 constant MIN_DEPOSIT = 10e6;

    MockFiatToken token;
    UsdcVault vault;
    address relay = address(0xA11CE);
    address alice = address(0xA1);
    address bob = address(0xB0B);
    address submitter = address(0x5AB);
    bytes spkP2pk = abi.encodePacked(uint8(0), bytes32(uint256(0x1234)));
    bytes spkP2sh = abi.encodePacked(uint8(8), bytes32(uint256(0x5678)));

    function setUp() public {
        vm.warp(1_800_000_000);
        token = new MockFiatToken();
        vault = new UsdcVault(IERC20(address(token)), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT);
        vault.setRelay(relay);
        token.mint(alice, 1_000_000e6);
        vm.prank(alice);
        token.approve(address(vault), type(uint256).max);
    }

    function dep(address who, uint64 amount, bytes memory spk) internal returns (uint64) {
        vm.prank(who);
        return vault.deposit(amount, spk);
    }

    // ------------------------------------------------------------------ storage layout (the guest pins this)

    function testStorageLayout() public {
        uint64 n = dep(alice, 123_456_789, spkP2pk);
        assertEq(n, 1);
        // slot 0: nonce in the low 8 bytes
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(0)))), 1);
        // slot 1 holds nothing
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(1)))), 0);
        bytes32 k0 = keccak256(abi.encode(uint256(1), uint256(1)));
        uint256 w0 = uint256(vm.load(address(vault), k0));
        assertEq(w0 & type(uint64).max, 123_456_789, "amount bits 0..63");
        assertEq((w0 >> 64) & 0xff, 0, "version bits 64..71");
        assertEq(address(uint160(w0 >> 72)), alice, "depositor bits 72..231");
        assertEq(w0 >> 232, 0, "bits 232..255 zero");
        assertEq(vm.load(address(vault), bytes32(uint256(k0) + 1)), bytes32(uint256(0x1234)), "payload word 1");
        // slot 3: outstanding in bits 0..63, relay packed into bits 64..223 (uint64 + address fit one word)
        uint256 w3 = uint256(vm.load(address(vault), bytes32(uint256(3))));
        assertEq(w3 & type(uint64).max, 123_456_789, "outstanding");
        assertEq(address(uint160(w3 >> 64)), relay, "relay packed after outstanding");
        assertEq(w3 >> 224, 0);
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(4)))), 0, "no slot 4");
        // a P2SH deposit
        dep(alice, 10e6, spkP2sh);
        bytes32 k1 = keccak256(abi.encode(uint256(2), uint256(1)));
        assertEq((uint256(vm.load(address(vault), k1)) >> 64) & 0xff, 8);
    }

    function testStorageLayoutMatchesInspect() public view {
        // `forge inspect UsdcVault storage-layout` must list exactly: nonce@0, deposits@1, settled@2, outstanding@3.
        // Asserted indirectly above; this keeps the slot numbers in one place for the guest's vault_layout.
        assertEq(vault.nonce(), 0);
    }

    // ------------------------------------------------------------------ deposit rules

    function testDepositRules() public {
        vm.startPrank(alice);
        vm.expectRevert("vault: below the minimum deposit");
        vault.deposit(MIN_DEPOSIT - 1, spkP2pk);
        vm.expectRevert("vault: kaspaSpk must be 33 bytes");
        vault.deposit(10e6, hex"00");
        vm.expectRevert("vault: kaspa version must be 0 or 8");
        vault.deposit(10e6, abi.encodePacked(uint8(1), bytes32(uint256(1))));
        vm.expectRevert("vault: zero kaspa payload");
        vault.deposit(10e6, abi.encodePacked(uint8(0), bytes32(0)));
        vm.stopPrank();
        assertEq(vault.nonce(), 0);
    }

    function testBlacklistedDepositorCannotDeposit() public {
        token.blacklist(alice);
        vm.prank(alice);
        vm.expectRevert("Blacklistable: account is blacklisted");
        vault.deposit(10e6, spkP2pk);
    }

    // ------------------------------------------------------------------ cap schedule

    function testCapSchedule() public {
        assertEq(vault.cap(), CAP0);
        dep(alice, CAP0, spkP2pk);
        vm.prank(alice);
        vm.expectRevert("vault: over the cap");
        vault.deposit(10e6, spkP2pk);
        assertEq(vault.room(), 0);

        vm.warp(block.timestamp + DOUBLING);
        assertEq(vault.cap(), 2 * CAP0);
        assertEq(vault.room(), CAP0);
        dep(alice, CAP0, spkP2pk);

        vm.warp(block.timestamp + 10 * DOUBLING); // 500 * 2^11 = 1,024,000 > ceiling
        assertEq(vault.cap(), CEILING);
        vm.warp(block.timestamp + 100 * DOUBLING); // shift overflow guard
        assertEq(vault.cap(), CEILING);
        assertEq(vault.capAt(0), CAP0); // before deployment
    }

    function testExitFreesRoom() public {
        dep(alice, CAP0, spkP2pk);
        assertEq(vault.room(), 0);
        vm.prank(relay);
        assertTrue(vault.settle(bytes32(uint256(1)), bob, 200e6, 0, submitter));
        assertEq(vault.room(), 200e6);
        assertEq(vault.outstanding(), 300e6);
        dep(alice, 200e6, spkP2pk);
    }

    // ------------------------------------------------------------------ settle

    function testSettlePaysRecipientAndTip() public {
        dep(alice, 100e6, spkP2pk);
        vm.prank(relay);
        assertTrue(vault.settle(bytes32(uint256(7)), bob, 100e6, 1e6, submitter));
        assertEq(token.balanceOf(bob), 99e6);
        assertEq(token.balanceOf(submitter), 1e6);
        assertTrue(vault.settled(bytes32(uint256(7))));
        assertEq(vault.outstanding(), 0);
    }

    function testSettleOnlyRelay() public {
        dep(alice, 100e6, spkP2pk);
        vm.expectRevert("vault: not the relay");
        vault.settle(bytes32(uint256(7)), bob, 100e6, 0, submitter);
    }

    function testSetRelayOnceByFactoryOnly() public {
        vm.expectRevert("vault: relay already set");
        vault.setRelay(address(1));
        UsdcVault fresh = new UsdcVault(IERC20(address(token)), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT);
        vm.prank(alice);
        vm.expectRevert("vault: not the factory");
        fresh.setRelay(relay);
        vm.prank(relay);
        vm.expectRevert("vault: not the relay"); // unset relay: nobody can settle
        fresh.settle(bytes32(uint256(1)), bob, 1, 0, submitter);
        fresh.setRelay(relay);
        assertEq(fresh.relay(), relay);
    }

    function testSettleOncePerTxId() public {
        dep(alice, 100e6, spkP2pk);
        vm.startPrank(relay);
        assertTrue(vault.settle(bytes32(uint256(7)), bob, 50e6, 0, submitter));
        assertFalse(vault.settle(bytes32(uint256(7)), bob, 50e6, 0, submitter));
        vm.stopPrank();
        assertEq(token.balanceOf(bob), 50e6);
    }

    function testSettleRefusesMoreThanOutstanding() public {
        dep(alice, 100e6, spkP2pk);
        vm.prank(relay);
        assertFalse(vault.settle(bytes32(uint256(7)), bob, 100e6 + 1, 0, submitter));
        assertFalse(vault.settled(bytes32(uint256(7))));
    }

    function testBlacklistedRecipientStaysClaimable() public {
        dep(alice, 100e6, spkP2pk);
        token.blacklist(bob);
        vm.prank(relay);
        assertFalse(vault.settle(bytes32(uint256(7)), bob, 100e6, 1e6, submitter), "refused, not reverted");
        assertFalse(vault.settled(bytes32(uint256(7))));
        assertEq(vault.outstanding(), 100e6);
        assertEq(token.balanceOf(submitter), 0, "no tip on a refused burn");
        token.unBlacklist(bob);
        vm.prank(relay);
        assertTrue(vault.settle(bytes32(uint256(7)), bob, 100e6, 1e6, submitter), "claimable later");
        assertEq(token.balanceOf(bob), 99e6);
    }

    function testBlacklistedSubmitterForfeitsTipOnly() public {
        dep(alice, 100e6, spkP2pk);
        token.blacklist(submitter);
        vm.prank(relay);
        assertTrue(vault.settle(bytes32(uint256(7)), bob, 100e6, 1e6, submitter));
        assertEq(token.balanceOf(bob), 99e6);
        assertEq(token.balanceOf(submitter), 0);
        assertEq(token.balanceOf(address(vault)), 1e6, "the tip stays in the vault");
        assertEq(vault.outstanding(), 0);
    }

    // ------------------------------------------------------------------ mainnet fork: the real USDC

    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    function testForkRealUsdc() public {
        string memory rpc = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return; // skipped without an RPC
        vm.createSelectFork(rpc);
        UsdcVault v = new UsdcVault(IERC20(USDC), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT);
        v.setRelay(relay);
        deal(USDC, alice, 1_000e6);
        vm.prank(alice);
        (bool ok,) = USDC.call(abi.encodeWithSignature("approve(address,uint256)", address(v), type(uint256).max));
        assertTrue(ok);
        vm.prank(alice);
        v.deposit(100e6, spkP2pk);
        assertEq(v.outstanding(), 100e6);

        // Circle's blacklister blacklists bob; the release to bob is refused, not reverted, and stays claimable.
        (, bytes memory ret) = USDC.staticcall(abi.encodeWithSignature("blacklister()"));
        address blacklister = abi.decode(ret, (address));
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("blacklist(address)", bob));
        assertTrue(ok);
        vm.prank(relay);
        assertFalse(v.settle(bytes32(uint256(9)), bob, 50e6, 0, submitter));
        assertFalse(v.settled(bytes32(uint256(9))));
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("unBlacklist(address)", bob));
        assertTrue(ok);
        vm.prank(relay);
        assertTrue(v.settle(bytes32(uint256(9)), bob, 50e6, 1e6, submitter));
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", bob));
        assertEq(abi.decode(ret, (uint256)), 49e6);

        // A blacklisted depositor cannot deposit at all (FiatTokenV2_2 reverts inside transferFrom).
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("blacklist(address)", alice));
        assertTrue(ok);
        vm.prank(alice);
        vm.expectRevert();
        v.deposit(10e6, spkP2pk);
    }
}
