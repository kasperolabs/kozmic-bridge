// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UsdcVaultV2, IERC20} from "../src/UsdcVaultV2.sol";
import {MockFiatToken} from "./MockFiatToken.sol";

/// The storage layout the inbound guest reads (slots 0 and 1, byte for byte as UsdcVault's), the bucket's
/// arithmetic at the boundaries, and the deposit limits, with vm.load.
contract UsdcVaultV2Test is Test {
    uint64 constant CAP0 = 500e6;
    uint64 constant CEILING = 50_000e6;
    uint64 constant DOUBLING = 7 days;
    uint64 constant MIN_DEPOSIT = 10e6;
    uint64 constant BUCKET_MAX = 10_000e6;
    uint64 constant REFILL_PER_DAY = 25_000e6;
    uint64 constant MAX_DEPOSIT = 10_000e6;

    MockFiatToken token;
    UsdcVaultV2 vault;
    address relay = address(0x4E1A);
    address alice = address(0xA1);

    function setUp() public {
        vm.warp(1_800_000_000);
        token = new MockFiatToken();
        vault = new UsdcVaultV2(IERC20(address(token)), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT, BUCKET_MAX, REFILL_PER_DAY, MAX_DEPOSIT);
        vault.setRelay(relay);
        token.mint(alice, 1_000_000e6);
        vm.prank(alice);
        token.approve(address(vault), type(uint256).max);
    }

    function testConstructorGuards() public {
        vm.expectRevert("vault: bad max deposit");
        new UsdcVaultV2(IERC20(address(token)), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT, BUCKET_MAX, REFILL_PER_DAY, BUCKET_MAX + 1);
        vm.expectRevert("vault: bad max deposit");
        new UsdcVaultV2(IERC20(address(token)), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT, BUCKET_MAX, REFILL_PER_DAY, MIN_DEPOSIT - 1);
        vm.expectRevert("vault: bad bucket");
        new UsdcVaultV2(IERC20(address(token)), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT, 0, REFILL_PER_DAY, MAX_DEPOSIT);
        vm.expectRevert("vault: relay already set");
        vault.setRelay(relay);
    }

    function testLayoutSlots0And1AreUsdcVaults() public {
        vm.prank(alice);
        uint64 n = vault.deposit(25e6, abi.encodePacked(uint8(8), bytes32(uint256(0x1234))));
        assertEq(n, 1);
        // slot 0: nonce in the low 8 bytes
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(0)))), 1);
        // deposits[1] word 0: amount | version << 64 | depositor << 72; word 1: payload
        bytes32 k0 = keccak256(abi.encode(uint256(1), uint256(1)));
        uint256 w0 = uint256(vm.load(address(vault), k0));
        assertEq(w0 & type(uint64).max, 25e6, "amount");
        assertEq((w0 >> 64) & 0xff, 8, "version");
        assertEq(address(uint160(w0 >> 72)), alice, "depositor");
        assertEq(w0 >> 232, 0, "top bits zero");
        assertEq(vm.load(address(vault), bytes32(uint256(k0) + 1)), bytes32(uint256(0x1234)), "payload");
        // slot 2: bucketFullAt, a whole word; slot 3: outstanding | relay << 64, as UsdcVault
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(2)))), block.timestamp, "bucket full now");
        uint256 w3 = uint256(vm.load(address(vault), bytes32(uint256(3))));
        assertEq(w3 & type(uint64).max, 25e6, "outstanding");
        assertEq(address(uint160(w3 >> 64)), relay, "relay");
    }

    function testDepositLimits() public {
        vm.warp(block.timestamp + 6 * DOUBLING); // cap 32,000
        vm.prank(alice);
        vm.expectRevert("vault: below the minimum deposit");
        vault.deposit(MIN_DEPOSIT - 1, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.prank(alice);
        vm.expectRevert("vault: above the maximum deposit");
        vault.deposit(MAX_DEPOSIT + 1, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        assertEq(token.balanceOf(address(vault)), 0, "nothing moved");
        vm.prank(alice);
        vault.deposit(MAX_DEPOSIT, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.prank(alice);
        vault.deposit(MIN_DEPOSIT, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        assertEq(vault.outstanding(), MAX_DEPOSIT + MIN_DEPOSIT);
    }

    function testBucketArithmetic() public {
        vm.warp(block.timestamp + 6 * DOUBLING);
        vm.prank(alice);
        vault.deposit(MAX_DEPOSIT, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.prank(alice);
        vault.deposit(MAX_DEPOSIT, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        // a release above the bucket pays exactly the bucket
        vm.prank(relay);
        uint64 paid = vault.release(bytes32(uint256(1)), alice, 15_000e6, 0, relay);
        assertEq(paid, BUCKET_MAX);
        assertEq(vault.available(), 0);
        assertEq(vault.bucketFullAt(), block.timestamp + 34_560, "10,000 at 25,000 a day is 0.4 day");
        // nothing more in the same second
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(1)), alice, 5_000e6, 0, relay), 0);
        // a second spend stacks on the first, from the future full time, not from now
        vm.warp(block.timestamp + 3600);
        uint64 avail = vault.available();
        assertGe(avail, 1_041e6);
        assertLe(avail, 1_042e6);
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(2)), alice, 1_000e6, 0, relay), 1_000e6);
        assertEq(vault.bucketFullAt(), block.timestamp - 3600 + 34_560 + 3_456, "stacked: 1,000 is 0.04 day more");
        // the refill never exceeds the bucket, however long it waits
        vm.warp(block.timestamp + 365 days);
        assertEq(vault.available(), BUCKET_MAX);
        // release caps at what is outstanding
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(3)), alice, 10_000e6, 0, relay), 9_000e6, "only 9,000 outstanding");
        assertEq(vault.outstanding(), 0);
    }

    function testReleaseTipAndRefusals() public {
        vm.prank(alice);
        vault.deposit(500e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        address bob = address(0xB0B);
        address sub = address(0x5AB);
        // tip > amount: refused, nothing paid
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(1)), bob, 10e6, 11e6, sub), 0);
        // tip first: 100 with tip 30 pays 70 to bob and 30 to the submitter
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(1)), bob, 100e6, 30e6, sub), 100e6);
        assertEq(token.balanceOf(bob), 70e6);
        assertEq(token.balanceOf(sub), 30e6);
        // the bucket holds less than the tip: refused (an installment must reach the recipient)
        vm.prank(relay);
        vault.release(bytes32(uint256(8)), bob, 400e6, 0, sub); // empties the bucket's room down to the outstanding 400
        assertEq(vault.outstanding(), 0);
        vm.prank(alice);
        vault.deposit(500e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        // make the bucket scarce: after the warp (which refills it) deposit 9,990 and release 9,990, leaving about 10
        vm.warp(block.timestamp + 6 * DOUBLING);
        vm.prank(alice);
        vault.deposit(9_990e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(8)), bob, 9_990e6, 0, sub), 9_990e6);
        assertEq(vault.outstanding(), 500e6);
        // about 10 of bucket left (minus one second of refill for the rounding): a tip of 20 cannot be paid alone
        uint64 avail = vault.available();
        assertLt(avail, 20e6);
        assertGt(avail, 0);
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(8)), bob, 100e6, 20e6, sub), 0, "installment would be all tip");
        assertEq(vault.available(), avail, "nothing spent");
        assertEq(token.balanceOf(sub), 30e6, "no tip");
        vm.warp(block.timestamp + 1 days);
        // blacklisted recipient: nothing paid, nothing spent
        token.blacklist(bob);
        uint64 availBefore = vault.available();
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(2)), bob, 50e6, 5e6, sub), 0);
        assertEq(vault.available(), availBefore);
        assertEq(token.balanceOf(sub), 30e6, "no tip without the recipient");
        assertEq(vault.outstanding(), 500e6);
        // blacklisted submitter: the tip is forfeited, the recipient is paid, the installment counts
        token.unBlacklist(bob);
        token.blacklist(sub);
        vm.prank(relay);
        assertEq(vault.release(bytes32(uint256(3)), bob, 50e6, 5e6, sub), 50e6);
        assertEq(token.balanceOf(bob), 70e6 + 400e6 + 9_990e6 + 45e6);
        assertEq(token.balanceOf(sub), 30e6);
        assertEq(token.balanceOf(address(vault)), 10_990e6 - 100e6 - 400e6 - 9_990e6 - 45e6, "the forfeited tip stays");
        assertEq(vault.outstanding(), 450e6);
    }

    // ------------------------------------------------------------------ mainnet fork: the real USDC, the owed path

    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    /// Circle's real token and blacklister (run with ETH_RPC_URL set; skipped otherwise): a release to a blacklisted
    /// recipient pays nothing and spends nothing; after the unblacklist the same release pays, no second proof.
    function testForkRealUsdcOwedPath() public {
        string memory rpc = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        address bob = address(0xB0B);
        address sub = address(0x5AB);
        UsdcVaultV2 v = new UsdcVaultV2(IERC20(USDC), address(this), CAP0, CEILING, DOUBLING, MIN_DEPOSIT, BUCKET_MAX, REFILL_PER_DAY, MAX_DEPOSIT);
        v.setRelay(relay);
        deal(USDC, alice, 1_000e6);
        vm.prank(alice);
        (bool ok,) = USDC.call(abi.encodeWithSignature("approve(address,uint256)", address(v), type(uint256).max));
        assertTrue(ok);
        vm.prank(alice);
        v.deposit(100e6, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        (, bytes memory ret) = USDC.staticcall(abi.encodeWithSignature("blacklister()"));
        address blacklister = abi.decode(ret, (address));
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("blacklist(address)", bob));
        assertTrue(ok);
        uint64 availBefore = v.available();
        vm.prank(relay);
        assertEq(v.release(bytes32(uint256(9)), bob, 50e6, 1e6, sub), 0, "refused, not reverted");
        assertEq(v.available(), availBefore, "bucket untouched");
        assertEq(v.outstanding(), 100e6);
        vm.prank(blacklister);
        (ok,) = USDC.call(abi.encodeWithSignature("unBlacklist(address)", bob));
        assertTrue(ok);
        vm.prank(relay);
        assertEq(v.release(bytes32(uint256(9)), bob, 50e6, 1e6, sub), 50e6);
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", bob));
        assertEq(abi.decode(ret, (uint256)), 49e6);
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", sub));
        assertEq(abi.decode(ret, (uint256)), 1e6);
        assertEq(v.outstanding(), 50e6);
        // a deposit above MAX_DEPOSIT moves no USDC
        vm.warp(block.timestamp + 6 * DOUBLING);
        vm.prank(alice);
        vm.expectRevert("vault: above the maximum deposit");
        v.deposit(MAX_DEPOSIT + 1, abi.encodePacked(uint8(0), bytes32(uint256(1))));
        (, ret) = USDC.staticcall(abi.encodeWithSignature("balanceOf(address)", alice));
        assertEq(abi.decode(ret, (uint256)), 900e6);
    }
}
