// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TestToken} from "../src/TestToken.sol";
import {Vault, IERC20} from "../src/Vault.sol";

/// The storage assertions here are the contract between Vault.sol and the eth-prover guest
/// (primitives/src/lib.rs `vault_layout`). If one changes, the other must.
contract VaultTest is Test {
    TestToken token;
    Vault vault;
    address alice = address(0xA11CE);

    uint256 constant DEPOSITS_SLOT = 1;
    bytes32 constant PAYLOAD = hex"0102030405060708091011121314151617181920212223242526272829303132";

    function setUp() public {
        token = new TestToken(1_000_000e6);
        vault = new Vault(IERC20(address(token)));
        token.transfer(alice, 100e6);
    }

    function _spk(uint8 version, bytes32 payload) internal pure returns (bytes memory) {
        return abi.encodePacked(version, payload);
    }

    function _key(uint64 n) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(n), DEPOSITS_SLOT));
    }

    function test_firstNonceIsOne_andStorageLayout() public {
        vm.startPrank(alice);
        token.approve(address(vault), 1_000_000);
        uint64 n = vault.deposit(1_000_000, _spk(0, PAYLOAD));
        vm.stopPrank();

        assertEq(n, 1);
        assertEq(vault.nonce(), 1);
        assertEq(token.balanceOf(address(vault)), 1_000_000);

        // slot 0 = nonce
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(0)))), 1);
        // slot 1 (mapping base) is empty
        assertEq(uint256(vm.load(address(vault), bytes32(uint256(1)))), 0);
        // deposits[1] word 0 = amount | version << 64
        bytes32 k = _key(1);
        assertEq(uint256(vm.load(address(vault), k)), uint256(1_000_000) | (uint256(0) << 64));
        // deposits[1] word 1 = payload
        assertEq(vm.load(address(vault), bytes32(uint256(k) + 1)), PAYLOAD);
        // and the public getter agrees
        (uint64 amount, uint8 version, bytes32 payload) = vault.deposits(1);
        assertEq(amount, 1_000_000);
        assertEq(version, 0);
        assertEq(payload, PAYLOAD);
    }

    function test_p2shVersionPacksIntoByte8() public {
        vm.startPrank(alice);
        token.approve(address(vault), 7);
        vault.deposit(7, _spk(8, PAYLOAD));
        vm.stopPrank();
        bytes32 k = _key(1);
        assertEq(uint256(vm.load(address(vault), k)), uint256(7) | (uint256(8) << 64));
    }

    function test_secondDepositGetsNonceTwo() public {
        vm.startPrank(alice);
        token.approve(address(vault), 3);
        vault.deposit(1, _spk(0, PAYLOAD));
        uint64 n = vault.deposit(2, _spk(0, PAYLOAD));
        vm.stopPrank();
        assertEq(n, 2);
        assertEq(uint256(vm.load(address(vault), _key(2))), 2);
    }

    function test_rejects() public {
        vm.startPrank(alice);
        token.approve(address(vault), type(uint256).max);
        vm.expectRevert(bytes("Vault: zero amount"));
        vault.deposit(0, _spk(0, PAYLOAD));
        vm.expectRevert(bytes("Vault: kaspaSpk must be 33 bytes"));
        vault.deposit(1, abi.encodePacked(PAYLOAD));
        vm.expectRevert(bytes("Vault: kaspa version must be 0 or 8"));
        vault.deposit(1, _spk(1, PAYLOAD));
        vm.expectRevert(bytes("Vault: zero kaspa payload"));
        vault.deposit(1, _spk(0, bytes32(0)));
        vm.stopPrank();
        // no approval from this contract -> transferFrom fails
        vm.expectRevert(bytes("KBT: allowance"));
        vault.deposit(1, _spk(0, PAYLOAD));
    }

    function test_noWithdrawSurface() public view {
        // There is nothing to call: the ABI has deposit, deposits, nonce, token. This test
        // exists to make the intent explicit; `forge inspect Vault abi` is the evidence.
        assertEq(address(vault.token()), address(token));
    }
}
