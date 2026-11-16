// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {RelayFactoryV3, VaultDeployerV4} from "../src/RelayFactoryV3.sol";
import {KaspaRelayV5} from "../src/KaspaRelayV5.sol";
import {UsdcVaultV4, IERC20} from "../src/UsdcVaultV4.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {MockVerifier} from "./MockVerifier.sol";
import {MockFiatToken} from "./MockFiatToken.sol";

contract RelayFactoryV3Test is Test {
    uint64 constant USD = 1e6;
    bytes32 constant OUT_IMAGE = bytes32(uint256(0x090ea092));
    bytes32 constant IN_IMAGE = bytes32(uint256(0x88e8d020));
    bytes32 constant TOKEN_ID = bytes32(uint256(0x13af6019));
    bytes32 constant TEMPLATE = 0x9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7;

    MockVerifier verifier;
    MockFiatToken usdc;
    RelayFactoryV3 factory;

    function setUp() public {
        verifier = new MockVerifier();
        usdc = new MockFiatToken();
        factory = new RelayFactoryV3(
            IRiscZeroVerifier(address(verifier)),
            OUT_IMAGE,
            IN_IMAGE,
            IERC20(address(usdc)),
            30,
            RelayFactoryV3.Limits({
                maxCeiling: 1_000_000 * USD,
                maxCap0: 5_000 * USD,
                minDoubling: 7 days,
                minMinDeposit: 10 * USD,
                minFloor: 450,
                minAlphaBps: 5_000,
                minSlowSpan: 1 days,
                maxAttestUnit: 2_000_000, // $2.00 per attester at most (F19: no instance thinner than #1)
                maxBucketMax: 10_000 * USD,
                maxRefillPerDay: 25_000 * USD,
                maxFeeBps: 10
            })
        );
    }

    function _v() internal pure returns (RelayFactoryV3.VaultParams memory) {
        return RelayFactoryV3.VaultParams({
            cap0: 5_000 * USD,
            ceiling: 1_000_000 * USD,
            doubling: 7 days,
            minDeposit: 10 * USD,
            bucketMax: 10_000 * USD,
            refillPerDay: 25_000 * USD,
            maxDeposit: 10_000 * USD,
            feeBps: 10,
            feeAddress: address(0xFEE),
            closeHash: sha256("the preimage")
        });
    }

    function _r() internal pure returns (KaspaRelayV5.Params memory) {
        return KaspaRelayV5.Params({
            genesisBits: 0x1a020526,
            tokenCovId: TOKEN_ID,
            templateHash: TEMPLATE,
            cmpLevel: 30,
            floor: 450,
            alphaBps: 5_000,
            slowSpan: 7 days,
            attestUnit: 2 * USD,
            minBurn: 10 * USD,
            minInstallment: 1 * USD
        });
    }

    function test_predicted_addresses_are_the_deployed_ones() public {
        bytes32 salt = keccak256("usdc.k #1");
        address pv = factory.predictVault(salt, _v());
        address pr = factory.predictRelay(salt, _v(), _r());
        (address vault, address relay) = factory.create(salt, _v(), _r());
        assertEq(vault, pv, "vault address as predicted before deployment");
        assertEq(relay, pr, "relay address as predicted before deployment");
        assertEq(UsdcVaultV4(vault).relay(), relay, "linked");
        assertEq(address(KaspaRelayV5(relay).SETTLEMENT()), vault);
        assertEq(KaspaRelayV5(relay).IMAGE_ID(), OUT_IMAGE);
        assertEq(UsdcVaultV4(vault).FEE_ADDRESS(), address(0xFEE));
        assertEq(UsdcVaultV4(vault).FEE_BPS(), 10);
        assertTrue(factory.isInstance(vault) && factory.isInstance(relay));
        assertFalse(factory.isInstance(address(this)));
        assertEq(factory.count(), 1);
    }

    function test_limits_hold() public {
        RelayFactoryV3.VaultParams memory v = _v();
        KaspaRelayV5.Params memory r = _r();
        v.closeHash = bytes32(0);
        vm.expectRevert("factory: close hash");
        factory.create(keccak256("a"), v, r);
        v = _v();
        v.feeBps = 11;
        vm.expectRevert("factory: fee");
        factory.create(keccak256("b"), v, r);
        v = _v();
        v.feeBps = 10;
        v.feeAddress = address(0);
        vm.expectRevert("factory: fee");
        factory.create(keccak256("b2"), v, r);
        v = _v();
        v.bucketMax = 10_001 * USD;
        vm.expectRevert("factory: bucket");
        factory.create(keccak256("c"), v, r);
        v = _v();
        r.attestUnit = 2_500_001; // a cheaper dollar than the factory allows
        vm.expectRevert("factory: attest unit");
        factory.create(keccak256("d"), v, r);
        r = _r();
        r.alphaBps = 4_000;
        vm.expectRevert("factory: alpha");
        factory.create(keccak256("e"), v, r);
        r = _r();
        r.floor = 300;
        vm.expectRevert("factory: floor");
        factory.create(keccak256("f"), v, r);
        r = _r();
        r.slowSpan = 1 hours;
        vm.expectRevert("factory: slow span");
        factory.create(keccak256("g"), v, r);
        r = _r();
        r.cmpLevel = 28;
        vm.expectRevert("factory: cmp level");
        factory.create(keccak256("h"), v, r);
        r = _r();
        r.genesisBits = 0;
        vm.expectRevert("factory: genesis bits");
        factory.create(keccak256("i"), v, r);
    }

    /// F17: the installment floor is bounded by the bucket, and nonzero.
    function test_min_installment_is_bounded_by_the_bucket() public {
        RelayFactoryV3.VaultParams memory v = _v();
        KaspaRelayV5.Params memory r = _r();
        r.minInstallment = 10_000 * USD + 1;
        vm.expectRevert("factory: min installment above the bucket");
        factory.create(keccak256("mi"), v, r);
        r = _r();
        r.minInstallment = 0;
        vm.expectRevert("factory: min installment");
        factory.create(keccak256("mi0"), v, r);
        r = _r();
        r.minInstallment = 10_000 * USD;
        (address vault, address relay) = factory.create(keccak256("mi-ok"), v, r);
        assertEq(KaspaRelayV5(relay).MIN_INSTALLMENT(), 10_000 * USD);
        assertEq(UsdcVaultV4(vault).BUCKET_MAX(), 10_000 * USD);
    }

    function test_only_the_factory_links_and_deploys() public {
        (address vault,) = factory.create(keccak256("x"), _v(), _r());
        vm.expectRevert("vault: not the factory");
        UsdcVaultV4(vault).setRelay(address(1));
        VaultDeployerV4 dep = factory.VAULT_DEPLOYER();
        vm.expectRevert("deployer: not the factory");
        dep.deploy(keccak256("y"), "");
    }
}
