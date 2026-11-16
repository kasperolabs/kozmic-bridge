// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlementV3} from "./ISettlementV3.sol";
import {UsdcVaultV4, IERC20} from "./UsdcVaultV4.sol";
import {KaspaRelayV5} from "./KaspaRelayV5.sol";

/// @notice Holds the vault's creation code and deploys it by CREATE2 for its factory only (RelayFactoryV2's shape:
///         the vault and the relay together outgrow one factory's runtime, so each has a deployer).
contract VaultDeployerV4 {
    address public immutable FACTORY;

    constructor() {
        FACTORY = msg.sender;
    }

    function initCode(bytes memory args) public pure returns (bytes memory) {
        return abi.encodePacked(type(UsdcVaultV4).creationCode, args);
    }

    function deploy(bytes32 salt, bytes memory args) external returns (address a) {
        require(msg.sender == FACTORY, "deployer: not the factory");
        bytes memory c = initCode(args);
        assembly {
            a := create2(0, add(c, 0x20), mload(c), salt)
        }
        require(a != address(0), "deployer: create2 failed");
    }
}

/// @notice The same for the relay.
contract RelayDeployerV5 {
    address public immutable FACTORY;

    constructor() {
        FACTORY = msg.sender;
    }

    function initCode(bytes memory args) public pure returns (bytes memory) {
        return abi.encodePacked(type(KaspaRelayV5).creationCode, args);
    }

    function deploy(bytes32 salt, bytes memory args) external returns (address a) {
        require(msg.sender == FACTORY, "deployer: not the factory");
        bytes memory c = initCode(args);
        assembly {
            a := create2(0, add(c, 0x20), mload(c), salt)
        }
        require(a != address(0), "deployer: create2 failed");
    }
}

/// @title RelayFactoryV3: the only way a USDC.k #1 bridge instance comes into being.
/// @notice RelayFactoryV2 for the v4 vault and the v5 relay. It fixes what a hostile deployer would otherwise
///         choose: the verifier, the outbound image, the token, the comparison level, and the minimum strength of
///         every constant: the floor, alpha, the memory span, the price of attestation (no instance may price a
///         dollar in fewer attesters than MAX_ATTEST_UNIT allows), the bucket and its refill, the fee (at most
///         MAX_FEE_BPS), and that a close hash exists. Holds no keys, has no owner; raising a limit is a new factory.
///
/// Deployment order (U5, unchanged): the Kaspa side comes first, because the relay pins the token's covenant id,
/// which exists only after the bridge covenant's `init` on Kaspa, which in turn pins the vault's address.
/// CREATE2 resolves the cycle: `predictVault(salt, params)` is the vault's address before anything is deployed.
/// The CREATE2 creator is the vault deployer (not the factory), so the prediction uses its address.
contract RelayFactoryV3 {
    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable OUTBOUND_IMAGE_ID;
    bytes32 public immutable INBOUND_IMAGE_ID;
    IERC20 public immutable TOKEN;
    uint8 public immutable CMP_LEVEL;
    uint64 public immutable MAX_CEILING;
    uint64 public immutable MAX_CAP0;
    uint64 public immutable MIN_DOUBLING;
    uint64 public immutable MIN_MIN_DEPOSIT;
    uint32 public immutable MIN_FLOOR;
    uint32 public immutable MIN_ALPHA_BPS;
    uint64 public immutable MIN_SLOW_SPAN;
    /// @notice No instance may let one attester vouch for more than this many base units.
    uint64 public immutable MAX_ATTEST_UNIT;
    /// @notice No instance's bucket (the most one proof can move) may exceed this.
    uint64 public immutable MAX_BUCKET_MAX;
    /// @notice No instance's bucket may refill faster than this per day.
    uint64 public immutable MAX_REFILL_PER_DAY;
    uint16 public immutable MAX_FEE_BPS;
    VaultDeployerV4 public immutable VAULT_DEPLOYER;
    RelayDeployerV5 public immutable RELAY_DEPLOYER;

    struct Instance {
        address vault;
        address relay;
        uint32 number;
    }

    uint32 public count;
    mapping(address => Instance) private byRelay;
    mapping(address => Instance) private byVault;
    Instance[] public instances;

    event InstanceCreated(uint32 indexed number, address indexed vault, address indexed relay, bytes32 salt);

    struct Limits {
        uint64 maxCeiling;
        uint64 maxCap0;
        uint64 minDoubling;
        uint64 minMinDeposit;
        uint32 minFloor;
        uint32 minAlphaBps;
        uint64 minSlowSpan;
        uint64 maxAttestUnit;
        uint64 maxBucketMax;
        uint64 maxRefillPerDay;
        uint16 maxFeeBps;
    }

    constructor(IRiscZeroVerifier verifier, bytes32 outboundImageId, bytes32 inboundImageId, IERC20 token, uint8 cmpLevel, Limits memory l) {
        require(address(verifier) != address(0) && address(token) != address(0), "factory: zero address");
        require(outboundImageId != bytes32(0) && inboundImageId != bytes32(0), "factory: zero image");
        require(cmpLevel != 0 && l.maxCeiling != 0 && l.maxCap0 != 0 && l.minDoubling != 0, "factory: zero limit");
        require(l.minMinDeposit != 0 && l.minFloor != 0 && l.minAlphaBps != 0 && l.minSlowSpan != 0, "factory: zero limit");
        require(l.maxAttestUnit != 0 && l.maxBucketMax != 0 && l.maxRefillPerDay != 0, "factory: zero limit");
        require(l.maxFeeBps <= 1_000, "factory: fee limit");
        VERIFIER = verifier;
        OUTBOUND_IMAGE_ID = outboundImageId;
        INBOUND_IMAGE_ID = inboundImageId;
        TOKEN = token;
        CMP_LEVEL = cmpLevel;
        MAX_CEILING = l.maxCeiling;
        MAX_CAP0 = l.maxCap0;
        MIN_DOUBLING = l.minDoubling;
        MIN_MIN_DEPOSIT = l.minMinDeposit;
        MIN_FLOOR = l.minFloor;
        MIN_ALPHA_BPS = l.minAlphaBps;
        MIN_SLOW_SPAN = l.minSlowSpan;
        MAX_ATTEST_UNIT = l.maxAttestUnit;
        MAX_BUCKET_MAX = l.maxBucketMax;
        MAX_REFILL_PER_DAY = l.maxRefillPerDay;
        MAX_FEE_BPS = l.maxFeeBps;
        VAULT_DEPLOYER = new VaultDeployerV4();
        RELAY_DEPLOYER = new RelayDeployerV5();
    }

    // ------------------------------------------------------------------ what an instance may be

    struct VaultParams {
        uint64 cap0;
        uint64 ceiling;
        uint64 doubling;
        uint64 minDeposit;
        uint64 bucketMax;
        uint64 refillPerDay;
        uint64 maxDeposit;
        uint16 feeBps;
        address feeAddress;
        bytes32 closeHash;
    }

    function checkVault(VaultParams memory v) public view {
        require(v.cap0 != 0 && v.cap0 <= MAX_CAP0, "factory: cap0");
        require(v.ceiling >= v.cap0 && v.ceiling <= MAX_CEILING, "factory: ceiling");
        require(v.doubling >= MIN_DOUBLING, "factory: doubling");
        require(v.minDeposit >= MIN_MIN_DEPOSIT, "factory: min deposit");
        require(v.bucketMax != 0 && v.bucketMax <= MAX_BUCKET_MAX, "factory: bucket");
        require(v.refillPerDay != 0 && v.refillPerDay <= MAX_REFILL_PER_DAY, "factory: refill");
        require(v.maxDeposit >= v.minDeposit && v.maxDeposit <= v.bucketMax, "factory: max deposit");
        require(v.feeBps <= MAX_FEE_BPS && (v.feeBps == 0 || v.feeAddress != address(0)), "factory: fee");
        require(v.closeHash != bytes32(0), "factory: close hash");
    }

    function checkRelay(KaspaRelayV5.Params memory r) public view {
        require(r.genesisBits != 0, "factory: genesis bits");
        require(r.tokenCovId != bytes32(0) && r.templateHash != bytes32(0), "factory: token");
        require(r.cmpLevel == CMP_LEVEL, "factory: cmp level");
        require(r.floor >= MIN_FLOOR, "factory: floor");
        require(r.alphaBps >= MIN_ALPHA_BPS && r.alphaBps < 10_000, "factory: alpha");
        require(r.slowSpan >= MIN_SLOW_SPAN, "factory: slow span");
        require(r.attestUnit != 0 && r.attestUnit <= MAX_ATTEST_UNIT, "factory: attest unit");
        require(r.minBurn >= MIN_MIN_DEPOSIT, "factory: min burn");
        require(r.minInstallment != 0, "factory: min installment");
    }

    // ------------------------------------------------------------------ addresses before deployment

    function vaultArgs(VaultParams memory v) public view returns (bytes memory) {
        return abi.encode(TOKEN, address(this), v.cap0, v.ceiling, v.doubling, v.minDeposit, v.bucketMax, v.refillPerDay, v.maxDeposit, v.feeBps, v.feeAddress, v.closeHash);
    }

    function relayArgs(address vault, KaspaRelayV5.Params memory r) public view returns (bytes memory) {
        return abi.encode(VERIFIER, OUTBOUND_IMAGE_ID, ISettlementV3(vault), r);
    }

    function create2Address(address creator, bytes32 salt, bytes memory initCode) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), creator, salt, keccak256(initCode))))));
    }

    /// @notice The vault's address for a salt and parameters; what the Kaspa covenant is pinned to before
    ///         anything is deployed on Ethereum.
    function predictVault(bytes32 salt, VaultParams memory v) public view returns (address) {
        return create2Address(address(VAULT_DEPLOYER), salt, VAULT_DEPLOYER.initCode(vaultArgs(v)));
    }

    function predictRelay(bytes32 salt, VaultParams memory v, KaspaRelayV5.Params memory r) public view returns (address) {
        return create2Address(address(RELAY_DEPLOYER), salt, RELAY_DEPLOYER.initCode(relayArgs(predictVault(salt, v), r)));
    }

    // ------------------------------------------------------------------ create

    /// @notice Deploys a vault and its relay as a pair, checks every constant, links them. Anyone may call;
    ///         what they get is an instance that cannot be weaker than this factory allows.
    function create(bytes32 salt, VaultParams memory v, KaspaRelayV5.Params memory r) external returns (address vault, address relay) {
        checkVault(v);
        checkRelay(r);
        // F17: an installment floor above the bucket would defer every burn larger than the bucket for good
        require(r.minInstallment <= v.bucketMax, "factory: min installment above the bucket");
        vault = VAULT_DEPLOYER.deploy(salt, vaultArgs(v));
        relay = RELAY_DEPLOYER.deploy(salt, relayArgs(vault, r));
        UsdcVaultV4(vault).setRelay(relay);

        uint32 n = ++count;
        Instance memory inst = Instance({vault: vault, relay: relay, number: n});
        byRelay[relay] = inst;
        byVault[vault] = inst;
        instances.push(inst);
        emit InstanceCreated(n, vault, relay, salt);
    }

    // ------------------------------------------------------------------ the check anyone can run

    /// @notice True only for a relay or a vault this factory deployed.
    function isInstance(address a) external view returns (bool) {
        return byRelay[a].relay == a || byVault[a].vault == a;
    }

    function instanceOf(address a) external view returns (Instance memory) {
        Instance memory i = byRelay[a];
        if (i.relay == a) return i;
        i = byVault[a];
        require(i.vault == a, "factory: not an instance");
        return i;
    }
}
