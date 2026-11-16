// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlementV2} from "./ISettlementV2.sol";
import {UsdcVaultV2, IERC20} from "./UsdcVaultV2.sol";
import {KaspaRelayV3} from "./KaspaRelayV3.sol";

/// @notice Holds the vault's creation code and deploys it by CREATE2 for its factory only. The v2 vault and v3
///         relay together outgrew the EIP-170 runtime limit of one factory contract (RelayFactory v1 carried
///         both creation codes in its runtime); the factory now deploys the two deployers in its own constructor
///         and keeps only their addresses. The creation code is still fixed at factory deployment and nothing
///         but the factory can call `deploy`.
contract VaultDeployerV2 {
    address public immutable FACTORY;

    constructor() {
        FACTORY = msg.sender;
    }

    function initCode(bytes memory args) public pure returns (bytes memory) {
        return abi.encodePacked(type(UsdcVaultV2).creationCode, args);
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
contract RelayDeployerV3 {
    address public immutable FACTORY;

    constructor() {
        FACTORY = msg.sender;
    }

    function initCode(bytes memory args) public pure returns (bytes memory) {
        return abi.encodePacked(type(KaspaRelayV3).creationCode, args);
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

/// @title RelayFactoryV2: the only way a Tipsy.k / USDC.k #1 bridge instance comes into being.
/// @notice RelayFactory (U5) for the v2 vault and the v3 relay. It fixes what a hostile deployer would otherwise
///         choose: the verifier, the outbound image, the token, the comparison level, and the minimum strength
///         of every constant, now including the release bucket: no instance can have a bucket larger than
///         MAX_BUCKET_MAX, a refill faster than MAX_REFILL_PER_DAY, or a MAX_DEPOSIT above its bucket. Holds no
///         keys, has no owner; raising a limit is a new factory.
///
/// Deployment order (U5, unchanged): the Kaspa side comes first, because the relay pins the token's covenant id,
/// which exists only after the bridge covenant's `init` on Kaspa, which in turn pins the vault's address.
/// CREATE2 resolves the cycle: `predictVault(salt, params)` is the vault's address before anything is deployed.
/// The CREATE2 creator is the vault deployer (not the factory), so the prediction uses its address.
contract RelayFactoryV2 {
    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable OUTBOUND_IMAGE_ID;
    bytes32 public immutable INBOUND_IMAGE_ID;
    IERC20 public immutable TOKEN;
    uint8 public immutable CMP_LEVEL;
    uint64 public immutable KNOWN_DAA;
    uint64 public immutable MAX_CEILING;
    uint64 public immutable MAX_CAP0;
    uint64 public immutable MIN_DOUBLING;
    uint64 public immutable MIN_MIN_DEPOSIT;
    uint32 public immutable MIN_FLOOR;
    uint32 public immutable MIN_ATTEST_FLOOR;
    uint64 public immutable MAX_ATTEST_UNIT;
    uint64 public immutable MIN_WINDOW_FLOOR;
    uint64 public immutable MAX_WINDOW_UNIT;
    /// @notice No instance's bucket (the most one proof can move) may exceed this.
    uint64 public immutable MAX_BUCKET_MAX;
    /// @notice No instance's bucket may refill faster than this per day.
    uint64 public immutable MAX_REFILL_PER_DAY;
    VaultDeployerV2 public immutable VAULT_DEPLOYER;
    RelayDeployerV3 public immutable RELAY_DEPLOYER;

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
        uint64 knownDaa;
        uint64 maxCeiling;
        uint64 maxCap0;
        uint64 minDoubling;
        uint64 minMinDeposit;
        uint32 minFloor;
        uint32 minAttestFloor;
        uint64 maxAttestUnit;
        uint64 minWindowFloor;
        uint64 maxWindowUnit;
        uint64 maxBucketMax;
        uint64 maxRefillPerDay;
    }

    constructor(IRiscZeroVerifier verifier, bytes32 outboundImageId, bytes32 inboundImageId, IERC20 token, uint8 cmpLevel, Limits memory l) {
        require(address(verifier) != address(0) && address(token) != address(0), "factory: zero address");
        require(outboundImageId != bytes32(0) && inboundImageId != bytes32(0), "factory: zero image");
        require(cmpLevel != 0 && l.maxCeiling != 0 && l.maxCap0 != 0 && l.minDoubling != 0, "factory: zero limit");
        require(l.minMinDeposit != 0 && l.minFloor != 0 && l.minAttestFloor != 0 && l.maxAttestUnit != 0, "factory: zero limit");
        require(l.minWindowFloor != 0 && l.maxWindowUnit != 0 && l.maxBucketMax != 0 && l.maxRefillPerDay != 0, "factory: zero limit");
        VERIFIER = verifier;
        OUTBOUND_IMAGE_ID = outboundImageId;
        INBOUND_IMAGE_ID = inboundImageId;
        TOKEN = token;
        CMP_LEVEL = cmpLevel;
        KNOWN_DAA = l.knownDaa;
        MAX_CEILING = l.maxCeiling;
        MAX_CAP0 = l.maxCap0;
        MIN_DOUBLING = l.minDoubling;
        MIN_MIN_DEPOSIT = l.minMinDeposit;
        MIN_FLOOR = l.minFloor;
        MIN_ATTEST_FLOOR = l.minAttestFloor;
        MAX_ATTEST_UNIT = l.maxAttestUnit;
        MIN_WINDOW_FLOOR = l.minWindowFloor;
        MAX_WINDOW_UNIT = l.maxWindowUnit;
        MAX_BUCKET_MAX = l.maxBucketMax;
        MAX_REFILL_PER_DAY = l.maxRefillPerDay;
        VAULT_DEPLOYER = new VaultDeployerV2();
        RELAY_DEPLOYER = new RelayDeployerV3();
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
    }

    function checkVault(VaultParams memory v) public view {
        require(v.cap0 != 0 && v.cap0 <= MAX_CAP0, "factory: cap0");
        require(v.ceiling >= v.cap0 && v.ceiling <= MAX_CEILING, "factory: ceiling");
        require(v.doubling >= MIN_DOUBLING, "factory: doubling");
        require(v.minDeposit >= MIN_MIN_DEPOSIT, "factory: min deposit");
        require(v.bucketMax != 0 && v.bucketMax <= MAX_BUCKET_MAX, "factory: bucket");
        require(v.refillPerDay != 0 && v.refillPerDay <= MAX_REFILL_PER_DAY, "factory: refill");
        require(v.maxDeposit >= v.minDeposit && v.maxDeposit <= v.bucketMax, "factory: max deposit");
    }

    function checkRelay(KaspaRelayV3.Params memory r) public view {
        require(r.checkpoint != bytes32(0) && r.checkpointDaa > KNOWN_DAA, "factory: checkpoint");
        require(r.tokenCovId != bytes32(0) && r.templateHash != bytes32(0), "factory: token");
        require(r.cmpLevel == CMP_LEVEL, "factory: cmp level");
        require(r.floor >= MIN_FLOOR, "factory: floor");
        require(r.attestFloor >= MIN_ATTEST_FLOOR, "factory: attest floor");
        require(r.attestUnit != 0 && r.attestUnit <= MAX_ATTEST_UNIT, "factory: attest unit");
        require(r.windowFloor >= MIN_WINDOW_FLOOR, "factory: window floor");
        require(r.windowUnit != 0 && r.windowUnit <= MAX_WINDOW_UNIT, "factory: window unit");
    }

    // ------------------------------------------------------------------ addresses before deployment

    function vaultArgs(VaultParams memory v) public view returns (bytes memory) {
        return abi.encode(TOKEN, address(this), v.cap0, v.ceiling, v.doubling, v.minDeposit, v.bucketMax, v.refillPerDay, v.maxDeposit);
    }

    function relayArgs(address vault, KaspaRelayV3.Params memory r) public view returns (bytes memory) {
        return abi.encode(VERIFIER, OUTBOUND_IMAGE_ID, ISettlementV2(vault), r);
    }

    function create2Address(address creator, bytes32 salt, bytes memory initCode) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), creator, salt, keccak256(initCode))))));
    }

    /// @notice The vault's address for a salt and parameters; what the Kaspa covenant is pinned to before
    ///         anything is deployed on Ethereum.
    function predictVault(bytes32 salt, VaultParams memory v) public view returns (address) {
        return create2Address(address(VAULT_DEPLOYER), salt, VAULT_DEPLOYER.initCode(vaultArgs(v)));
    }

    function predictRelay(bytes32 salt, VaultParams memory v, KaspaRelayV3.Params memory r) public view returns (address) {
        return create2Address(address(RELAY_DEPLOYER), salt, RELAY_DEPLOYER.initCode(relayArgs(predictVault(salt, v), r)));
    }

    // ------------------------------------------------------------------ create

    /// @notice Deploys a vault and its relay as a pair, checks every constant, links them. Anyone may call;
    ///         what they get is an instance that cannot be weaker than this factory allows.
    function create(bytes32 salt, VaultParams memory v, KaspaRelayV3.Params memory r) external returns (address vault, address relay) {
        checkVault(v);
        checkRelay(r);
        vault = VAULT_DEPLOYER.deploy(salt, vaultArgs(v));
        relay = RELAY_DEPLOYER.deploy(salt, relayArgs(vault, r));
        UsdcVaultV2(vault).setRelay(relay);

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
