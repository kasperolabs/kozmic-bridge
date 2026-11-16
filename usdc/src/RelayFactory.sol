// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {ISettlement} from "./ISettlement.sol";
import {UsdcVault, IERC20} from "./UsdcVault.sol";
import {KaspaRelayV2} from "./KaspaRelayV2.sol";

/// @title RelayFactory: the only way a Kaspero USDC bridge instance comes into being.
/// @notice One factory per chain and per review tier. It fixes what a hostile deployer would otherwise choose:
///         the RISC Zero verifier, the outbound guest image, the token, the comparison level, the schedule's
///         shape and the minimum strength of every constant. An instance that `isInstance` reports true for has
///         at least these protections, whatever its deployer intended. The factory holds no keys and has no
///         owner; raising the review tier (a higher MAX_CEILING after outside review) is a new factory.
///
/// Deployment order (U5): the Kaspa side comes first, because the relay pins the wUSDC token's covenant id and
/// that id only exists after the bridge covenant's `init` on Kaspa, which in turn pins the vault's address.
/// CREATE2 resolves the cycle: `predictVault(salt, ...)` is the vault's address before anything is deployed.
///   1. pick a salt; read `predictVault`;
///   2. on Kaspa: bridge covenant genesis pinned to that vault address, `init` -> token covenant id;
///   3. `create(salt, vault params, relay params with that token id)`: vault, relay, `setRelay`, one transaction.
///
/// The inbound guest image id is pinned by the Kaspa covenant, not by Ethereum; it is recorded here only so a
/// page can show one place to compare both ids against the reproducible builds.
contract RelayFactory {
    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable OUTBOUND_IMAGE_ID;
    bytes32 public immutable INBOUND_IMAGE_ID;
    IERC20 public immutable TOKEN;
    uint8 public immutable CMP_LEVEL;
    /// @notice An instance's initial checkpoint must have a DAA score above this (a known mainnet block at
    ///         factory deployment), so no instance can start from a fabricated past.
    uint64 public immutable KNOWN_DAA;
    /// @notice The review tier: no instance from this factory can ever hold more than this.
    uint64 public immutable MAX_CEILING;
    uint64 public immutable MAX_CAP0;
    uint64 public immutable MIN_DOUBLING;
    uint64 public immutable MIN_MIN_DEPOSIT;
    uint32 public immutable MIN_FLOOR;
    uint32 public immutable MIN_ATTEST_FLOOR;
    /// @notice Weaker than this (more base units per attester) is refused.
    uint64 public immutable MAX_ATTEST_UNIT;
    uint64 public immutable MIN_WINDOW_FLOOR;
    /// @notice Weaker than this (more base units per extra hour) is refused.
    uint64 public immutable MAX_WINDOW_UNIT;

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
    }

    constructor(IRiscZeroVerifier verifier, bytes32 outboundImageId, bytes32 inboundImageId, IERC20 token, uint8 cmpLevel, Limits memory l) {
        require(address(verifier) != address(0) && address(token) != address(0), "factory: zero address");
        require(outboundImageId != bytes32(0) && inboundImageId != bytes32(0), "factory: zero image");
        require(cmpLevel != 0 && l.maxCeiling != 0 && l.maxCap0 != 0 && l.minDoubling != 0, "factory: zero limit");
        require(l.minMinDeposit != 0 && l.minFloor != 0 && l.minAttestFloor != 0 && l.maxAttestUnit != 0, "factory: zero limit");
        require(l.minWindowFloor != 0 && l.maxWindowUnit != 0, "factory: zero limit");
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
    }

    // ------------------------------------------------------------------ what an instance may be

    struct VaultParams {
        uint64 cap0;
        uint64 ceiling;
        uint64 doubling;
        uint64 minDeposit;
    }

    function checkVault(VaultParams memory v) public view {
        require(v.cap0 != 0 && v.cap0 <= MAX_CAP0, "factory: cap0");
        require(v.ceiling >= v.cap0 && v.ceiling <= MAX_CEILING, "factory: ceiling");
        require(v.doubling >= MIN_DOUBLING, "factory: doubling");
        require(v.minDeposit >= MIN_MIN_DEPOSIT, "factory: min deposit");
    }

    function checkRelay(KaspaRelayV2.Params memory r) public view {
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

    function vaultInitCode(VaultParams memory v) public view returns (bytes memory) {
        return abi.encodePacked(
            type(UsdcVault).creationCode,
            abi.encode(TOKEN, address(this), v.cap0, v.ceiling, v.doubling, v.minDeposit)
        );
    }

    function relayInitCode(address vault, KaspaRelayV2.Params memory r) public view returns (bytes memory) {
        return abi.encodePacked(
            type(KaspaRelayV2).creationCode,
            abi.encode(VERIFIER, OUTBOUND_IMAGE_ID, ISettlement(vault), r)
        );
    }

    function create2Address(bytes32 salt, bytes memory initCode) public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode))))));
    }

    /// @notice The vault's address for a salt and parameters; what the Kaspa covenant is pinned to before
    ///         anything is deployed on Ethereum.
    function predictVault(bytes32 salt, VaultParams memory v) public view returns (address) {
        return create2Address(salt, vaultInitCode(v));
    }

    function predictRelay(bytes32 salt, VaultParams memory v, KaspaRelayV2.Params memory r) public view returns (address) {
        return create2Address(salt, relayInitCode(predictVault(salt, v), r));
    }

    // ------------------------------------------------------------------ create

    /// @notice Deploys a vault and its relay as a pair, checks every constant, links them. Anyone may call;
    ///         what they get is an instance that cannot be weaker than this factory allows.
    function create(bytes32 salt, VaultParams memory v, KaspaRelayV2.Params memory r) external returns (address vault, address relay) {
        checkVault(v);
        checkRelay(r);
        bytes memory vc = vaultInitCode(v);
        bytes memory rc;
        assembly {
            vault := create2(0, add(vc, 0x20), mload(vc), salt)
        }
        require(vault != address(0), "factory: vault create2 failed");
        rc = relayInitCode(vault, r);
        assembly {
            relay := create2(0, add(rc, 0x20), mload(rc), salt)
        }
        require(relay != address(0), "factory: relay create2 failed");
        UsdcVault(vault).setRelay(relay);

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
