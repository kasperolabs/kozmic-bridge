# vault: Ethereum side of the Kaspa ZK bridge (CP-3)

Two contracts on Ethereum mainnet, deployed with Foundry from a throwaway key:

- `src/Vault.sol`: `deposit(uint64 amount, bytes kaspaSpk)` pulls `amount` of the token
  (`transferFrom`, so `approve` first), increments `nonce`, stores `deposits[nonce]` and emits
  `Deposited`. No owner, no withdraw, no pause, no upgrade, no other function. Tokens that go in
  stay in; v1 of the bridge is one-way by design (handoff section 5).
- `src/TestToken.sol`: plain ERC-20 "Kaspero Bridge Test" (KBT), 6 decimals, 1,000,000 KBT minted
  to the deployer, nothing else. The asset the bridge locks while the loop is proven out, so nothing
  of value is locked forever. USDC later, same vault code.

The guest (`eth-prover`, CP-2) proves `deposits[nonce]` against the Ethereum state root of a
finalized block and commits `(nonce, amount, kaspa_spk)` to its journal. The storage layout below is
therefore a contract between `Vault.sol` and `eth-prover/primitives/src/lib.rs::vault_layout`;
`test/Vault.t.sol` asserts it with `vm.load`.

## Solidity has no `bytes33`

The handoff wrote the recipient as `bytes33 kaspaSpk`. Solidity's fixed byte types stop at
`bytes32`, so the ABI takes `bytes calldata kaspaSpk` and requires length 33, and storage splits it
into a version byte and a 32-byte payload. The 33 bytes are: Kaspa address **version byte** (0 =
P2PK Schnorr, 8 = P2SH; ECDSA version 1 is refused) followed by the 32-byte **address payload**.
`bin/kaspa-spk.mjs` converts a `kaspa:` address to and from this form. The covenant (CP-6) turns
them into the KCC-20 token state of the minted UTXO: owner identifier = payload, owner type =
pubkey (0x00) for version 0 and script hash (0x01) for version 8; the same key or script that
would spend a plain P2PK / P2SH output spends the token (`bridge/README.md`).

## Storage layout (frozen 2026-10-12)

| where | what |
|---|---|
| slot 0 | `nonce`, uint64 in the low 8 bytes of the word. First deposit is nonce 1; nonce 0 never exists. |
| slot 1 | `deposits` mapping base slot. Holds nothing itself (always zero). |
| `k0 = keccak256(abi.encode(uint256(n), uint256(1)))` | `deposits[n]` word 0: bits 0..63 `amount` (uint64), bits 64..71 `kaspaVersion` (uint8), bits 72..255 zero |
| `k0 + 1` | `deposits[n]` word 1: `kaspaPayload` (bytes32, the whole word) |

`token` is `immutable`, so it lives in code and takes no slot. `forge inspect Vault storage-layout`
prints exactly `nonce` at slot 0 and `deposits` at slot 1.

For the guest a deposit is therefore two `eth_getProof` storage proofs (word 0 and word 1) under one
account proof. Word 0 is rejected unless bits 72..255 are zero, the amount is nonzero and the version
is 0 or 8; word 1 is rejected if zero. Both conditions are also enforced by `deposit()`, so every
deposit the contract ever writes is provable, and a zero word (an absent key in the trie) can never
be claimed as a deposit.

Sanity check from an anvil run of `script/Deploy.s.sol` (block 4, the deposit tx):

```
nonce (slot 0): 0x0000000000000000000000000000000000000000000000000000000000000001
mapping base 1: 0x0000000000000000000000000000000000000000000000000000000000000000
key0 (word 0) : 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f    (= cast index uint256 1 1)
word 0        : 0x00000000000000000000000000000000000000000000000000000000000f4240    (amount 1000000, version 0)
key1 (word 1) : 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b6887930
word 1        : 0x0102030405060708091011121314151617181920212223242526272829303132    (payload)
```

The guest's `verify_vault_deposits` ran verbatim over that run's `eth_getProof` output against the
block's state root and accepted it; a tampered amount and a wrong state root were both rejected.
`eth-prover/primitives` unit tests pin `word0_key(1)` / `word1_key(1)` to the two keys above.

## Gas (measured on anvil, Cancun, solc 0.8.28, optimizer 200 runs)

| tx | gas used |
|---|---|
| deploy TestToken | 397,056 |
| deploy Vault | 410,390 |
| approve | 46,115 |
| deposit (first, two fresh slots) | 126,766 |
| total | 980,327 (forge's estimate with its 30% buffer: 1,292,215) |

## Files

```
vault/
  foundry.toml            solc 0.8.28, cancun, optimizer 200
  src/Vault.sol
  src/TestToken.sol
  script/Deploy.s.sol     deploy both, approve, first deposit (4 txs; dry run = gas estimate)
  test/Vault.t.sol        storage-layout assertions, rejections, nonce sequence
  verify-storage.sh       reads deposits[N] from mainnet storage and decodes it
  lib/forge-std           git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
```

## Procedure (what was run; the mainnet record below has the results)

```
cd ~/kaspa-zk/kaspa-zk-tests/vault
git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
forge build && forge test -vv
forge inspect Vault storage-layout

# recipient for the test deposit (any P2PK or P2SH address of ours)
KASPA_SPK=$(node ../bin/kaspa-spk.mjs kaspa:...)

# the key file is "address<TAB>privatekey"; never cat it into a command line
KEY=$(cut -f2 ../eth-deployer-key.txt | tr -d '[:space:]')
# gas estimate, unfunded key is fine (simulation only)
KASPA_SPK=$KASPA_SPK forge script script/Deploy.s.sol --rpc-url $(cat ../eth-rpc-url.txt) --private-key $KEY
# fund the deployer with the printed "Estimated amount required" plus margin, then:
KASPA_SPK=$KASPA_SPK forge script script/Deploy.s.sol --rpc-url $(cat ../eth-rpc-url.txt) --private-key $KEY --broadcast
# txids and addresses: broadcast/Deploy.s.sol/1/run-latest.json (python3 -c to read it; jq is not on the box)
./verify-storage.sh <vault> 1
```

## Mainnet record (2026-10-12, 19:10 UTC)

Deployed and exercised with `script/Deploy.s.sol --broadcast` in one run; gas used matched the anvil
numbers exactly. Total cost 0.000125 ETH at a 0.12 gwei base fee.

| item | value |
|---|---|
| deployer (throwaway key, `eth-deployer-key.txt`) | `0x4aC7b1478afeaf28a4c62d59160Ad4c81C229105` |
| TestToken (KBT) | [`0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004`](https://etherscan.io/address/0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004) |
| Vault | [`0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529`](https://etherscan.io/address/0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529) |
| deploy TestToken, block 26,178,398, 397,056 gas | [`0x0a8207c021f1989357c1457e759651e1cab88997fc746449e7779c044e8f1ebf`](https://etherscan.io/tx/0x0a8207c021f1989357c1457e759651e1cab88997fc746449e7779c044e8f1ebf) |
| deploy Vault, block 26,178,399, 410,390 gas | [`0x5a0628f56e004319c4253d07c52e900e45ae2a6dd1c9211954de42f3799b2f5a`](https://etherscan.io/tx/0x5a0628f56e004319c4253d07c52e900e45ae2a6dd1c9211954de42f3799b2f5a) |
| approve, block 26,178,399, 46,115 gas | [`0x2f8af465c1a42149827eb082eaad704c99779cb43e577ceb1e3d718be1a370a4`](https://etherscan.io/tx/0x2f8af465c1a42149827eb082eaad704c99779cb43e577ceb1e3d718be1a370a4) |
| deposit #1, block 26,178,399, 126,766 gas | [`0x2d59f64ebc4ad26e5d3c0892692d47f4fa2f2d506e6703444efd9c0f90bdd7a7`](https://etherscan.io/tx/0x2d59f64ebc4ad26e5d3c0892692d47f4fa2f2d506e6703444efd9c0f90bdd7a7) |
| deposit #1 | nonce 1, amount 1000000 (1.000000 KBT), kaspa_spk `0x00856bc60330866c89f02fc502c265416b906e4c4eb7b2bab38af18c6f36e6829c` = `kaspa:qzzkh3srxzrxez0s9lzs9sn9g94eqmjvf6mm9w4n3tcccmeku6pfc5vuun3t2` (P2PK, the bridge genesis key) |
| approve #2, block 26,178,685, 46,115 gas | [`0x0e85eec16749de78c9eb314b3c0ca1ec5e20230617953302ef0806ec448fbd79`](https://etherscan.io/tx/0x0e85eec16749de78c9eb314b3c0ca1ec5e20230617953302ef0806ec448fbd79) |
| deposit #2, block 26,178,686, 92,566 gas (`cast send`, 2026-10-12 20:08 UTC) | [`0x73cba55994da8a55a586d7b6b29669d1ea450c7b6ef40eb4b7143bf04265c721`](https://etherscan.io/tx/0x73cba55994da8a55a586d7b6b29669d1ea450c7b6ef40eb4b7143bf04265c721) |
| deposit #2 | nonce 2, amount 2500000 (2.500000 KBT), kaspa_spk `0x005bf352ff28b58d2dc6038893f344305073d027f87aac8e3a880b4dbde517eaed` = `kaspa:qpdlx5hl9z6c6twxqwyf8u6yxpg885p8lpa2er363q95m009zl4w629zj9juj` (P2PK, Oz's Kasla wallet). Keys `0xd9d16d34…330f` / `…3310`, word 0 `0x…2625a0`. A later deposit costs 92,566 gas (the nonce slot is already nonzero). |

`verify-storage.sh 0x3DD8… 1` against mainnet:

```
nonce (slot 0): 0x0000000000000000000000000000000000000000000000000000000000000001
mapping base 1: 0x0000000000000000000000000000000000000000000000000000000000000000
key0 (word 0) : 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f
word 0        : 0x00000000000000000000000000000000000000000000000000000000000f4240
key1 (word 1) : 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b6887930
word 1        : 0x856bc60330866c89f02fc502c265416b906e4c4eb7b2bab38af18c6f36e6829c
getter        : 1000000 0 0x856bc6…829c      vault KBT balance: 1000000
eth_getProof  : storageHash 0x9704eaef…, account proof 9 nodes, 2 nodes per slot
```

Deposit #1 was first proven on its own inside the mainnet-spec guest against finalized exec block
26,178,455 (image `4756d736…`, bundle `eth-prover/out-deposit-1/`); see `eth-prover/README.md`.

## Where the deposits ended up (CP-6, Kaspa mainnet, 2026-10-12 20:56 UTC)

Both deposits were proven in one journal against finalized exec block 26,178,742
(`eth-prover/out-deposit-12/`, 55.2M cycles, 208 s GPU + 71 s wrap) and minted by one Kaspa
transaction, with no signature anywhere on the Kaspa side:

| Ethereum deposit | Kaspa result |
|---|---|
| #1, 1.000000 KBT to `kaspa:qzzkh3…` | KCC-20 UTXO `e108d4161c14883e05940c933b616acbc119a0163e2380e16ef9782481d00f99:2`, 1,000,000 units, owner = that key; later spent wallet-side (tx `6cf4a2af…`: 0.4 to `kaspa:qpdlx5…`, 0.6 change) |
| #2, 2.500000 KBT to `kaspa:qpdlx5…` (Oz's Kasla wallet) | KCC-20 UTXO `e108d416…:3`, 2,500,000 units, owner = that key |

Token: KCC-20 covenant `87b503510d715acfa3cca82f245e696593c30d78dde70e11e69afa88b3d03a3f`, 6 decimals,
minter branch owned by bridge covenant `ac21e83194b0beb1ae8c932a4734984f692ab982f6739037af6f979aef0dea0b`
(`bridge/README.md`). The vault holds 3.5 KBT, the token supply on Kaspa is 3.5 KBT.

## Notes from the deploy

- `eth-deployer-key.txt` holds `address<TAB>privatekey` on one line (the `cast wallet new` table row).
  `cast wallet address --private-key $(cat file)` tolerates the two-word expansion, `forge script` does
  not: use `KEY=$(cut -f2 ../eth-deployer-key.txt | tr -d '[:space:]')`.
- `forge script` dry runs work from an unfunded key (local simulation does not charge gas); forge's
  "Estimated amount required" includes a 30% gas buffer.
- Contracts are not source-verified on Etherscan (no API key). `forge verify-contract --verifier sourcify`
  needs no key if that ever matters; the bytecode is reproducible from this directory (solc 0.8.28,
  optimizer 200 runs, cancun).
