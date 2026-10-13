# vault: the Ethereum side of the bridge

Two contracts on Ethereum mainnet, deployed with Foundry from a throwaway key:

- `src/Vault.sol`: `deposit(uint64 amount, bytes kaspaSpk)` pulls `amount` of the token
  (`transferFrom`, so `approve` first), increments `nonce`, stores `deposits[nonce]` and emits
  `Deposited`. No owner, no withdraw, no pause, no upgrade, no other function. Tokens that go in
  stay in; this version of the bridge is one-way by design.
- `src/TestToken.sol`: plain ERC-20 "Kaspero Bridge Test" (KBT), 6 decimals, 1,000,000 KBT minted
  to the deployer, nothing else. The asset the bridge locks while the loop is proven out, so nothing
  of value is locked forever.

The proven program (`eth-prover`) proves `deposits[nonce]` against the Ethereum state root of a
finalized block and commits `(nonce, amount, kaspa_spk)` to its journal. The storage layout below is
therefore a contract between `Vault.sol` and `eth-prover/primitives/src/lib.rs::vault_layout`;
`test/Vault.t.sol` asserts it with `vm.load`.

The comments inside `Vault.sol` still carry the internal checkpoint labels used while building it
(CP-2, CP-3, CP-6). They are left unchanged on purpose: the deployed bytecode embeds a hash of the
source (Solidity metadata), so editing a comment would make the bytecode no longer reproducible from
this directory.

## The Kaspa recipient: 33 bytes

Solidity's fixed byte types stop at `bytes32`, so the ABI takes `bytes calldata kaspaSpk` and
requires length 33, and storage splits it into a version byte and a 32-byte payload. The 33 bytes
are: Kaspa address **version byte** (0 = P2PK Schnorr, 8 = P2SH; ECDSA version 1 is refused)
followed by the 32-byte **address payload**. `bin/kaspa-spk.mjs` converts a `kaspa:` address to and
from this form. The covenant turns them into the KCC-20 token state of the minted UTXO: owner
identifier = payload, owner type = pubkey (0x00) for version 0 and script hash (0x01) for version 8;
the same key or script that would spend a plain P2PK / P2SH output spends the token
(`bridge/README.md`).

## Storage layout (frozen 2026-10-12)

| where | what |
|---|---|
| slot 0 | `nonce`, uint64 in the low 8 bytes of the word. First deposit is nonce 1; nonce 0 never exists. |
| slot 1 | `deposits` mapping base slot. Holds nothing itself (always zero). |
| `k0 = keccak256(abi.encode(uint256(n), uint256(1)))` | `deposits[n]` word 0: bits 0..63 `amount` (uint64), bits 64..71 `kaspaVersion` (uint8), bits 72..255 zero |
| `k0 + 1` | `deposits[n]` word 1: `kaspaPayload` (bytes32, the whole word) |

`token` is `immutable`, so it lives in code and takes no slot. `forge inspect Vault storage-layout`
prints exactly `nonce` at slot 0 and `deposits` at slot 1.

For the proven program a deposit is therefore two `eth_getProof` storage proofs (word 0 and word 1)
under one account proof. Word 0 is rejected unless bits 72..255 are zero, the amount is nonzero and
the version is 0 or 8; word 1 is rejected if zero. Both conditions are also enforced by `deposit()`,
so every deposit the contract ever writes is provable, and a zero word (an absent key in the trie)
can never be claimed as a deposit.

Sanity check from an anvil run of `script/Deploy.s.sol` (block 4, the deposit tx):

```
nonce (slot 0): 0x0000000000000000000000000000000000000000000000000000000000000001
mapping base 1: 0x0000000000000000000000000000000000000000000000000000000000000000
key0 (word 0) : 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f    (= cast index uint256 1 1)
word 0        : 0x00000000000000000000000000000000000000000000000000000000000f4240    (amount 1000000, version 0)
key1 (word 1) : 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b6887930
word 1        : 0x0102030405060708091011121314151617181920212223242526272829303132    (payload)
```

The program's `verify_vault_deposits` ran verbatim over that run's `eth_getProof` output against the
block's state root and accepted it; a tampered amount and a wrong state root were both rejected.
`eth-prover/primitives` unit tests pin `word0_key(1)` / `word1_key(1)` to the two keys above.

## Gas (measured on anvil, Cancun, solc 0.8.28, optimizer 200 runs; mainnet matched exactly)

| tx | gas used |
|---|---|
| deploy TestToken | 397,056 |
| deploy Vault | 410,390 |
| approve | 46,115 |
| deposit (first, two fresh slots) | 126,766 |
| deposit (later; the nonce slot is already nonzero) | 92,566 |

## Files

```
vault/
  foundry.toml            solc 0.8.28, cancun, optimizer 200
  src/Vault.sol
  src/TestToken.sol
  script/Deploy.s.sol     deploy both, approve, first deposit (4 txs; dry run = gas estimate)
  test/Vault.t.sol        storage-layout assertions, rejections, nonce sequence
  verify-storage.sh       reads deposits[N] from mainnet storage and decodes it
  broadcast/              forge's record of the mainnet deployment (run-latest.json)
  lib/forge-std           git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
```

## Build, test, deploy

```
cd vault
git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
forge build && forge test -vv
forge inspect Vault storage-layout

# recipient for a test deposit (any P2PK or P2SH Kaspa address)
KASPA_SPK=$(node ../bin/kaspa-spk.mjs kaspa:...)

# a key file holding "address<TAB>privatekey"; never paste a key into a command line
KEY=$(cut -f2 ../eth-deployer-key.txt | tr -d '[:space:]')
# gas estimate: an unfunded key is fine (simulation only)
KASPA_SPK=$KASPA_SPK forge script script/Deploy.s.sol --rpc-url $(cat ../eth-rpc-url.txt) --private-key $KEY
# fund the deployer with the printed "Estimated amount required" plus margin, then:
KASPA_SPK=$KASPA_SPK forge script script/Deploy.s.sol --rpc-url $(cat ../eth-rpc-url.txt) --private-key $KEY --broadcast
./verify-storage.sh <vault address> 1
```

A deposit to the live vault (the token must be approved first):

```
cast send --rpc-url $RPC --private-key $KEY 0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004 "approve(address,uint256)" 0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529 <amount>
cast send --rpc-url $RPC --private-key $KEY 0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529 "deposit(uint64,bytes)" <amount> <kaspa_spk>
cast storage --rpc-url $RPC 0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529 0     # the deposit counter
```

## Mainnet record (2026-10-12 and 2026-10-13)

Deployed and exercised with `script/Deploy.s.sol --broadcast` in one run. Total deploy cost
0.000125 ETH at a 0.12 gwei base fee.

| item | value |
|---|---|
| deployer (throwaway key) | `0x4aC7b1478afeaf28a4c62d59160Ad4c81C229105` |
| TestToken (KBT) | [`0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004`](https://etherscan.io/address/0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004) |
| Vault | [`0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529`](https://etherscan.io/address/0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529) |
| deploy TestToken, block 26,178,398 | [`0x0a8207c0…1ebf`](https://etherscan.io/tx/0x0a8207c021f1989357c1457e759651e1cab88997fc746449e7779c044e8f1ebf) |
| deploy Vault, block 26,178,399 | [`0x5a0628f5…2f5a`](https://etherscan.io/tx/0x5a0628f56e004319c4253d07c52e900e45ae2a6dd1c9211954de42f3799b2f5a) |
| approve, block 26,178,399 | [`0x2f8af465…70a4`](https://etherscan.io/tx/0x2f8af465c1a42149827eb082eaad704c99779cb43e577ceb1e3d718be1a370a4) |
| **deposit #1**, block 26,178,399: 1.000000 KBT to `kaspa:qzzkh3srxzrxez0s9lzs9sn9g94eqmjvf6mm9w4n3tcccmeku6pfc5vuun3t2` | [`0x2d59f64e…d7a7`](https://etherscan.io/tx/0x2d59f64ebc4ad26e5d3c0892692d47f4fa2f2d506e6703444efd9c0f90bdd7a7) |
| **deposit #2**, block 26,178,686: 2.500000 KBT to `kaspa:qpdlx5hl9z6c6twxqwyf8u6yxpg885p8lpa2er363q95m009zl4w629zj9juj` | [`0x73cba559…c721`](https://etherscan.io/tx/0x73cba55994da8a55a586d7b6b29669d1ea450c7b6ef40eb4b7143bf04265c721) |
| **deposit #3**, block 26,180,018 (2026-10-13 00:35 UTC): 0.500000 KBT to `kaspa:qpdlx5…`, made while the prover service ran, nothing else done | [`0x29e6f6a8…19b0`](https://etherscan.io/tx/0x29e6f6a874164b38c556abd32dbcfb3adc262e06238b46bfb8f3ce4107a419b0) |

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

## Where the deposits ended up on Kaspa

| Ethereum deposit | Kaspa result |
|---|---|
| #1, 1.0 KBT | KCC-20 UTXO `e108d416…:2` (tx `e108d4161c14883e05940c933b616acbc119a0163e2380e16ef9782481d00f99`, deposits #1 and #2 minted together); later spent wallet-side, tx `6cf4a2af…`: 0.4 to `kaspa:qpdlx5…`, 0.6 change |
| #2, 2.5 KBT | KCC-20 UTXO `e108d416…:3` |
| #3, 0.5 KBT | KCC-20 UTXO `568bedc5…:2` (tx `568bedc542e6ed51ce6ecbbef0968a730d43b049f95150d37960ca7a86f44aaf`), minted by the prover service 18.5 minutes after the deposit block |

Token: KCC-20 covenant `87b503510d715acfa3cca82f245e696593c30d78dde70e11e69afa88b3d03a3f`, 6 decimals.
The vault holds 4.0 KBT; the token supply on Kaspa is 4.0 KBT.

## Notes

- `forge script` dry runs work from an unfunded key (local simulation does not charge gas); forge's
  "Estimated amount required" includes a 30% gas buffer.
- Foundry writes RPC URLs into `cache/` during a broadcast. `cache/` and `out/` are git-ignored here;
  check before committing a fork of this directory.
- Contracts are not source-verified on Etherscan. `forge verify-contract --verifier sourcify` needs no
  key; the bytecode is reproducible from this directory (solc 0.8.28, optimizer 200 runs, cancun).
