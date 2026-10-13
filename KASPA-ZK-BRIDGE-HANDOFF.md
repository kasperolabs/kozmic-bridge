# Kaspa L1 ZK bridge: working handoff

Purpose: a fresh session should be able to start building from this file alone.
Scope: one-way, trustless, capped bridge from Ethereum mainnet to Kaspa L1 mainnet (Oz's rule: no testnets;
the deposited asset during development is a self-minted ERC-20 so nothing of value is locked, USDC last),
minting a KCC-20 asset against deposits proven by a RISC Zero program. Stablecoin PoC = the same
bridge with USDC as the deposited asset. Target: working on mainnet (small cap, self-minted test token) in 1 to 2 weeks of focused work.

Author of record: Oz (Kaspero Labs). Built with Claude. Date of this handoff: 2026-10-11.
Last update: 2026-10-12 21:05 UTC. CP-1/CP-2 ported, measured on CPU and GPU, Docker image published, first bundle spent
on mainnet (tx c99d357a…). CP-4/CP-5 done: Silverscript BRIDGE covenant deployed on mainnet, two consecutive
transitions (txs 0fda7120…, d5fd63b5…), replay of the first proof rejected twice. CP-3 + CP-2 done: Vault.sol and
TestToken.sol on Ethereum mainnet, deposits #1 and #2 made, storage layout frozen, journal layout frozen (230 + 49n).
**CP-6 done 2026-10-12 20:52 to 20:58 UTC: the loop is closed on mainnet.** New bridge covenant `ac21e831…` (image
`4756d736…`, mainnet commitment, vault pinned, state `{header, committee, cursor, token}`), KCC-20 token `87b50351…`
(KBT on Kaspa, 6 decimals, minter branch owned by the bridge covenant id), one advance with a fresh proof of deposits
#1 and #2 minted both (tx `e108d416…`, budget 1562), replay rejected (`f6d8f759…`), a wallet-side KCC-20 transfer
spent a minted UTXO (`6cf4a2af…`). **Next: CP-7** (prover service: watch, prove, submit, heartbeat; no manual step).

---

## 1. What is already proven (do not re-derive)

All on Kaspa mainnet, node rusty-kaspa v2.1.0, SDK v2.1.0, risc0-zkvm 3.0.4. Ethereum side: mainnet, Foundry 1.8.5, solc 0.8.28.

| fact | evidence |
|---|---|
| `OpZkPrecompile` (0xa6) verifies Groth16/BN254 on mainnet | tx `8d7700f4c007c7f98082f03239416035b9af95b46e9015737f77a7e741097205` |
| Exact compute budget for a 5-input Groth16 P2SH spend: **1550** (`used=15,500,893` units) | tx `e1ee18140a6ec3a7e4745e9b175e5895bd6df45643ae41ea0f33e76866217a3b` |
| Covenant pinned to a RISC Zero **image id** via `ZkScriptBuilder.commitToGroth16`, opened with `finalizeWithGroth16Proof`; same budget 1550 | tx `c215f3774ca5cc8d640e227f6421c437cb9083f79f2327947a1acf5ead22c987` (SDK fixture receipt) |
| Same, with a program we wrote (melody guest, image id `cb56513fb90a208039ef1126c8a50a27fb3e555787ca0d47961edaf7582a337a`) | tx `9f7abc0c35441799a9dabf0295da3b5ad7f08b30a6d3a27721941c8fb83a3b62` |
| Both failure modes observed | corrupted proof bytes: `ARK serialization error`; valid proof, wrong public input: `Groth16 verification failed` |
| Proving cost of a tiny guest, Groth16 wrap via Docker, CPU only | 140 s |
| Ethereum light-client guest (eth-prover) builds at risc0 3.0.4 with accelerated BLS12-381 and executes a consensus-spec finality update in the zkVM | fixture run: 35.4M user cycles, 36 segments, minimal spec (32-member committee); journal matches the vector's expected header |
| **CPU proving time of that fixture, succinct (STARK + recursion, no Groth16 wrap), node box 12 cores / 62 GB, Kaspa node running alongside** | **6994.5 s (1 h 56 min)**, receipt verified. ~5,400 padded cycles/s end to end. Decision rule fired: GPU proving (rented per run) is the operating mode; CPU is the baseline only. |
| **Same fixture on a rented RTX 4090 (RunPod, $0.89/h), image `kasperolabs/eth-prover:cuda`** | **69.5 s** STARK + recursion (`prove --no-wrap`), then **72.6 s** Groth16 wrap on the node box via Docker (`eth-prover wrap`). First Groth16 bundle from the Ethereum guest: `eth-prover/out-fixture-gpu/`, image id (minimal-spec guest, Docker build) `d7c7337682e590949ef78256a572d6a497c3230a9352627596f3342a8e1b5859`. The CUDA Groth16 wrap itself crashes in sppark on that box ("illegal memory access"), so the split prove/wrap flow is the working one. |
| **That bundle opened a mainnet covenant pinned to the Ethereum guest's image id** (`r0spend.mjs`, budget 1550, journal-hash-flipped attempt rejected with `Groth16 verification failed` first) | tx `c99d357ae17554e77667e78810dc0e48e0262c10857c2cefd8b41b6fa1d20e8c`, covenant address `kaspa:pqxzwe50n33ep720ctqtumd3pdlmqjn6apugqjcvsqf66xd6dvy4urv5cnvdl`. |
| **Step 1 of the same vector (crosses a sync-committee period, carries the signed rotation), proven with `eth-prover fixture --step 1`** | 69.8M user cycles, 71 segments; **138.6 s** on an RTX 4090 (2.0x cycles, 2.0x time), **71.5 s** wrap. Bundle `eth-prover/out-fixture-step1/`, same image id `d7c73376…`. |
| **CP-4/CP-5: BRIDGE covenant (`bridge/bridge.sil`, Silverscript) test instance on mainnet.** Covenant id `4e97879a4fe9fee3814ccd1576ef9743fa511a42abd6eff4580abd66140c42a7`, pinned to image `d7c73376…` and the consensus-spec test chain's commitment `aa4a6036…` | genesis `9bece8dffc7066cc969eebfeebd0bfb66ea8babaf8a22d40e599560e811ea5b6` |
| Transition 1: step 0 proof, state `381b93f6… -> 811ca9d0…`. Budget **1551**: the node reported `used=15,510,880` at 1550 (local engine 15,511,029). Sigscript 1443 B, tx 1678 B, fee 0.3143 KAS at 2x minimum | tx `0fda7120a9fba8565edc5741da59d526e5d2aced9271ae17b49485e2ddbca26d` |
| Replay of the step 0 proof after transition 1 | rejected: `script ran, but verification failed` (tx `9a15bcec…`, never accepted) |
| Transition 2: step 1 proof, state `811ca9d0… -> 2eceb4af…`, budget 1551, node `used=15,510,880` again | tx `d5fd63b5933952fd2ffd629d7806a4ac659bb03328e117d8c94ae8df52f8ca52`; live UTXO `kaspa:pq2n5622tg57x47yu9szn2ak6rx9v3gp86l5y3vdz5l9umrdwux7ur6f9alum`, 0.871408 KAS (state file `bridge-state.json`, left as the CP-4/5 record) |
| Replay of the step 0 proof after transition 2 | rejected (tx `f81cfb8d…`, never accepted) |
| **First real Ethereum mainnet input (mainnet-spec guest, 512-member committee), fetched from ChainSafe's public Lodestar endpoint** (`https://lodestar-mainnet.chainsafe.io`; its `/config/spec` does not parse in helios 0.12, so `fetch` treats the chain-id check as non-fatal; signatures are checked against mainnet's genesis root anyway) | checkpoint_in `0x15cbb28a…` slot 15,416,736 -> finalized `0xaa341931…` slot 15,416,800, period 1881, participation 511/512, chain commitment `0xffc6300b0673ffdeaa10b11d162bc7bc375514c89e29dd03dc6eeabd88b0c90b`. **53.3M user cycles, 54 segments**, no rotation, no deposits. **107.3 s STARK** on an RTX 4090, **71.0 s wrap**, image `f1542762…` (CP-4/5 layout, superseded). Bundle `eth-prover/out-mainnet-1/`, never spent. |
| **CP-3: Vault.sol and TestToken.sol on Ethereum mainnet** (`vault/`, Foundry, solc 0.8.28). Vault: `deposit(uint64 amount, bytes kaspaSpk)`, 33-byte recipient (version byte + 32-byte payload), `nonce++`, `deposits[nonce] = {amount, kaspaVersion, kaspaPayload}`, no owner, no withdraw. TestToken: plain ERC-20 "Kaspero Bridge Test" (KBT), 6 decimals, 1,000,000 KBT to the deployer. Deployer `0x4aC7b1478afeaf28a4c62d59160Ad4c81C229105` (throwaway, 0.00287 ETH left). Gas 397,056 + 410,390 + 46,115 + 126,766 = 980,327 (0.000125 ETH at 0.12 gwei) | TestToken `0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004` (tx `0x0a8207c0…`, block 26,178,398); Vault `0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529` (tx `0x5a0628f5…`, block 26,178,399); approve `0x2f8af465…`; **deposit #1** tx `0x2d59f64ebc4ad26e5d3c0892692d47f4fa2f2d506e6703444efd9c0f90bdd7a7` (block 26,178,399): nonce 1, 1,000,000 (1.000000 KBT), kaspa_spk `0x00856bc6…829c` = `kaspa:qzzkh3srxzrxez0s9lzs9sn9g94eqmjvf6mm9w4n3tcccmeku6pfc5vuun3t2` (the bridge genesis key). **Deposit #2** (20:08 UTC, `cast send`): approve `0x0e85eec1…`, deposit tx `0x73cba55994da8a55a586d7b6b29669d1ea450c7b6ef40eb4b7143bf04265c721` (block 26,178,686, 92,566 gas): nonce 2, 2,500,000 (2.5 KBT), kaspa_spk `0x005bf352…eaed` = `kaspa:qpdlx5hl9z6c6twxqwyf8u6yxpg885p8lpa2er363q95m009zl4w629zj9juj` (Oz's Kasla wallet). Storage read back on mainnet per the layout table (`vault/README.md`). |
| **CP-2: deposit #1 proven inside the mainnet-spec guest, with the frozen journal layout.** Step `0xd034a38c…` (slot 15,417,248, period 1881) -> `0xa63ca480…` (slot 15,417,408, period 1882, one signed sync-committee rotation), participation 508/512, exec block 26,178,455. Journal 279 bytes = 230 + one 49-byte deposit | **104,501,905 user cycles, 106 segments**; **142.4 s STARK on an RTX 4090 (1.36 s per M cycles)**, **71.6 s wrap**. Image id (mainnet-spec guest, CP-2 layout, Docker build) **`4756d736d00cc0e5b813fd9bbb8fe586dbfe9cee524e61e79335cc2585413a50`** (node-box native build: `68a40a12…`, not pinnable). Journal hash `543f0f54…`, receipt 696 B borsh. Bundle `eth-prover/out-deposit-1/` (the engine tests' fixture). |
| **CP-6 proof: deposits #1 and #2 in one journal, no rotation.** Bootstrapped at the old checkpoint_out `0xa63ca480…` (Lodestar still served that bootstrap; no waiting for a new finality update), finalized `0x6dc6c279c8bf03e4de767d69585e02215e6ea6ee049d417ce8fe965fd830a3e5` (slot 15,417,696, period 1882), participation 511/512, exec block 26,178,742, state root `0x50b601db…`. Journal 328 bytes = 230 + 2 x 49, hash `777a689477c30cab5d8afdaf16d1b9c77ee8c0c0e264f8948faeb106a2da04bb` | **55,191,707 user cycles, 56 segments** (53.3M plain step + about 1M per deposit), **208.3 s STARK** on a rented RTX 4090 (slower than the 142 s for 104.5M yesterday: different pod or cold GPU, unexplained), **71.1 s wrap**. Image `4756d736…` (checked before wrap), receipt 745 B borsh. Bundle `eth-prover/out-deposit-12/`. |
| **CP-6 on mainnet: bridge covenant `ac21e83194b0beb1ae8c932a4734984f692ab982f6739037af6f979aef0dea0b`** (image `4756d736…`, chain commitment `0xffc6300b…`, vault `0x3DD8Cd71…`, max_fee 5 KAS, token template `b5323a04…`), genesis state header `0xa63ca480…` / committee `0xc68d24d7…` / cursor 0 / token 0, 20 KAS at `kaspa:prc7qzgt7zr5qrjj20yjfnu7hcyhj99aw2kxsfsgtv356medzjdnxrs840rv3` (address reproduced on the node box and in the build sandbox) | genesis tx `6f98c736fbc661a5affbda8cf86d27760f0c4e9bfdfad55a8a897ebf220be080` |
| **KCC-20 token `87b503510d715acfa3cca82f245e696593c30d78dde70e11e69afa88b3d03a3f`** (KBT on Kaspa, 6 decimals; kcc20.sil at the pinned silverscript rev, maxCovIns 4, maxCovOuts 5; its only minter branch is owned by the bridge covenant id, created by the bridge's `init` transition as a KIP-20 genesis output whose id the node confirmed). Node used=55,663 units at budget 4, accepted at **budget 5**, fee 0.080 KAS at 2x (storage mass 40,114 g) | init tx `004a4d280e5fc64b2072d0408df7c78df61c5ca01cbfd33ffc413f28bb8e8ad9` |
| **First deposit -> token on Kaspa mainnet, two deposits in one advance, no signature on the Kaspa side.** State `0xa63ca480… -> 0x6dc6c279…`, cursor 0 -> 2. Tx: 2 inputs (bridge, token minter branch), 4 outputs (bridge successor 16.587 KAS, minter branch 1 KAS, **1 KBT to `kaspa:qzzkh3…`** (UTXO `:2`), **2.5 KBT to `kaspa:qpdlx5…`** (UTXO `:3`, Oz's Kasla key)). Node used=15,627,605 at budget 1561 (local engine 15,627,754), accepted at **budget 1562**; token input budget 5 (local 40,709 units); mass 166,284 g (storage 114,379), fee 0.3326 KAS at 2x plus the 2 KAS carried into the token UTXOs | tx `e108d4161c14883e05940c933b616acbc119a0163e2380e16ef9782481d00f99` |
| Replay of the same bundle after the mint (state header `0x6dc6c279…`, cursor 2): the driver's heartbeat shape, local engine rejects, node rejects | `script ran, but verification failed` (tx `f6d8f759…`, never accepted) |
| **Wallet-side KCC-20 transfer:** the 1 KBT UTXO `e108d416…:2`, owner = the genesis key (plain Schnorr signature over the KCC20 covenant input), -> 0.4 KBT to `kaspa:qpdlx5…` + 0.6 KBT change. Node used=121,428 units (local 129,572), **budget 12**; storage mass 147,730 g (two 0.426 KAS covenant outputs), fee 0.1477 KAS at 1x | tx `6cf4a2afa5e732473d532cf6d34ec22f5e9f991d4344ad4c5810bc722debdf33` |

Live after CP-6 (state file `bridge-cp6-state.json` on the node box): bridge UTXO `e108d416…:0` at
`kaspa:ppghgf7m5pa9cf7zg0c2mz2szgpqww67v3atcyzfzddgp776pww22klhp39lk`, 16.5872 KAS, state header `0x6dc6c279…`,
committee `0xc68d24d7…`, cursor 2, token `87b50351…`; minter branch `e108d416…:1` (1 KAS) at
`kaspa:ppfk57wxszm8p98nxwh6altu9assmdj6geslruvazy0lsww04d8wcvz0ye432`; token UTXOs `e108d416…:3` (2.5 KBT, Kasla key),
`6cf4a2af…:0` (0.4 KBT, Kasla key), `6cf4a2af…:1` (0.6 KBT, genesis key). Vault holds 3.5 KBT; Kaspa supply 3.5 KBT.

Code: `~/kaspa-zk/kaspa-zk-tests` on the node box (tarball `kaspa-zk-tests-v1.0.tgz`, plus `eth-prover-v0.1.tgz`
to unpack beside `prover/`, plus `bridge-cp45-v0.1.tgz`, plus `cp3-cp2-v0.1.tgz`, plus **`bridge-cp6-v0.1.tgz`** over the
repo root (replaces `bridge/{bridge.sil, Cargo.toml, src/lib.rs, src/main.rs, tests/engine.rs}`, adds `bridge/kcc20.sil`,
replaces `bin/bridge.mjs` and `src/cost.js`), plus `cp6-docs-v0.1.tgz` (this file, `bridge/README.md`,
`vault/README.md`); the project docs hold the current copy of every one of these files). Key files:
`src/zk-scripts.js` (stack contracts), `src/cost.js` (consensus cost model incl. KIP-9 storage mass), `src/tx.js`
(v1 tx construction), `bin/r0spend.mjs` (bundle -> address / spend), `bin/measure.mjs` (budget discovery by free
rejections), `bin/kaspa-spk.mjs` (kaspa: address <-> 33-byte kaspa_spk), `prover/` (melody guest), `eth-prover/`
(Ethereum light-client guest and host; README there is the operating manual), `bridge/` (`bridge.sil` the bridge,
`kcc20.sil` the token, Rust tool `bridge-covenant` that compiles both, assembles the complete init / advance / transfer
transactions and runs every input through the 2.1.0 engine, `tests/engine.rs` 15 tests on the real deposit-1 proof,
README with the mainnet record), `bin/bridge.mjs` (key | genesis | init | advance | replay | transfer | show; state in
`bridge-cp6-state.json`, genesis key in `bridge-key.json`), `vault/` (Vault.sol, TestToken.sol, Deploy.s.sol, Vault.t.sol,
verify-storage.sh, README with the mainnet record and the storage layout).

### Hard numbers to design against (mainnet == testnet-10)

- Groth16 verify: 140,000 grams + 250,000 script units per `gamma_abc` element (public inputs + 1).
  RISC Zero Groth16 wrapper = 5 public inputs = 6 elements. Floor budget 1550 = 155,000 grams.
- Block compute limit 500,000 grams: **3 Groth16 verifies per block**, ~30/s network-wide at 10 bps.
- Compute budget is u16 per input; allowed units = `budget*10_000 + 9_999`; compute mass += `budget*100`.
- Min relay fee 100 sompi/gram on `max(compute, storage, transient/2)`. A verify spend costs ~0.16 KAS at 1x.
- BRIDGE covenant budgets (measured): light-client step alone 1551 (CP-4/5 contract); CP-6 contract: heartbeat 1553
  (local), 1 deposit 1559 (local), **2 deposits 1562 (node)**: about 3 budget units per deposit. Token (KCC20) minter
  input in a mint: budget 5 (node 40,709 units for 3 token outputs). Init: budget 5. Wallet transfer 1 -> 2: budget 12
  (node 121,428). P2PK input in a v1 tx: budget 10.
- **KIP-9 storage mass:** a covenant output is 63 + 35 + 32 bytes = plurality 2, so creating a covenant UTXO holding `v`
  sompi costs `4e12 / v` grams (0.2 KAS -> 200k grams, over a block's budget for three of them). Token UTXOs carry
  **1 KAS** (`--token-kas`), paid out of the bridge's KAS; a mint with n deposits drains `n` KAS + fee, bounded by
  `max_fee` (5 KAS on this instance, so at most 4 mints per advance, which is also the contract's MAX_DEPOSITS).
  A wallet transfer that splits one 1 KAS token UTXO into two costs about 0.15 KAS at the minimum rate; at a 2x fee
  multiplier the fee and the shrinking outputs have no fixed point, so transfers use `--fee-mult 1`.
- Post-Toccata: sig script <= 250,000 B, script element <= 1,000,000 B. Literal pushes are free.
- Script sizes: bridge redeem 4216 B (state at bytes 1..108: header, committee, cursor as 8-byte int, token), advance
  sigscript 4636 B (1 deposit) / 4685 B (2), init sigscript 6844 B (carries the token template), token redeem 2662 B
  (template 1 + 2615 B), token transfer sigscript ~2.8 KB.
- RISC Zero Succinct (tag 0x21) is verifiable but 222 KB per proof and 2 per block. Use Groth16 (0x20).
- Under-budget spends are rejected at mempool for free and report `used=N`. Use this to measure.
- SDK `calculateTransactionMass()` ignores v1 compute budgets (wallet/core/src/tx/mass.rs TODO). Compute mass by hand.
- Proving cost, mainnet spec, RTX 4090: 53.3M cycles / 107 s without rotation; 104.5M / 142 s with one rotation plus
  one deposit; **55.2M / 208 s with two deposits, no rotation** (the 208 s is an outlier against the 1.36 to 2.0 s/M
  seen before; check `nvidia-smi` next run). A rotation adds ~50M cycles, **a deposit about 1M**. Groth16 wrap: 71 to
  73 s on the node box, independent of cycles. Pod cost per proof: under $0.10 plus image pull time.
- Ethereum gas, CP-3: deploy both contracts ~807k, approve 46k, first deposit 126,766, later deposits 92,566.
- Ethereum finality observed 2026-10-12: the finalized header lagged wall clock by ~30 min, not the nominal 13.
- Covenant ids are `blake2b_keyed("CovenantID", genesis outpoint, [(index, value, spk)...])` (KIP-20): two covenants
  cannot embed each other's id at genesis, hence the bridge's `init` step.

### Toolchain pins

- `risc0-zkvm = "=3.0.4"` (the SDK embeds this version's control root; other versions do not verify).
  `rzup install r0vm 3.0.4`, `cargo-risczero 3.0.4`. Groth16 wrap needs x86_64 + Docker.
- With the `cuda` (or `prove`) feature the in-process prover compiles risc0-zkvm 3.0.4 against its sibling crates, and
  newer patch releases of those broke the API: pin `risc0-zkp 3.0.3`, `risc0-circuit-{rv32im,recursion,keccak} 4.0.3`,
  `risc0-groth16 3.0.3`, `risc0-binfmt 3.0.3` in `eth-prover/Cargo.lock` (done 2026-10-12; `cargo update` would undo it).
- Guest Rust toolchain must be >= 1.90 (MSRV of the helios/alloy dependency tree): `rzup install rust 1.94.1`
  is known good. Host: stable.
- Accelerated forks pinned in `eth-prover/methods/guest/Cargo.toml` `[patch.crates-io]`:
  `bls12_381` tag `bls12_381/v0.8.0-risczero.1`, `sha2` tags `sha2-v0.9.9-risczero.0` and `sha2-v0.10.9-risczero.0`,
  `tiny-keccak` tag `tiny-keccak/v2.0.2-risczero.0`. `risc0-bigint2` resolves to a single copy (1.4.14).
- helios 0.12.0 (git tag). 0.8.3 (what r0vm-helios pins) lacks Fulu and cannot verify post-Fusaka updates.
- Silverscript: kaspanet/silverscript rev `a0dd7448ccc7bad5b99140f2c8edbbd0b2a874f1` (2026-10-10, the commit that moved
  to rusty-kaspa 2.1.0 crates; its lock has risc0-zkvm 3.0.4). `bridge/Cargo.toml` pins it by rev; Rust >= 1.94
  (edition 2024). The redeem script is a function of (this rev, constructor args, state) only. **The KCC20 token's
  template is a function of (this rev, `bridge/kcc20.sil`, maxCovIns 4, maxCovOuts 5)**: hash
  `b5323a04194ba2343adf8fc08da9cfe746aa2a4baef74b1a18ee518b508b45cf`. A different rev or different loop bounds is a
  different template, which the deployed bridge would refuse. `bridge/kcc20.sil` is a verbatim copy of
  `silverscript-lang/tests/examples/kcc20.sil` at that rev (sha256 `54bca2fe…96a`); never edit it.
- Foundry 1.8.5 on the node box (`/root/.foundry/bin`), solc 0.8.28 pinned in `vault/foundry.toml`, evm cancun,
  optimizer 200 runs. `lib/forge-std` is a `git clone --depth 1` (not committed).
- Image ids depend on the build environment and on the guest source. Pinnable (Docker `kasperolabs/eth-prover:cuda`
  builds): minimal-spec `d7c73376…` (fixture work); mainnet-spec CP-4/5 layout `f1542762…` (superseded); **mainnet-spec
  CP-2 layout `4756d736…` (current, pinned by the live CP-6 bridge)**. Node-box native builds give different ids
  (`91378ffb…`, `68a40a12…`); never pin those. Proofs for the live bridge must come from the Docker image.
- Receipt format for the SDK: `borsh::to_vec(receipt.inner.groth16()?)` (Groth16Receipt<ReceiptClaim>).
- Journal hash = plain sha256 of journal bytes (`receipt.journal.digest()`).
- The SDK's redeem script reconstructs the ReceiptClaim in script assuming `ExitCode::Halted(0)`, no assumptions, zero input digest. Guests must halt normally (no `env::exit` with nonzero code).
- CPU proving memory: r0vm needed > 6 GB for a 37M-cycle session even at `RISC0_SEGMENT_PO2=18`. Budget RAM accordingly.

### Stack contracts (engine, top of stack first)

```
tag 0x20 Groth16:      vk | proof | n (i64) | input[0..n)         (arkworks compressed; Fr 32 B LE)
tag 0x21 R0 Succinct:  hashfn | control_id | image_id | journal | seal | control_digests | control_index | claim
ZkScriptBuilder.commitToGroth16(imageId)  -> redeem: push(image_id) + fixed VK + claim reconstruction + 0x20 + OpZkPrecompile (801 B)
ZkScriptBuilder.finalizeWithGroth16Proof(receiptBorshHex, journalHashHex) -> { sigScript, redeemScript }
   sigScript = push(journal_hash) push(proof 128 B) push(redeem)
Silverscript r0.g16.verify(journal_hash, proof, image_id): the compiler emits the same SDK fragment
   (append_r0_groth16_verifier_dynamic_image_id). public inputs: a0 a1 (control root) c0 c1 (claim digest) bn254 id.
```

### Frozen formats (2026-10-12)

**Journal** (big-endian; `eth-prover/primitives/src/lib.rs::journal`, `eth-prover/README.md`):

```
0    32  chain_commitment      keccak256(genesis_validators_root || cbor(forks)); mainnet = 0xffc6300b…
32   32  prev_header           checkpoint_in (finalized beacon header root)
64   32  prev_committee        sync committee hash at checkpoint_in
96   32  new_header            checkpoint_out
128  32  new_committee         sync committee hash at checkpoint_out
160  8   new_slot
168  32  exec_state_root       at checkpoint_out
200  8   exec_block_number
208  20  vault                 Vault.sol address (all zero when no deposits are proven)
228  2   deposit_count n
230  49n deposits              per deposit: nonce (8) | amount (8) | kaspa_spk (33)
```
Deposit nonces are strictly increasing within a journal (guest-enforced). `kaspa_spk` = Kaspa address version byte
(0 = P2PK Schnorr, 8 = P2SH; 1 = ECDSA refused) + 32-byte payload. **The covenant turns it into KCC-20 token state,
not an output script:** `{ownerIdentifier: payload, identifierType: version 0 -> 0x00 (pubkey) / 8 -> 0x01 (script
hash), amount, isMinter: false}`. (The earlier note "version 0 -> `20<payload>ac`" described plain outputs; KCC-20
tokens are covenant UTXOs, see below.)

**KCC-20 token** (`bridge/kcc20.sil` = silverscript's example at the pinned rev): a token UTXO is a P2SH covenant output
whose redeem script is `template_prefix (1 B) || state || template_suffix (2615 B)`, state = `ownerIdentifier byte[32]
| identifierType byte | amount int (8-byte LE script number) | isMinter bool`, each field with its push prefix. Owner
types: 0x00 pubkey (spend = Schnorr sig over the 32-byte x-only key, same key as Kaspa P2PK), 0x01 script hash
(spend = an input in the tx whose spk is that P2SH), 0x02 covenant id (spend = an input of that covenant in the tx).
Non-minter branches conserve `amount` and cannot create minter branches; the one minter branch (owner = the bridge
covenant id) may change supply, and only when a bridge input is present. The covenant id of the token
(`87b50351…`) is what identifies KBT-on-Kaspa; the template hash identifies the token class.

**Bridge state** (bytes 1..108 of the bridge redeem): `header byte[32] | committee byte[32] | cursor int | token byte[32]`.

**Vault.sol storage** (`vault/README.md`, asserted by `vault/test/Vault.t.sol`, hardcoded in the guest as
`vault_layout`, so the image id pins it):

```
slot 0                                      nonce (uint64, low 8 bytes); first deposit is nonce 1
slot 1                                      deposits mapping base (always zero)
k0 = keccak256(abi.encode(uint256(n), 1))   deposits[n] word 0: amount (bits 0..63) | kaspaVersion (bits 64..71); bits 72..255 zero
k0 + 1                                      deposits[n] word 1: kaspaPayload (bytes32)
```
`token` is immutable (no slot). Guest refuses: zero words, nonzero bits above 71, amount 0, version not in {0, 8},
non-increasing nonces. `deposit()` enforces the same, so every deposit the contract writes is provable.

---

## 2. Target architecture (one-way, v1)

```
Ethereum mainnet                         prover (GPU pod + node box)          Kaspa L1 mainnet
-----------------                        ----------------                     --------------------------------
Vault.sol  0x3DD8Cd71… (live)            guest: eth-bridge-guest              BRIDGE covenant ac21e831… (live)
  deposit(amount, kaspaSpk[33]) -----> 1. verify beacon finality            state: { header, committee, cursor, token }
  storage: deposits[nonce] =             from checkpoint_in to checkpoint_out advance(journal, proof) requires:
    (amount, version, payload)         2. verify MPT proofs of              - OpZkPrecompile(imageId, journal)
  no owner, no withdraw                   deposits[n] words 0 and 1          - journal.chain_commitment == CONST
                                       3. journal = [chain, cp_in, cmt_in,   - journal.vault == VAULT_CONST
TestToken.sol 0x88C589bB… (live)          cp_out, cmt_out, slot, root, blk,  - journal.cp_in == state.header
  KBT, 6 decimals, 1,000,000 supply       vault, n, deposits...]             - journal.cmt_in == state.committee
                                       4. Groth16 wrap -> bundle             - successor: {cp_out, cmt_out, cursor', token}
                                                                             - for each deposit with nonce > cursor:
                                                                               KCC20 output {payload, type, amount, false}
                                                                             - exactly 1 token input (minter branch) and
                                                                               1 + mints token outputs; 0 and 0 on heartbeat
                                                                             KCC-20 token 87b50351… (live): minter branch
                                                                             owned by the bridge covenant id
```

Trust assumptions of v1, to be stated in the README: Ethereum sync committee (512 validators) rather than full
consensus, as in every Helios-class client; RISC Zero toolchain and Groth16 ceremony; the vault contract code;
Circle's freeze power over the vault address (for USDC). No signer, no relayer with keys, no admin. Latency is
Ethereum's finality (15 to 35 min), not ours; any faster lane is an LP layer above the rail, never a shortcut in it.

Design change from the first draft (2026-10-11): the covenant state pins the **sync committee hash** next to the
checkpoint, and the journal carries both the before and after values. Pinning only the header lets a prover supply
the committee that signs the next step (zkSecurity finding on r0vm-helios); pinning the committee hash closes that.
The journal also carries a chain commitment (genesis validators root + fork schedule) which the covenant compares
to a constant, so a proof from another chain running the same program cannot open it.

Design change 2026-10-12 (CP-5 as built): no nonce in the light-client state. The guest refuses proofs that do not
advance the finalized header, so header continuity alone makes every proof single-use; the replay test on mainnet
confirms it. Deposits get their own nonce (CP-2), and per-deposit single use is the covenant's cursor (CP-6):
deposits at or below the cursor are skipped, never minted twice, while the light-client step still applies.

Design note 2026-10-12 (CP-2 as built): deposits are first-class journal fields decoded by the guest, not raw
storage slots. The covenant never sees Solidity packing, and the vault layout is pinned by the image id.

Design note 2026-10-12 (CP-6 as built): the token is kcc20.sil's covenant-state token. The bridge is the controller
covenant (the role kcc20-minter.sil plays in silverscript's example), with the proof replacing the admin signature.
Because KIP-20 ids depend on the genesis outputs, bridge and token cannot embed each other at genesis: the bridge is
deployed with `token = 0`, then `init` (no proof, anyone may submit, result is fully determined) creates the KCC20
genesis as output 1 of a two-output tx, requires it to be a covenant genesis (`OpCovInputCount(id) == 0`, so the id is
fresh and the group is exactly that output, no second minter branch) with state `{bridge id, 0x02, 0, true}`, and
records the id. Heartbeats require zero token inputs and outputs, so the minter branch cannot be burned or moved
under cover of a plain advance.

---

## 3. Connection points (the actual work)

Each item: what exists, what must be written, how we know it works.

### 3a. Status of CP-1 and CP-2

Done and measured. `eth-prover/` is a port of `risc0/r0vm-helios` (RISC Zero's own SP1-Helios port, zkSecurity
audit April 2025) to risc0 3.0.4 + helios 0.12.0. Its guest does CP-1 (sync committee updates + finality update, BLS
aggregate verification with the accelerated bls12_381 fork) and CP-2 (vault account proof + two storage proofs per
deposit against the execution state root of the new finalized header, decoded with the Vault.sol layout) in one
program. Journal: frozen formats above.

Operating mode (decided 2026-10-12): proving runs on a rented GPU per proof (RunPod/Vast class, prepaid balance as
the hard cost cap), image `kasperolabs/eth-prover:cuda` built from `docker/Dockerfile.cuda` (BuildKit cache mounts;
a guest change rebuilds in minutes), pod flow: ssh in, `prove --no-wrap`, scp out (into `eth-prover/`, not the repo
root), `wrap` on the node box (`eth-prover/README.md` section 2b). RunPod only injects `PUBLIC_KEY` if the key is
saved in Settings before deploy and "SSH terminal access" is ticked. Image pull on a fresh pod takes longer than
proving. Boundless remains the no-machine alternative. Architecture: contracts always on; a small always-on watcher
(CP-7, no GPU) on the node box; a GPU that exists for the minutes a proof takes.

**Gloas warning:** Sepolia activated Gloas (Glamsterdam) at epoch 353024 (early October 2026). Gloas light-client
headers carry `execution_block_hash` only, no execution payload header, so the guest's execution-state-root path
fails there. Mainnet and Hoodi are on Fulu. When mainnet goes Gloas the guest needs the execution-header witness
(RLP header, `keccak(rlp) == execution_block_hash`, read `state_root` and `number`). helios 0.12.0 has Gloas types,
so the consensus side already works there. Track the mainnet Glamsterdam date.

### 3b. Operating without an Ethereum node (decided 2026-10-12)

Light-client data is self-verifying (BLS signatures checked against the pinned committee), so the prover uses public
beacon endpoints and a free-tier execution RPC (for `eth_getProof`); no Ethereum node is run. A bad endpoint can stall
the bridge (withhold or serve stale data) but cannot make it accept a false state. Consequences:
- Endpoint list with failover in CP-7 (ChainSafe Lodestar today; add more; public ask for redundancy).
- Heartbeat: the covenant must be advanced at least every few months even without deposits, because beacon nodes
  only keep committee-handoff updates (`light_client/updates`) for a limited window; a covenant that falls behind
  that window cannot catch up and has no admin path. A handoff costs ~50M extra cycles; cadence (weekly is the working
  assumption) to be set in CP-7. Heartbeat budget 1553.
- Batch deposits: one proof can carry the light-client step plus up to 4 deposit entries (MAX_DEPOSITS in bridge.sil;
  about 1M cycles and 3 budget units each); the Kaspa verify fee is per proof.
- Fetch `eth_getProof` at the finalized block promptly (non-archive providers keep recent state only). Alchemy free
  tier served blocks 26,178,455 and 26,178,742 fine minutes after finality.
- `fetch --checkpoint <the covenant's current header>` works directly when Lodestar still serves that bootstrap
  (it did for a header ~1 h old on 2026-10-12): no need to bootstrap at the head and wait for the next update.
  CP-7 should always fetch from the covenant's recorded header.
- Execution RPC in use: Alchemy free tier, URL with key in `eth-rpc-url.txt` (`--execution-rpc $(cat ../eth-rpc-url.txt)`).
  reqwest connection errors include the URL; check before pasting an error into a chat.

### CP-1 Ethereum consensus inside a RISC Zero guest  (DONE)
- Exists: `eth-prover/methods/guest`. Helios (a16z) consensus-core 0.12.0 does the verification; the guest
  wraps it, refuses input stores that carry `next_sync_committee`, and refuses updates that do not advance the
  finalized header (participation < 2/3).
- Evidence: section 1.

### CP-2 Storage proof of the deposit  (DONE 2026-10-12)
- Built: `ProofInputs.vault_deposits: Option<VaultDeposits>` (vault address, account proof, per nonce: word 0 + proof,
  payload + proof). Guest `verify_vault_deposits`: account proof against `exec_state_root`, both words against the
  account's storage root, `vault_layout::decode_word0`, zero payload refused, nonces strictly increasing, commits
  `(nonce, amount, kaspa_spk)`. Host: `fetch --execution-rpc URL --vault 0x.. --nonce N [--nonce M]` builds the keys,
  one `eth_getProof` call, decodes on the host first; `eth-prover journal --file` decodes any journal.
- Evidence: section 1 (deposit #1 alone, image `4756d736…`, bundle `out-deposit-1/`; deposits #1 + #2, `out-deposit-12/`).

### CP-3 Vault contract  (DONE 2026-10-12)
- Built: `vault/` (Foundry). `Vault.sol`: `deposit(uint64 amount, bytes calldata kaspaSpk)`, requires length 33,
  version 0 or 8, nonzero amount and payload, `transferFrom`, `++nonce`, store, emit `Deposited`. No owner, no
  withdraw, no other function. `TestToken.sol`: minimal ERC-20, KBT, 6 decimals. `script/Deploy.s.sol`, `test/Vault.t.sol`
  (5 tests, storage layout asserted), `verify-storage.sh`.
- Evidence: section 1.
- Operational: deployer key file is `address<TAB>privatekey`; use `KEY=$(cut -f2 ../eth-deployer-key.txt | tr -d '[:space:]')`.
  Contracts are not Etherscan-verified (no API key); bytecode is reproducible from `vault/`.

### CP-4 Journal -> script: reading fields in Silverscript  (DONE 2026-10-12)
- Built: `bridge/bridge.sil`. silverscript's native `r0.g16.verify(journal_hash, proof, image_id)` lowers to the SDK
  2.1.0 fragment itself. The contract computes `sha256(journal)` and slices fields with `journal.slice(a, b)`;
  big-endian u64s are read by concatenating the 8 one-byte slices in reverse and `int(byte[8](...))`.
- Evidence: `bridge/tests/engine.rs`, then mainnet (section 1).

### CP-5 Covenant state and successor  (DONE 2026-10-12)
- Built: `#[covenant.singleton(mode = transition)]` entries; the generated wrapper enforces exactly one authorized
  successor with the same template and covenant id. No nonce in the light-client state (section 2).
- Evidence: two consecutive transitions and two replay rejections on the test instance; one advance and one replay
  rejection on the production instance (section 1).

### CP-6 KCC-20 mint under covenant authority  (DONE 2026-10-12)
- Built: `bridge/bridge.sil` v2 (constructor adds `vault`, `token_prefix_len`, `token_suffix_len`,
  `token_template_hash`, `init_cursor`, `init_token`; state adds `cursor`, `token`; entries `init` and `advance`;
  the full rule list is in `bridge/README.md`), `bridge/kcc20.sil` (pinned copy), `bridge/src/lib.rs` (`build_init`,
  `build_advance`, `build_transfer` assemble complete v1 txs; `BuiltTx::execute_all` runs every input through the
  engine; `sign` does Schnorr SIG_HASH_ALL for wallet transfers; compute budgets are not in the v1 sighash, so the
  driver walks them up without re-signing), `bridge/src/main.rs` (`script | journal | token-script | init | advance |
  transfer`, prints the whole tx and the engine verdict as JSON), `bridge/tests/engine.rs` (15 tests, real deposit-1
  proof), `bin/bridge.mjs` (fetches UTXO entries, fee = max(compute, storage, transient/2) iterated to a fixed point,
  budget walk-up per input, state in `bridge-cp6-state.json` incl. every minted token UTXO), `src/cost.js`
  (`utxoPlurality`, `storageMassGrams`).
- Evidence: section 1 (genesis `6f98c736…`, init `004a4d28…`, mint `e108d416…`, replay rejected `f6d8f759…`,
  transfer `6cf4a2af…`), `bridge/README.md` (local table: every rejection case).
- Open: whether Kasla displays `e108d416…:3` (2.5 KBT, Oz's key) and `6cf4a2af…:0`; depends on which kcc20 template
  (rev and loop bounds) Kasla recognizes. If it keys on a template hash list, add `b5323a04…`.
- Not done, by design: no KAS funding input in a mint or transfer (the bridge's KAS pays for token UTXOs; a wallet
  transfer pays from the token UTXO's own KAS). CP-7 may add a funding input to the mint tx so the bridge's KAS lasts.

### CP-7 Prover service and submit path  (NEXT)
- Exists: everything the service needs as commands: `eth-prover fetch --checkpoint <state.header> --nonce ... `,
  pod `prove --no-wrap`, `eth-prover wrap`, `node bin/bridge.mjs advance --bundle DIR` (idempotent in effect: a
  bundle whose deposits are all <= cursor is a heartbeat; a bundle whose prev_header is stale is rejected locally
  before submission). RunPod REST API for pods.
- Write: `bridge-prover` (Node orchestrating `eth-prover`, a pod and `bridge.mjs`): poll the Vault (`nonce()` and
  `Deposited` logs) and the bridge state file; when `vault.nonce > cursor` and the deposit block <= the latest
  finalized exec block, fetch from the covenant's header with every unminted nonce (max 4 per proof), rent a GPU,
  prove, wrap, advance, stop the pod; heartbeat advance on a timer (weekly) when nothing is pending; endpoint
  failover; a KAS balance alarm for the bridge UTXO (16.59 KAS left, 1 KAS + ~0.33 fee per mint, ~0.16 per heartbeat).
  Anyone can run it; nothing in it holds a key except the pod account.
- Done when: a deposit on Ethereum results in a token on Kaspa mainnet with no manual step.

### CP-8 Budget and limits for the real guest  (measured; keep updating)
- Budgets: section 1 and "Hard numbers". Still unmeasured: a mint with 3 or 4 deposits (expect ~1565 to 1568), a
  heartbeat on the node (local 1553), a rotation + deposits proof on the current image.
- Proving: 55.2M / 208 s outlier needs one more data point on a fresh pod.

---

## 4. Order of work (1 to 2 weeks)

Day 1 to 2: CP-1 feasibility. **Done.**
Day 2 to 3: CP-4 + CP-5. **Done 2026-10-12** (section 1, `bridge/`).
Day 3 to 4: CP-3 + CP-2. **Done 2026-10-12** (section 1, `vault/`, `eth-prover/out-deposit-1/`).
Day 5 to 7: CP-6. **Done 2026-10-12** (section 1: first end-to-end deposit -> token on Kaspa mainnet, same day).
Day 8 to 10: CP-7 prover service, README, measurements, cap, publish.
Everything above runs on Ethereum mainnet and Kaspa mainnet from the start (decision 2026-10-12): the vault locks
deposits forever in v1, so the asset is a self-minted ERC-20 until the loop runs clean; USDC last, few dollars, small cap.
Mainnet is on Fulu, which also sidesteps the Gloas witness Sepolia would need.

Parallel, no ZK, separate session: the curve token (bonding-curve KCC-20) teaches the same KCC-20 handling.

---

## 5. Decisions already made

- Groth16 (tag 0x20) via RISC Zero wrapper, not Succinct. Not SP1 (its VK differs from the SDK's embedded one).
- Ethereum as source chain (only chain that can verify our proofs back, needed for stage 2 outbound; where USDC and
  ERC-20 liquidity live; every L2 posts state roots to it). Helios-class light clients verify Ethereum's beacon
  chain only; "any network" in r0vm-helios refers to the destination.
- One-way v1. Redemption is out of scope; document a labeled signer-based exit if any real value is bridged.
- Immutable program, no upgrade key, small cap. Timelocked image-id rotation only in a later version.
- Journal carries recipient as 33-byte kaspa_spk (address version byte + 32-byte payload, P2PK or P2SH only);
  the covenant turns it into KCC-20 owner state and enforces the output (front-running protection).
- Covenant state pins (checkpoint, sync committee hash); journal carries chain commitment (see section 2).
- Guest input store may not carry `next_sync_committee`; rotations come as signed updates.
- Covenant written in Silverscript with the native `r0.g16.verify` builtin and `#[covenant.singleton]` (2026-10-12).
- Light-client state has no nonce; replay protection is header continuity (2026-10-12).
- Deposits are decoded by the guest, committed as first-class journal fields; the covenant keeps a deposit cursor.
- Vault ABI is `deposit(uint64, bytes)` with a 33-byte requirement, not `bytes33` (does not exist in Solidity).
- Test asset: self-minted KBT (6 decimals) until the loop runs clean; USDC last.
- No early minting, no relayer: latency equals Ethereum finality. Fast lanes, if ever, are a bonded LP layer on top.
- **Token = kcc20.sil as is** (silverscript's draft, pinned rev, maxCovIns 4, maxCovOuts 5), bridge = controller
  covenant; two-phase genesis + init; MAX_DEPOSITS 4 per proof; token UTXOs carry 1 KAS paid by the bridge; max_fee
  5 KAS; decimals 6 = the vault's uint64 unchanged (2026-10-12).
- Transfers at fee multiplier 1 (storage-mass bound; no fixed point at 2x) (2026-10-12).

## 6. Things that will bite

- Toolchain drift: SDK 2.1.0 <-> risc0 3.0.4. A newer SDK may embed a newer control root; re-check
  `Groth16ReceiptVerifierParameters::default()` in `crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs`.
  The same applies to silverscript: a newer rev changes the bridge redeem AND the token template; the live bridge
  (`ac21e831…`) and token (`87b50351…`) are pinned to rev `a0dd7448` forever. Keep `bridge/Cargo.toml` at that rev.
- The SDK's in-script claim reconstruction assumes Halted(0) and zero input digest; guests must not use
  `env::input_digest`-style features that change the claim shape.
- Gloas (ePBS) light-client headers have no execution payload header (3a). Sepolia is there already; mainnet will be.
- **KIP-9 plurality 2 for covenant outputs**: small-value token UTXOs are expensive to create and to split; a fee
  multiplier above 1 on a split has no fixed point. Fund token UTXOs with ~1 KAS; consider a KAS funding input
  (CP-7) and, product-wise, Oz's "gas tank" idea.
- The bridge's KAS is finite: 1 KAS per mint plus fees; a griefer with a copy of a valid bundle can submit the
  advance with the maximum fee (max_fee bounds it to 5 KAS per advance, and advances are proof-rate-limited).
- One state UTXO = one mint per block, at most 4 deposits per proof. Fine for v1; shard later.
- Explorer support for v1 tx fields is partial; verify with node RPC, not explorer pages.
- Beacon light-client endpoints are rare; Lodestar's finality update lagged ~30 min behind wall clock on 2026-10-12.
- `IMAGE_IDS.txt` in the CUDA image is empty (`eth-prover ids` cannot run in the GPU-less build stage). Get ids from
  `image_id.hex` in a bundle. Fix pending: drop that line from `Dockerfile.cuda`.
- `docker/run-rented-gpu.sh` passes `prove …` without the program name; fix pending: insert `eth-prover` before `prove`.
- `src/sdk.js` re-exports only a subset of the SDK; anything else comes off the `kaspa` object.
- `jq` is not installed on the node box; use `python3 -c` for JSON. Node on the box is v20: `node --input-type=module -e`
  with `import fs from "node:fs"`, no `require`.
- `bridge.mjs key` only creates `bridge-key.json`; the address is derived with `new kaspa.PrivateKey(k.privateKey).toAddress("mainnet")`
  (`kaspa:qzzkh3…` for the current key, which is also deposit #1's recipient and holds 0.6 KBT).
- `scp -r` from the pod lands in the current directory; the bundles belong in `eth-prover/`.

## 7. References

- rusty-kaspa v2.1.0: `crypto/txscript/src/zk_precompiles/` (engine), `crypto/txscript/zk-sdk/` (ZkScriptBuilder),
  `consensus/core/src/mass/` (incl. `calc_storage_mass`, `utxo_plurality`), `consensus/core/src/hashing/covenant_id.rs`,
  `crypto/txscript/src/covenants.rs` (genesis vs continuation contexts), `mining/src/mempool/check_transaction_standard.rs`.
- KIPs: 9 (storage mass), 16 (zk opcodes), 17 (covenant opcodes), 20 (covenant ids), 21 (lanes), 24 (tx v1), 25 (budget/pricing).
- Toccata docs: https://docs.kaspa.org/toccata and sub-pages.
- kaspanet/silverscript (`tests/examples/kcc20.sil`, `kcc20-minter.sil`, `tests/kcc20_tests.rs`, `docs/kcc20-book`,
  `std/builtins.sil` for `validateOutputStateWithInputTemplate` etc.; `r0.g16.verify` lowering in
  `silverscript-lang/src/compiler/compile/expression/builtin.rs`), kaspanet/vprogs (patterns only), kaspanet/research.
- RISC Zero: risc0/risc0 (3.0.x), risc0/r0vm-helios (the port's origin; zkSecurity audit at
  reports.zksecurity.xyz/reports/risc0-helios), risc0/risc0-ethereum (Steel), a16z/helios 0.12.0,
  succinctlabs/sp1-helios (design reference).
- Ethereum mainnet: Vault `0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529`, TestToken `0x88C589bB7b0A3D75cfe0BAD6629C6E9503b69004`
  (Etherscan links in `vault/README.md`). Beacon: `https://lodestar-mainnet.chainsafe.io`. Execution: Alchemy (key in `eth-rpc-url.txt`).
- Kaspa mainnet: bridge covenant `ac21e83194b0beb1ae8c932a4734984f692ab982f6739037af6f979aef0dea0b`, token covenant
  `87b503510d715acfa3cca82f245e696593c30d78dde70e11e69afa88b3d03a3f`, txids in section 1.
- Our code: kaspa-zk-tests v1.0 (this repo), eth-prover v0.3 (CP-2 layout), bridge v0.2 (CP-6), vault v0.1, Docker image
  `kasperolabs/eth-prover:cuda` (image id `4756d736…`), and the mainnet txids above.
