# eth-prover: Ethereum light-client step for the Kaspa ZK bridge (CP-1 + CP-2)

A RISC Zero guest that verifies one Ethereum beacon-chain finality update (sync committee
BLS aggregate signature over a finalized header), optionally applies sync-committee rotations
before it, and optionally proves deposits of `vault/src/Vault.sol` against the execution state
root of the new finalized block. Its journal is a fixed-width record a Kaspa covenant can `substr`.

Derived from [risc0/r0vm-helios](https://github.com/risc0/r0vm-helios) (MIT, audited by
zkSecurity, April 2025), ported to **risc0-zkvm 3.0.4** (the version the Kaspa SDK 2.1.0 embeds)
and **helios 0.12.0** (Fulu and Gloas fork support; r0vm-helios' helios 0.8.3 cannot parse
post-Fusaka updates). The Solidity side of r0vm-helios is gone; the covenant replaces it.

## Status (2026-10-12, evening)

| what | state |
|---|---|
| guest builds for `riscv32im-risc0-zkvm-elf` with the accelerated `bls12_381`, `sha2`, `tiny-keccak` forks | yes, `risc0-bigint2` resolves to one copy |
| executes on a consensus-spec test vector (electra, minimal spec, 32-member committee) | yes: 35.4M user cycles, 36 segments, journal matches `steps.yaml` |
| proves (STARK + recursion, succinct receipt) on CPU, node box 12 cores | 6994.5 s (1 h 56 min) for the fixture |
| proves on an RTX 4090 (RunPod, $0.89/h) via `docker/Dockerfile.cuda` | 69.5 s for the fixture (STARK + recursion); the CUDA Groth16 wrap crashes in sppark, so: `prove --no-wrap` on the GPU, `wrap` on a Docker box (72.6 s) |
| that bundle opens a mainnet covenant pinned to this guest (`bin/r0spend.mjs`, budget 1550, flipped journal hash rejected first) | tx `c99d357ae17554e77667e78810dc0e48e0262c10857c2cefd8b41b6fa1d20e8c` |
| BRIDGE covenant (`bridge/bridge.sil`) advanced twice on mainnet with fixture steps 0 and 1, replays rejected | txs `0fda7120…`, `d5fd63b5…` |
| executes and proves on real mainnet data (512-member committee) from `https://lodestar-mainnet.chainsafe.io` | 53.3M user cycles, 54 segments; 107.3 s STARK on an RTX 4090 + 71.0 s wrap; image `f1542762…` (CP-4/CP-5 layout, no deposits, no rotation) |
| **CP-2 on mainnet: one finality update plus the first Vault deposit (nonce 1) proven on a rented RTX 4090** | user cycles 104,501,905 (106 segments; the step also carried a sync-committee rotation, period 1881 -> 1882), **142.4 s STARK** (1.36 s per M cycles), **71.6 s wrap** on the node box; image id (mainnet spec, Docker build) **`4756d736d00cc0e5b813fd9bbb8fe586dbfe9cee524e61e79335cc2585413a50`**; journal 279 bytes, hash `543f0f54d4a158b8dc005b8c13eaa90b367aded45b260a4f010c81abc5106431`; bundle `out-deposit-1/` on the node box. Journal: checkpoint `0xd034a38c…` (slot 15,417,248) -> `0xa63ca480…` (slot 15,417,408), exec block 26,178,455, vault `0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529`, deposit nonce 1 amount 1000000 kaspa_spk `0x00856bc6…829c` |

## Layout

```
eth-prover/
  primitives/      ProofInputs, Vault storage layout (vault_layout), journal layout (shared by guest and host)
  methods/guest/   the guest: src/lib.rs (generic over ConsensusSpec), two bins:
                     eth-bridge-guest          mainnet spec (the real one)
                     eth-bridge-guest-minimal  minimal spec (offline test vectors only)
  host/            eth-prover CLI: fetch | execute | prove | fixture | wrap | journal | ids
  docker/          CUDA image for rented GPUs (Dockerfile.cuda, pod-start.sh, run-rented-gpu.sh)
```

Guest dependency pins live in `methods/guest/Cargo.toml` (`[patch.crates-io]`) and are locked
in `methods/guest/Cargo.lock`. Do not bump risc0 without re-checking the control root in the
Kaspa SDK (`crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs`).

## Journal (230 bytes + 49 per deposit, big-endian). Frozen 2026-10-12.

| offset | len | field |
|---|---|---|
| 0 | 32 | chain_commitment = keccak256(genesis_validators_root ‖ cbor(forks)); the covenant pins this constant |
| 32 | 32 | prev_header: finalized beacon header root at checkpoint_in |
| 64 | 32 | prev_committee: tree hash of the sync committee the covenant trusted |
| 96 | 32 | new_header: checkpoint_out |
| 128 | 32 | new_committee: sync committee hash after this step (rotates at period boundaries) |
| 160 | 8 | new_slot |
| 168 | 32 | exec_state_root at checkpoint_out |
| 200 | 8 | exec_block_number |
| 208 | 20 | vault: the Vault.sol address whose deposits follow (all zero when none are proven) |
| 228 | 2 | deposit count n |
| 230 | 49·n | per deposit: nonce (8) ‖ amount (8) ‖ kaspa_spk (33 = version byte ‖ 32-byte payload) |

Bytes 0..208 are unchanged from the CP-4/CP-5 layout, so the deployed `bridge.sil` reads its fields
at the same offsets. Deposit nonces are strictly increasing within one journal (the guest enforces
it), so a covenant can keep a single "last minted nonce" cursor (CP-6).

Covenant rule (CP-5): require `prev_header == state.header && prev_committee == state.committee`,
set state to `(new_header, new_committee)`. Pinning the committee hash, not only the header, is
what makes the prover unable to pick the committee that signs the next step. CP-6 adds: require
`vault == VAULT_CONST`, and for each deposit with nonce > cursor mint `amount` to the output script
derived from `kaspa_spk` (version 0 -> `20<payload>ac`, version 8 -> `aa20<payload>87`).

### How a deposit is proven (CP-2)

`vault/src/Vault.sol` stores `deposits[n]` in two words: `k0 = keccak256(abi.encode(uint256(n), 1))`
holds `amount | kaspaVersion << 64`, `k0 + 1` holds the 32-byte Kaspa payload (layout table in
`vault/README.md`, asserted by `vault/test/Vault.t.sol`). The host fetches both words with one
`eth_getProof` at the execution block of checkpoint_out; the guest verifies the account proof against
`exec_state_root`, both storage proofs against the account's storage root, decodes word 0 with
`primitives::vault_layout::decode_word0` (bits above 71 must be zero, amount nonzero, version 0 or 8),
refuses a zero payload, and commits `(nonce, amount, version ‖ payload)`. The layout is compiled into
the guest, so the image id pins it.

What the guest refuses: an input store carrying `next_sync_committee` or `best_valid_update`
(rotation must arrive as a signed update); a finality update that does not advance the finalized
header (participation below 2/3 or stale); a storage word claimed as zero (absent key); a word 0 that
is not a Vault deposit; nonces that are not strictly increasing.

## Trust assumptions (state these in the bridge README)

Ethereum sync committee (512 validators, 2/3 supermajority) rather than full consensus, as in
every Helios-class client; RISC Zero's toolchain and Groth16 ceremony; the covenant's pinned
image id, chain commitment and vault address; the Vault.sol code (no owner, no withdraw). No signer,
no relayer key, no admin.

## Build and run on the node box

Needs rzup with r0vm 3.0.4 and a RISC Zero Rust toolchain >= 1.90 (the dependency tree's MSRV).

```
rzup install rust 1.94.1          # or any >= 1.90 rzup offers; `rzup show` to see what is installed
rzup install r0vm 3.0.4
cd eth-prover
cargo build --release             # builds both guests (~3 min first time) and the host
./target/release/eth-prover ids   # prints both image ids; the Docker build's ids are the pinned ones
```

### 1. Offline sanity check (no network): the consensus-spec vector

```
git clone --depth 1 -b 0.12.0 https://github.com/a16z/helios /tmp/helios
RISC0_DEV_MODE=1 ./target/release/eth-prover fixture --dir /tmp/helios/ethereum/consensus-core/testdata/electra/light_client_sync
```
Expect `user cycles : 35391232` and `new_header : 0x811ca9d0...`.

### 2. Real data: one mainnet finality update

You need a beacon node that serves the light-client REST endpoints
(`/eth/v1/beacon/light_client/{bootstrap,updates,finality_update}`). ChainSafe's public Lodestar
(`https://lodestar-mainnet.chainsafe.io`) does; its `/config/spec` does not parse in helios 0.12, which
`fetch` tolerates (signatures are checked against mainnet's genesis root anyway). Mainnet is on Fulu;
Sepolia activated Gloas and Gloas light-client headers carry only an execution block hash, so the
storage-proof path needs an extra witness there (not implemented).

```
BEACON=https://lodestar-mainnet.chainsafe.io
# bootstrap at the current finalized checkpoint
./target/release/eth-prover fetch --network mainnet --consensus-rpc $BEACON --out inputs.cbor
# it prints "re-run fetch with --checkpoint 0x... in ~13 minutes": do that once a newer
# finality update exists, so there is progress to prove
./target/release/eth-prover fetch --network mainnet --consensus-rpc $BEACON --checkpoint 0x... --out inputs.cbor

# dev-mode execution: the number we are after is "user cycles"
RISC0_DEV_MODE=1 ./target/release/eth-prover execute --inputs inputs.cbor
```

### 2b. Split: GPU for the STARK, CPU box for the wrap (the operating mode)

```
# on the GPU pod (image kasperolabs/eth-prover:cuda), ~2 s per million user cycles on a 4090:
eth-prover prove --inputs inputs.cbor --no-wrap --out out-eth       # writes out-eth/receipt.succinct.bin
# copy out-eth/ (image_id.hex, journal*.hex, receipt.succinct.bin, timing.txt) to the node box, then:
./target/release/eth-prover wrap --receipt out-eth/receipt.succinct.bin --out out-eth   # Docker wrap, ~70 s
node bin/r0spend.mjs address --bundle eth-prover/out-eth
```
`wrap` verifies the succinct receipt against `image_id.hex` in `--out` before wrapping, so a receipt from a
different guest build is rejected instead of silently wrapped.

`fetch` runs the exact guest checks on the host first, so a bad endpoint or a stale update fails
in a second, not after proving. `prove` writes `timing.txt` next to the bundle.

### 3. With Vault deposits (CP-2)

```
./target/release/eth-prover fetch --network mainnet --consensus-rpc $BEACON --checkpoint 0x... \
    --execution-rpc $(cat ../eth-rpc-url.txt) --vault 0x<Vault.sol> --nonce 1 [--nonce 2 ...] --out inputs.cbor
```
`fetch` computes the two storage keys per nonce, calls `eth_getProof` once at the execution block of
checkpoint_out, decodes each deposit on the host (so an undeposited nonce fails here) and prints them.
The deposit must be in a block at or before that execution block: deposit, wait for finality (13 min nominal,
30 min observed on 2026-10-12), then fetch. `eth_getProof` for a recent block works on Alchemy's free tier;
fetch promptly. If `fetch` says `word 0 = 0 is not a Vault deposit`, the finalized block is still before the
deposit: wait one epoch and rerun with the same `--checkpoint`.

```
./target/release/eth-prover journal --file out-eth/journal.hex     # decode any journal with the frozen layout
```

## What is next

- CP-6: covenant pins the vault address, keeps a deposit cursor, mints KCC-20 to `kaspa_spk`.
- Gloas headers (Sepolia today, mainnet at Glamsterdam): add `execution_header_rlp` as a witness,
  check `keccak(rlp) == execution_block_hash`, read `state_root` and `number` from it.
- Heartbeat cost is measured once: the rotation step above cost 104.5M against 53.3M without, so a committee handoff adds about 51M cycles (the single deposit in the same step is a small part of that; a no-rotation step with a deposit will isolate it).
