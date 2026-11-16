# kaspa-prover: Kaspa headers verified inside the RISC Zero zkVM

Outbound study, experiment **E1**: what does one Kaspa mainnet header cost to verify inside the zkVM?
The number this produces, **user cycles per header**, decides the rest of the study (section 4 of
`docs/KASPA-OUTBOUND-STUDY.md`): under 50k, full-header verification works for hour-scale windows on one GPU;
50k to 300k, parallel segments; above that, superblock compression is mandatory.

Since 2026-10-14 the same crate also carries **O1, the relay guest** (`kaspa-relay-guest`, `relay` subcommand):
superblock ladders plus the burn's acceptance through the KIP-21 sequencing commitment. See the last section
and `outbound/burnwitness/README.md`.

Same toolchain pins as `eth-prover/` (risc0-zkvm 3.0.4 and its sibling crates, the risc0 tiny-keccak fork).
Everything here runs in **dev mode** (execution only, no proof); the number is the cycle count, and the guest's
image id is not pinned by anything yet.

## What the guest checks, per header

Input: the header's exact serialized preimage (the bytes `hash_override_nonce_time` in
`consensus/core/src/hashing/header.rs` feeds to blake2b), as `outbound/kpow/vectors` dumps them from a node.

1. **parse**: version, parents by level (the level-0 list is kept for the link check), timestamp, bits, nonce,
   daa_score, blue_score, blue_work, pruning_point; the length must match exactly.
2. **hash**: blake2b-256 keyed `"BlockHash"` over the preimage (the block hash), and again with timestamp and
   nonce zeroed (`pre_pow_hash`). The two share every byte before the timestamp, so the prefix is absorbed once
   and the state cloned: one and a bit blake2b passes instead of two.
3. **powhash**: cSHAKE256("ProofOfWorkHash") over `pre_pow_hash | timestamp | 0^32 | nonce`, one keccak-f[1600]
   from the precomputed sponge state (the same constants as `crypto/hashes/src/pow_hashers.rs`, copied verbatim
   and re-derived from the cSHAKE definition in a unit test).
4. **full**: xoshiro256++ seeded with `pre_pow_hash`, the 64x64 nibble matrix, the heavy-hash product, XOR,
   cSHAKE256("HeavyHash") (the second keccak-f), `pow <= target(bits)`, and the level
   `max(225 - bitlen(pow), 0)` (mainnet `max_block_level` = 225).
5. **link**: header i's hash must appear among header i+1's direct parents (so the batch is one chain of
   descendants, not a bag of unrelated headers).

Stages are cumulative and chosen by the input, so each one can be measured alone by differencing.

The two keccak-f permutations go through the zkVM's **keccak coprocessor**
(`risc0_zkvm::guest::env::risc0_keccak_update`, the same path the risc0 tiny-keccak fork uses). The input can
switch the guest to the plain software permutation to measure what the accelerator saves. blake2b has no
accelerator in risc0 3.0; it runs as RISC-V code (`blake2b_simd`, portable path) and is expected to dominate.

Not checked (same as `kpow`, see its README): the matrix **rank** (rusty-kaspa regenerates the matrix until it has
full rank, in floating point; this verifier uses the first matrix, and the host refuses any vector where rusty-kaspa
needed more than one attempt), that **bits is the difficulty the DAA required** (a header proves work at its own
claimed target), the claimed **blue_work**, and anything inside the block.

## Layout

```
kaspa-prover/
  primitives/      the verifier, in plain Rust with no kaspa crates: parse, hashes, matrix, target, level,
                   staged verify, input and journal formats. Unit tests re-derive the cSHAKE constants and check
                   blake2b against rusty-kaspa's own test vectors.
                   relay.rs (O1): keyed blake3 hashers of the sequencing commitment, SMT proof verification,
                   transaction ids (v0, v1), the ladder walks, the relay witness and journal; tests against
                   rusty-kaspa's tx-id vectors and the seq-commit crate's golden values.
  methods/guest/   kaspa-header-guest (E1) and src/bin/kaspa-relay-guest (O1): read the input frame, run the
                   primitives, commit the journal
  host/            the kaspa-prover CLI: check | execute | sweep | relay | synth | ids
  Cargo.lock, methods/guest/Cargo.lock   pinned like eth-prover (risc0-zkvm 3.0.4, risc0-zkp 3.0.3,
                   circuits 4.0.3, groth16 3.0.3, binfmt 3.0.3; tiny-keccak = risc0 fork v2.0.2-risczero.0;
                   blake3 1.8 added for O1)
```

## Journal (592 bytes, big-endian)

| offset | len | field |
|---|---|---|
| 0 | 4 | n headers |
| 4 | 1 | stage (0 parse, 1 hash, 2 powhash, 3 full) |
| 5 | 1 | links checked |
| 6 | 1 | keccak path (0 accelerator, 1 software); informational |
| 7 | 1 | reserved |
| 8 | 32 | hash of the first (oldest) header |
| 40 | 32 | hash of the last (newest) header |
| 72 | 4 | min level |
| 76 | 4 | max level |
| 80 | 512 | level histogram, u16 per level 0..=255 (full stage only) |

Input frame: `"KZE1" | stage u8 | link u8 | keccak u8 | n u32 LE | n x (len u32 LE, preimage)`, oldest first.

## Run it on the node box

Needs the rzup toolchain `eth-prover/` already builds with (`rzup install rust 1.94.1`, `rzup install r0vm 3.0.4`)
and the vectors from `outbound/kpow` (200 mainnet chain blocks; `--count 36000` for an hour).

```bash
cd ~/kaspa-zk/kaspa-zk-tests/outbound/kaspa-prover
cargo build --release                       # builds the guest too (first build a few minutes)

# 1. native cross-check: every stage of every vector against rusty-kaspa's values, no zkVM involved
./target/release/kaspa-prover check --vectors ../kpow/sol/vectors.json

# 2. one dev-mode run (8 headers, full verification, accelerated keccak)
RISC0_DEV_MODE=1 ./target/release/kaspa-prover execute --vectors ../kpow/sol/vectors.json --count 8

# 3. the E1 table: full verification at 0,1,2,4,...,128,200 headers (marginal cycles per header),
#    each stage at 200 (cost breakdown), and the software-keccak comparison at 200
RISC0_DEV_MODE=1 ./target/release/kaspa-prover sweep --vectors ../kpow/sol/vectors.json --out e1-results.json
```

Without a node: `kaspa-prover synth --count 8 --out vectors.synth.json` writes parent-linked synthetic headers
(values computed by this crate, so only the plumbing is tested; PoW does not pass on them, so run `execute` on
them with `--stage powhash` at most).

## Reading the sweep

- **marginal cost** is the least-squares slope of user cycles over the header count: the per-header number E1
  asks for, with the fixed program setup removed. "last interval" is the same thing from the two largest counts.
- **cost by stage** at the full count: parse, +blake2b, +PoW keccak, +matrix/heavy/target/level, each as the
  delta over the previous stage divided by the header count.
- **software keccak** at the full count: the same run with the permutation done in RISC-V instructions. The
  difference to the accelerated run is what the keccak coprocessor saves per header (two permutations).
- `padded cycles` (sum of 2^po2 over segments) is what proving pays for; at small counts it is dominated by
  segment padding, so judge by user cycles and the slope.
- Every run's journal is compared with the same code run natively; a mismatch fails the run.

## Results (2026-10-14, node box, 200 mainnet chain blocks from kpow's vectors, sink `a1b60c0a…`)

Dev-mode image id `6538d47dd16e3a6dd3cc3f7dbb0961adc510cf4b0b7be7f6386a90abc24c22cb` (native build, not pinned).
`check`: all 200 headers equal rusty-kaspa at every stage (block hash, pre_pow_hash, pow hash, pow, level, passed;
the vector's matrix-row packing is undocumented and matched none of the four natural candidates, but pow matching
proves the matrix). Guest journals matched the native run on every execution.

**Full verification, keccak accelerated, by header count** (links checked):

| headers | segments | user cycles | padded cycles | per header |
|---|---|---|---|---|
| 0 | 1 | 8,677 | 65,536 | setup only |
| 1 | 1 | 325,618 | 524,288 | 325,618 |
| 8 | 4 | 3,812,517 | 4,194,304 | 476,564 |
| 32 | 19 | 18,413,791 | 19,922,944 | 575,430 |
| 128 | 74 | 71,073,551 | 76,611,584 | 555,262 |
| 200 | 114 | 110,412,202 | 119,013,376 | 552,061 |

**Marginal cost: 554,841 user cycles per header** (least squares over 1..200; 546,370 between 128 and 200). The
first headers are cheaper because the vectors are newest-first and the oldest (smallest) headers come first after
reversal; the slope over the whole set is the number. Padded cycles are 1.08x user cycles at 200 headers. Dev-mode
execution: 2.6 s for 200 headers.

**Cost by stage at 200 headers** (delta per header over the previous stage):

| stage | per header | delta |
|---|---|---|
| parse | 4,567 | |
| + blake2b x2 (shared prefix) | 459,002 | **454,435** |
| + PoW cSHAKE (1 keccak-f, accelerated) | 460,328 | 1,325 |
| + matrix, heavy hash (1 keccak-f, accelerated), target, level | 552,061 | 91,733 |

**Software keccak-f** at 200 headers: 582,794 per header, so the keccak coprocessor saves **30,733 cycles per
header** for the two permutations (about 15k each in software against about 1.3k through the coprocessor).

Reading: **82% of a header is blake2b** over the ~7.4 KB preimage (about 7.6k cycles per 128-byte compression on
rv32: 64-bit arithmetic in 32-bit pairs, and risc0 3.0 has no blake2b accelerator). The matrix step (generation plus
the 64x64 nibble product) is the other 16%. Keccak is already negligible. The size of a header, 56 expanded parent
levels, is what sets the cost, so headers with more parents cost more (the 2,465 to 15,201 byte range means roughly
200k to 1M cycles per header).

**E1 decision** (study section 4): 555k is far above the 300k band, so **compression is mandatory** for the
happy path. One hour of the DAG (36,080 headers, measured below) is 20B cycles, about 11 GPU-hours per chain-hour
at the measured 2 s per million cycles; the selected chain alone (4,905 an hour) is 1.5 GPU-hours and proves 13.6%
of the work (next section). What the number does make cheap: a single header is 1.1 s of GPU; a D5 bisection
ends on one header; a superblock proof of a few hundred headers is a minute or two of GPU per update, which is the
D6 shape. Next measurement: superblocks per level per hour from the node (weekend item 3) to size a D6 update.

## E2 and the superblock estimator (2026-10-14, 36,000 chain blocks, sink `439a9d0e…`, `vectors-1h.json`)

`check` on 36,000 consecutive chain blocks: all equal rusty-kaspa at every stage (the matrix dump is "nibble 2k
low, bytes reversed", a `bytes32` of the Solidity `uint256` row). Header bytes 2,433 / 7,716 avg / 15,361.

**The window, read from the headers:** 26,434 s (**7.34 h**, so `--count 36000` is seven hours of chain blocks, not
one). Chain blocks 1.36/s; DAG blocks (Δdaa_score) 10.02/s; blue blocks (Δblue_score) 10.02/s: 264,899 blue of
264,993, **94 red blocks in 7.3 h (0.035%)**. The selected chain is **13.6% of the blocks and 13.6% of blue work**
(chain work 1.2267e21 of Δblue_work 9.0248e21 hashes): that is E2. Hashrate over the window: 9.0248e21 / 26,434 s =
**341 PH/s**, 3.4e16 hashes per block (E7 input). Per hour: 4,905 chain blocks, 36,080 DAG blocks.

**Superblock estimator** (blocks at level >= L on the chain, times 2^(31+L) hashes, over the chain's own work):

| level | at L | at >= L | est / chain work |
|---|---|---|---|
| 23 | 1,922 | 36,000 | 0.529 (= target / 2^202: below the base level, every valid block already counts) |
| 24 | 17,089 | 34,078 | 1.001 |
| 25 | 8,492 | 16,989 | 0.998 |
| 26 | 4,108 | 8,497 | 0.998 |
| 27 | 2,226 | 4,389 | 1.031 |
| 28 | 1,117 | 2,163 | 1.016 |
| 29 | 523 | 1,046 | 0.983 |
| 30 | 273 | 523 | 0.983 |
| 31 | 131 | 250 | 0.940 |
| 32 | 61 | 119 | 0.895 |
| 33 | 32 | 58 | 0.872 |
| 34 | 13 | 26 | 0.782 |
| 36 | 3 | 8 | 0.962 |
| 38 | 2 | 4 | 1.925 |

Within 3% from the base level up to level 30 (523 blocks); beyond that the deviation is what 1/sqrt(count) predicts
(±6% at 250, ±9% at 119, ±20% at 26, single blocks at the top). Rule for sizing a compact proof: the relative error
is 1/sqrt(number of superblocks shown), at any level; ~500 superblocks for ±5%, ~100 for ±10%.

**What it means with E1's 555k per header:**
- D1 (every DAG header): 36,080 x 555k = 20B cycles per hour of chain, ~11 GPU-hours per hour. Dead.
- D2 (chain only): 4,905 x 555k = 2.7B cycles per hour, ~1.5 GPU-hours per hour (~$1.35), and it bounds 13.6% of the
  work. Possible with two pods in parallel, slow and expensive for what it proves.
- D6 (superblocks, DAG-wide, 7.4x the chain counts): level >= 30 gives ~525 per hour, ~290M cycles, ~10 GPU-minutes,
  about $0.15 per hourly update at ±4%; level >= 32 gives ~120 per hour, ~2 minutes, ±9%.

Caveat for E3': this table counts superblocks on the selected chain, an honest sample by construction. A D6 proof
walks `parents_by_level[L]` across the DAG and the prover chooses what to show; selection and suppression attacks
live there, and this table says nothing about them. It shows the statistic is right, not that the comparison rule
is safe.

## O1: the relay guest on a real burn (2026-10-14)

`kaspa-relay-guest` (dev-mode image `1731819156c937a8a9dcd58039637599d708531ab3128541c021a7168eb5785d` for the
v2 journal, `9acc2f0f…` for v1; native builds, not pinned) verifies, for a checkpoint K and a tip B: every header's PoW; closed walks over
`parents_by_level[L]` from B to K for each ladder level, counting superblocks after K; each burn transaction's
body, id, summed burn outputs and v2 payload (target, tip, recipient; 1 to 16 burns per proof); and its acceptance under B through the KIP-21 sequencing commitment
(activity digest, lane tip, SMT proof, state root, seq_commit chained along the selected chain to B's
`accepted_id_merkle_root`). The witness comes from `outbound/burnwitness` (rusty-kaspa crates), which records the
node's own value of every intermediate hash; `kaspa-prover relay` compares them, runs the program natively, then
in the zkVM. Design, run commands and the full record: `outbound/burnwitness/README.md`.

Measured on burn tx `484d5fee…` (0.2 KAS, accepted in chain block `446e654a…`, B `0b85b644…` 33 chain blocks
later, K `1afb30c5…` one hour back):

| levels | headers | user cycles | segments | dev-mode exec |
|---|---|---|---|---|
| 32 | 125 | 74,689,309 | 79 | 1.9 s |
| 30, 32 | 534 | 316,838,840 | 333 | 7.9 s |
| 28, 30, 32 | 2,216 | 1,304,712,005 | 1,375 | 32.3 s |
| 30, 32, journal v2, two burns (`8a518392…`, `892751f5…`), B `2be05211…` | 524 | 304,410,525 | 320 | 7.6 s |

**~590k user cycles per header, ~0.7M for everything else** (walks, tx id, activity digest, SMT proof, 33-step
seq_commit chain). Every intermediate equal to the node's; journals equal to the native runs. E4 is under a
million cycles; E6 per hourly update at 2 s/M on a 4090: ~2.5 GPU-min (level 32), ~10.5 min (30+32), ~43 min (28+30+32).

## O2: a real proof of the relay guest (GPU STARK, Groth16 wrap)

The O1 journal is only a dev-mode claim. O2 produces the receipt the Ethereum relay contract will verify:
`prove --no-wrap` on a rented GPU inside `kasperolabs/kaspa-prover:cuda` (the pinned toolchain, so the image id is
the one to pin), `wrap` on the node box (r0vm 3.0.4 + Docker, RISC Zero's `risczero/risc0-groth16-prover`), then
`verify` on the bundle alone. `bin/relay-prove.mjs` runs the five steps and records everything; the pod lifecycle is
`src/runpod.js`, lifted from `bin/bridge-prover.mjs` (CP-7).

```
# 1. the GPU image (x86_64 box with Docker, no GPU needed; ~30 min the first time, minutes after a source change)
cd outbound/kaspa-prover
docker build -f docker/Dockerfile.cuda -t kasperolabs/kaspa-prover:cuda .
docker build -f docker/Dockerfile.cuda --target ids --output type=local,dest=. . && cat IMAGE_IDS.txt   # the pinnable ids
docker push kasperolabs/kaspa-prover:cuda                                                              # the pod pulls it

# 2. the host on this box (native build: fetch-free, decodes journals, wraps; its own image id is NOT the pinned one)
cargo build --release

# 3. one proof: native check, dev-mode cycles, pod STARK, wrap, verify, record.json
cd ../..
node bin/relay-prove.mjs --witness outbound/burnwitness/witness.json --levels 30,32 --out outbound/kaspa-prover/out-relay-1

# by hand, the same thing
./target/release/kaspa-prover relay --witness ../burnwitness/witness.json --levels 30,32 --native-only --out-input relay-input.bin
docker run --rm --gpus all -v $PWD:/work kasperolabs/kaspa-prover:cuda kaspa-prover prove --input /work/relay-input.bin --no-wrap --out /work/out   # on a GPU box
./target/release/kaspa-prover wrap --receipt out/receipt.succinct.bin --out out
./target/release/kaspa-prover verify --bundle out --image-id $(cat out/image_id.hex)
./target/release/kaspa-prover journal --file out/journal.hex
```

Bundle layout, the same as `prover/` and `eth-prover/`: `image_id.hex` (the pod's build), `journal.hex` (O1 v2 layout),
`journal_hash.hex` (sha256), `receipt.hex` (borsh of the Groth16 receipt; the 256-byte seal inside is what the Ethereum
verifier takes), `receipt.succinct.bin` (between the two machines), `timing.txt`, `prove.log`, `wrap.log`, `verify.log`,
`record.json`. `wrap` verifies the succinct receipt against `image_id.hex` before wrapping and `verify` reconstructs the
receipt from `receipt.hex` + `journal.hex` and verifies it against the image id, so a bundle that passes `verify` on a
clean checkout is the evidence.

### Record (2026-10-14, `out-relay-1`, the v2 witness: two burns, levels 30+32)

| | |
|---|---|
| image `kasperolabs/kaspa-prover:cuda` | digest `sha256:1b0eea83631740c1cf0c68d3cb2ca31cd007ebec0eabd8174beeb3c136ffa26d` |
| **relay guest image id (Docker build, the one to pin)** | **`483db80e9f2ea7a44a96f8cd888661fe5d5c86823de7f89e772a945c661018eb`** |
| header guest image id (Docker build) | `5deae50cd3b90068de986488fc7cbc94168f0aa7892bcec346eaf408a911a173` |
| native build of the same source on the node box | relay `17318191…`, header `fd3e6740…` (different toolchain, never pinned) |
| input frame | 3,985,563 bytes: 524 headers, 2 burns, levels 30 and 32 |
| dev-mode execution (box) | 304,410,525 user cycles, 335,544,320 padded, 320 segments, journal sha256 `70f9ed7a…` |
| STARK | Runpod secure pod, RTX 4090 (EU-RO-1, $0.89/h): **492.0 s** for 304.4M user cycles = **1.62 s per million** (1.47 s/M padded); pod SSH-ready 153 s after creation (image pull); pod alive ~13 min, under $0.20 |
| pod journal | sha256 `70f9ed7a51333d7e5c0df00ee9743e6a9b778555cbccc547de17594761c5d60f`, equal to the dev-mode journal |
| Groth16 wrap (node box, CPU, `risczero/risc0-groth16-prover`) | **71.7 s**; receipt 695 bytes borsh, seal 256 bytes |
| `verify --bundle out-relay-1 --image-id 483db80e…` | `verified : Groth16 receipt ok`; image id and journal hash match the bundle files |
| journal | K `50cd3826…`, B `2be05211…` (daa 565,807,371), 524 headers, level 30: 523, level 32: 112, target `0x4ac7…9105`, burns `8a518392…` (0.2 KAS, tip 0.01) and `892751f5…` (0.2 KAS, tip 0), both to `0x4ac7…9105` |

This stage has no chain transaction; its evidence is the bundle in `out-relay-1/` (`image_id.hex`, `journal.hex`,
`journal_hash.hex`, `receipt.hex`), which `kaspa-prover verify` checks on any machine with the pinned crates, and
the `ids` target of the Dockerfile, which reproduces the image id from source. The Ethereum transaction that consumes
this receipt is O3. One correction to the O1 estimate: the 4090 does 1.6 s/M on this guest, not 2, so an hourly
30+32 update is ~8 GPU-minutes and level 32 alone ~2 minutes.

A run that is interrupted after the pod finished (the STARK is on disk) resumes at the wrap with
`node bin/relay-prove.mjs --resume --out outbound/kaspa-prover/out-relay-1`.


## O5: adversarial witnesses (2026-10-15)

`host/src/adversarial.rs` (24 cases) takes a real `burnwitness` file, changes one thing and asserts what the guest
does: the exact panic for what it detects (duplicate or missing headers, a rewired first parent, a tampered burn, a
wrong chain root, a real non-chain block as B, bad levels or burn counts) or a strictly weaker journal for what it
cannot tell from an honest witness (a forged B gets zero attesters; a wrong or shortened attestation chain loses
attesters; a tampered first-parent header gains nothing). `host/src/witness.rs` holds the witness.json parser that
`relay` and the tests share. Nothing in `primitives/` or the guest changed; the image id stays `b3b91971…`.

```
cd outbound/kaspa-prover
RELAY_WITNESS=/abs/path/witness.json cargo test --release -p kaspa-prover-host -- adversarial --nocapture --test-threads 1
RELAY_ZKVM=1 ...       # also execute every case in the zkVM (dev mode) and require it to agree with the native run
RELAY_BUNDLE=/abs/path/out-relay-N   # assert the unmodified witness gives that bundle's journal hash
```

Paths are absolute because `cargo test` runs with `host/` as the working directory. Journals the contract should
refuse (`forged_b`, `thin_attestation`) are written to `out-adversarial/`; `relay/script/o5-relay.sh send-journal`
puts one on chain with a dummy seal, which is enough because the journal gates fire before the verifier. The P0
witness needs `burnwitness --extra-nonchain N` for the real-non-chain-B cases. Results and transactions:
`relay/README.md`, section "O5".

Bundles from the night: `out-relay-5` (P0, 2,990,395,621 cycles, 3,155 segments, 5,724.9 s STARK on a 4090, $1.45:
the 8.55-hour-gap proof), `out-relay-6` (A, 784,331,533 cycles, 1,608.9 s), `out-relay-7` (B, 892,650,428 cycles,
1,431.9 s). The clean-box `--target ids` build on `vmi3019233` reproduced relay `b3b91971…` and header `a669fdbc…`.
`bin/relay-prove.mjs --ip-cap 420` (default) now deletes a pod that has no IP or SSH after seven minutes instead of
waiting out the pod cap; `--pod-cap` must cover the proof (about 2 s per million user cycles plus 300).
