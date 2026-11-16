# O1: the outbound relay guest, in dev mode, on a real burn

Stage O1 of the outbound leg (HANDOFF section 8). Vehicle: **wrapped KAS on Ethereum, one way**. KAS is
burned on Kaspa mainnet, a RISC Zero guest proves the burn and the proof-of-work behind it, Ethereum
mints wKAS to the recipient named in the burn (O3). This stage builds and measures the guest; nothing
is proven or minted yet.

Three pieces, in the order they run:

| piece | where | toolchain |
|---|---|---|
| `bin/burn.mjs` | repo root | Node 20 + the vendored SDK v2.1.0 |
| `outbound/burnwitness/` | this directory | rusty-kaspa v2.1.0 crates in Docker `rust:1.97-bookworm` (as dagwalk) |
| `outbound/kaspa-prover/` `relay` subcommand + `kaspa-relay-guest` | kaspa-prover | the rzup toolchain of E1 (risc0-zkvm 3.0.4) |

## What a relay proof says

For a checkpoint K the relay already trusts and a tip B chosen by the prover:

1. **Headers.** Every header in the witness passes kHeavyHash (the E1 verifier: blake2b x2, cSHAKE,
   matrix, heavy hash, target, level) and is listed once.
2. **Ladder.** For each level L in the ladder (default 28, 30, 32): the closed walk from B along
   `parents_by_level[L]` reaches K; every level-L parent of every expanded header is in the witness;
   a header whose claimed `daa_score` is at or below K's is a leaf (verified, not expanded, not
   counted). The journal carries, per level, the number of expanded headers: superblocks at level
   >= L in past(B) and after K. That count times 2^(31+L) is the work bound (study E2, dagwalk).
   K and B must be at level >= L_max; B must come after K.
3. **Burns, 1 to 16 per proof.** Each transaction body is given; its id is recomputed (`hashing/tx.rs`,
   v0 and v1 including the blake3 `TransactionV1Id` scheme); it is a native-lane transaction; the
   amount is the **sum of every output** paying `20 <NUMS key> ac` (BIP-341's point H, nothing can sign
   for it), so no honest output is stranded; the payload is
   `"KZB1" | 0x02 | target(20) | tip(8, big-endian sompi) | recipient(20)` with `tip <= amount`.
   `target` binds the burn to one relay contract (the contract requires `target == address(this)`), so
   a burn can never be claimed on two relay instances; `tip` is paid from the burned amount to whoever
   submits the proof, so running a prover pays without anyone being able to inflate it. All burns in
   a proof name the same target; no tx id appears twice.
4. **Acceptance, chained to B, per burn.** The transaction's activity leaf sits in the native lane's
   activity digest of its chain block C; the lane tip, SMT leaf, lanes root, activity root, state root
   and seq_commit(C) are recomputed as `utxo_validation.rs` and `consensus/seq-commit` do; seq_commit
   is then chained through the state roots of the chain blocks after C and must equal B's
   `accepted_id_merkle_root`. Consensus validates that field for every chain block, so an honest B
   binds the burn's canonical acceptance. A dishonest B has to win the superblock count first (E3').

Two corrections to the study, found in the v2.1.0 source while building this:
- the sequencing commitment and the v1 transaction id use **keyed blake3** (key = domain string
  zero-padded to 32 bytes), not blake2b; only `BlockHash` and the v0 `TransactionID` are blake2b;
- `parents_at_level` closure in `validate_pruning_proof` only needs *one* known level parent per
  header; this guest requires *all* of them (dagwalk showed closed level-L walks are complete on
  mainnet, so honest provers lose nothing and selection is ruled out).

Chain membership of C is not proven by GHOSTDAG (not ported, per saefstroem) nor by claimed
`blue_work` (a claim); it is proven by the seq_commit hash chain, which every chain block's header
commits to and consensus checks. That is what made the inclusion part cheap.

Journal (142 + 68 n bytes, big-endian; `primitives/src/relay.rs`, `Journal`):
`"KZO1" | K(32) | B(32) | B.daa(8) | headers(4) | n_levels(1) | 8 x (level u8, count u32) | target(20) |
n_burns(1) | n x (tx id 32 | amount 8 | tip 8 | recipient 20)`. The contract reads it at fixed offsets:
K must equal its checkpoint, the counts decide the comparison, B becomes the next checkpoint, each burn
mints `amount - tip` to `recipient` and `tip` to the submitter, once per tx id.

Format history: v1 (the first run below) had one burn, `output_index`, a 25-byte payload without target
or tip, and K.daa in the journal. v2 (2026-10-14, after the journal review) batches burns, sums burn
outputs, binds the target, carries the tip, and drops K.daa (the contract already holds it). The v1 burn
`484d5fee…` is refused by the v2 guest: it is bound to nothing.

## Run it (node box)

Unpack `kaspa-relay-o1-v0.1.tgz` over the repo root. It adds `bin/burn.mjs`, `outbound/burnwitness/`,
and in `outbound/kaspa-prover/`: `primitives/src/relay.rs`, an updated `primitives/src/lib.rs` and
`primitives/Cargo.toml` (adds `blake3`), `methods/guest/src/bin/kaspa-relay-guest.rs`, and an updated
`host/src/main.rs` (the `relay` subcommand; `ids` now prints both guests).

```bash
cd ~/kaspa-zk/kaspa-zk-tests
tar xzf kaspa-relay-o1-v0.1.tgz

# 0. primitives unit tests: rusty-kaspa's tx-id vectors and the seq-commit crate's goldens
cd outbound/kaspa-prover && cargo test -p kaspa-prover-primitives --release 2>&1 | tail -20
cargo build --release 2>&1 | tail -3          # builds both guests; the lock gains blake3 only
./target/release/kaspa-prover ids

# 1. burn 0.2 KAS from the genesis key (fund kaspa:qzzkh3... first if it is empty); --target is the
#    relay contract the burn is bound to (until O3 deploys it, any address: those burns stay test burns)
cd ~/kaspa-zk/kaspa-zk-tests
node bin/burn.mjs --to 0x4aC7b1478afeaf28a4c62d59160Ad4c81C229105 --target 0x<relay> --tip 0.01 --amount 0.2
#    -> prints the sink before submission (START) and the TXID; several burns batch with --txid a,b below

# 2. the witness (wait 2 to 3 minutes for a level-32 chain block after the burn)
cd outbound/burnwitness
docker run --rm --network host -v "$PWD":/w -w /w \
  -v kpow-cargo-registry:/usr/local/cargo/registry -v kpow-cargo-git:/usr/local/cargo/git \
  rust:1.97-bookworm \
  cargo run --release -- --url ws://127.0.0.1:17110 --txid TXID1,TXID2 --start START --levels 28,30,32 --hours 1 --out /w/witness.json

# 3. native check, then the guest in dev mode (cycles)
cd ../kaspa-prover
RISC0_DEV_MODE=1 ./target/release/kaspa-prover relay --witness ../burnwitness/witness.json --native-only
RISC0_DEV_MODE=1 ./target/release/kaspa-prover relay --witness ../burnwitness/witness.json --levels 32
RISC0_DEV_MODE=1 ./target/release/kaspa-prover relay --witness ../burnwitness/witness.json --levels 30,32
RISC0_DEV_MODE=1 ./target/release/kaspa-prover relay --witness ../burnwitness/witness.json
```

`burnwitness` prints `ok`/`DIFF` for the lane tip and seq_commit(C) computed with the node's own crates,
the ladder table (counted, leaves, visited, max level parents per level), and the checkpoint it chose.
`kaspa-prover relay` prints the same intermediates computed by the guest's code next to the node's
values, the per-level counts, then user cycles and segments for the zkVM execution.

Numbers this stage produces (E4 and E6 of the study): cycles for the inclusion part (run with
`--levels 32`, a few dozen headers, and subtract the headers' 555k each), cycles per ladder level over
one hour, and the total for the three-level ladder. The GPU proof and wrap are O2.

## Results (2026-10-14, mainnet, node box)

**Burn:** tx `484d5fee3cd99dfcdf7253301409b41fb525cf1728f269ffe5c5f718363088b6`, v0, 0.2 KAS (20,000,000 sompi)
to `kaspa:qpgf9xm5cxsyj49h3d9kqd0f0f0q0zj6pu5we9k4g7l7axkwsqavqnhtu3wx3` (the NUMS key, spk version 0,
script `20 5092…3ac0 ac`), payload `0x4b5a4231 01 4ac7b1478afeaf28a4c62d59160ad4c81c229105`, fee 420,400 sompi,
from the genesis key `kaspa:qzzkh3…`. START (sink at submission) `e9382bf7…`.

**Witness (burnwitness, 1 m 04 s build, ~1 min run, 2,288 RPC calls):** accepted in chain block
C `446e654a3923829c8d4cd543c036a4e0cc901825177426905403be1ef7f7100d` (daa 565,774,764, blue score
563,738,992), selected parent `dfb59a9e…`; 4 accepted txs in C over 2 lanes, native lane 3, burn at index 2.
`lane tip ok`, `seq_commit(C) ok` with the node's own `kaspa_seq_commit` and `kaspa_smt` crates: the
merge-order, lane-tip, SMT (collapsed hasher `SeqCommitActiveCollapsedNode`) and state-root assumptions hold
on a live block. B `0b85b644386f71a4dc6cd8022988eafbccc3cac4b8d98ee43429bc1f5a38b586` (level 34, daa
565,775,019), 33 chain blocks after C, seq_commit chain ok. K `1afb30c501a78a455ea806b6ecc0b8e41b555bf6064d3c014049ff589f8485d8`
(level 34, daa 565,738,734), 1.00 h before B.

| level | counted | leaves | visited | max level parents |
|---|---|---|---|---|
| 28 | 2,214 | 1 | 2,216 | 7 |
| 30 | 533 | 0 | 534 | 4 |
| 32 | 124 | 0 | 125 | 2 |

2,216 unique headers, 17,206,344 bytes (avg 7,764). The counts match dagwalk's hour (2,201 / 544 / 133).

**Guest (`kaspa-prover relay`, dev mode, relay image `9acc2f0f…` native build, not pinned):** every
intermediate (tx id, activity digest, context hash, lane tip, lanes root, seq_commit(C), seq_commit(B))
equal to the node's; per-level counts equal burnwitness's; guest journal equal to the native run in all three
executions.

| levels | headers | input bytes | user cycles | padded | segments | exec | journal sha256 |
|---|---|---|---|---|---|---|---|
| 32 | 125 | 979,293 | 74,689,309 | 82,313,216 | 79 | 1.9 s | `cf30297a…` |
| 30, 32 | 534 | 4,185,142 | 316,838,840 | 349,175,808 | 333 | 7.9 s | `ba58de38…` |
| 28, 30, 32 | 2,216 | 17,206,344 | 1,304,712,005 | 1,441,005,568 | 1,375 | 32.3 s | `95eeeb36…` |

Differencing: **~590k user cycles per header** (592k between the first two runs, 587k between the last two;
E1 measured 555k on 7,400-byte headers) and **~0.7M cycles for everything that is not a header**: the three
walks, the burn body and its id, the activity digest, the SMT proof, and the 33-step seq_commit chain. That is
E4: inclusion is under a million cycles, which is less than two headers. E6 at the measured 2 s per million
cycles on a 4090: a one-hour update at level 32 alone ~2.5 GPU-min (124 superblocks, ±9%), levels 30+32
~10.5 min (±4.3% at the lower level), 28+30+32 ~43 min (±2.1%). Which levels a relay carries is the O6 decision
(window, cap, luck bound); the cost per level is now measured, not estimated.

Journal of the full run: K `1afb30c5…`, B `0b85b644…`, K daa 565,738,734, B daa 565,775,019, 2,216 headers,
levels (28, 2214) (30, 533) (32, 124), tx `484d5fee…`, 20,000,000 sompi, payload v1, recipient
`0x4ac7b1478afeaf28a4c62d59160ad4c81c229105`.

### v2 run (2026-10-14, two burns in one proof, journal v2)

Burns from the genesis key, both bound to target `0x4ac7…9105` (placeholder until O3 deploys the relay):
`8a5183920ce882db1f2c566b0efeefa0de8b66fc8c8865b8f7022238d8672597` (0.2 KAS, tip 0.01 KAS, START `6bf0edfb…`,
accepted in C `3eb975d7…` daa 565,805,036, native lane 1 tx) and
`892751f5e4a1703b3e9164b30dc0a2c9abbc15e7ba8f31c312b12d9e1c3444f1` (0.2 KAS, tip 0, accepted in C `7659a368…`
daa 565,807,035, native lane 3 txs, burn at index 2). A 0.1 KAS burn was refused by the SDK's generator
("Storage mass exceeds maximum"): a lone 0.1 KAS output is 100,000 grams of KIP-9 storage mass, the standard
transaction ceiling, so **a burn output must hold more than 0.1 KAS** (0.2 KAS is 50,000 grams).

B `2be052112b1cadfcc8c8b1d09ce59aa7f884b96c3ec0955875989c5ca9090847` (level 32, daa 565,807,371; 328 and 47 chain
blocks after the two C's), K `50cd38262bd49da71d1b9389e3cab622e866de14f58791f9464f900b0770e5e5` (level 34, 1.01 h
before B). Ladder: 28: 2,275 (2 leaves), 30: 523, 32: 112; 2,278 headers, 17,460,230 bytes (avg 7,664). Every
intermediate `ok` for both burns, both seq_commit chains end at B's `268c32e2…`; `lane tip` and `seq_commit(C)`
`ok` in burnwitness with the node's crates.

`relay --levels 30,32`: 524 headers, 3,970,156 input bytes, **304,410,525 user cycles**, 335,544,320 padded,
**320 segments**, 7.6 s dev-mode; journal 278 bytes (142 + 2 x 68), sha256 `70f9ed7a…`, relay image (native,
not pinned) `1731819156c937a8a9dcd58039637599d708531ab3128541c021a7168eb5785d`. ~581k per header; the second
burn and its 375 extra chain steps cost nothing visible against the v1 single-burn run (316.8M for 534 headers).

Next: O2, prove this witness on a rented GPU and Groth16-wrap it (eth-prover's Docker and `wrap` pattern;
`kaspa-prover relay --out-input` writes the 4 MB frame to feed a `prove` subcommand).


## O5 additions (2026-10-15)

- `--extra-nonchain N`: after the ladders, record N real blocks that are not on the selected chain (taken from the
  mergesets of chain blocks in (B, T]) under `extra_headers` with their preimage, selected parent and whether that
  parent is a chain block. The adversarial tests in `outbound/kaspa-prover/host/src/adversarial.rs` present them as B;
  the guest refuses each at the inclusion step, since no node-served data chains a burn to such a block.
- `--check-first-parent` now follows first parents from every superblock until a chain block (up to five steps) and
  prints, per level, the histogram of steps plus how many non-direct superblocks join within two and three steps
  (`first_parent_steps_hist` in the JSON). Measured 2026-10-15 over two independent hours: 10,000 of 10,000 chain
  blocks with first parent == selected parent; level 28: 2,334 superblocks, 1,750 direct, 538 of the 584 others
  within three steps, 4 never within five; level 30: 599, 443 direct, 140 of 156 within three; level 32: 150, 100
  direct, 48 of 50 within three. Design doc 8.1: a three-step rule recovers ~90% of the non-attesting honest
  superblocks.
- Witnesses of the night: `witness-o5-p0.json` (two burns, K 8.55 h old, 4,958 level-30 superblocks, 4,960 headers,
  38.8 MB, 11,361 RPC calls), `witness-o5-floor.json` (`--depth-daa 8400 --min-count 0 --min-attest 0`: T 4.7 min
  past K, 43 counted, for the below-the-floor rejection), `witness-o5-a.json` and `witness-o5-b.json` (the competing
  submissions, 1,274 and 1,435 counted). A K that is hours old is fine for the builder; the cost is in the proof.
