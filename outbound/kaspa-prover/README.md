# kaspa-prover: Kaspa's proof of work, proven for Ethereum

The outbound half of Kozmic Bridge. `kaspa-relay-guest` is a RISC Zero program that takes a witness built
by `outbound/burnwitness` from a Kaspa node and proves, for one or more burns of the bridge token:

1. **Every header in the PoW set passes kHeavyHash** (blake2b x2 with the shared prefix absorbed once,
   cSHAKE256 "ProofOfWorkHash", the xoshiro-seeded 64x64 nibble matrix and heavy hash, `pow <= target(bits)`)
   and gets its **level**, `max(225 - bitlen(pow), 0)`. The level is a property of the hash alone: a
   level-30 block is about 2^61 hashes of work whatever chain it sits on and whatever its `bits` says.
2. **The ladder.** For each level L in the witness (the live relay compares at level 30), a closed walk
   from the tip T along `parents_by_level[L]` expands every level-L parent of every expanded header;
   each expanded header must be in the PoW set at level >= L. Headers whose `daa_score` is at or below
   B's are leaves. The journal carries `count` (expanded superblocks after B) and `attesting` per level.
3. **Attestation.** A counted superblock *attests* when its first parent, followed by hash through at
   most three first-parent headers (hash-verified, no PoW needed: nothing the honest network mined points
   at a fabricated one), reaches a Kaspa chain block whose `accepted_id_merkle_root` sits on the
   commitment chain `c_0 = aimr(B), c_i = H_seq(c_{i-1}, root_i)`. So every attester was mined after B.
4. **The burns.** Each transaction body is given; its id is recomputed (v0 blake2b and v1 keyed blake3
   schemes); the burn amount is the sum of its KCC-20 cells owned by the burn owner (scheme 3, the hash of
   `OP_RETURN`), each cell checked against the token's reference template; the payload is
   `"KZB1" | 0x03 | target(20) | tip(8) | recipient(20) | beacon number(8) | beacon hash(32)` with
   `tip < amount`; every burn's acceptance is proven through the KIP-21 sequencing commitment of its
   accepting chain block C (activity digest, lane tip, SMT proof, state root, seq_commit) chained forward
   to `aimr(B)`. All burns name the same target and token; no tx id appears twice; 1 to 16 per proof.
5. **The anchor.** The highest Ethereum beacon among the burns' payloads goes into the journal; the relay
   checks it against Ethereum's own history (EIP-2935) and measures time from it. Since a burn carries the
   beacon's hash, B accepts the burn and every attester commits to B, every attester was mined after the
   beacon.
6. **The difficulty reading** `r_bits`: the median compact target over the superblocks the walks expanded
   (a median, so a forger moves it only with a majority of the ladder; the relay takes
   `max(its 7-day history, r_bits)` and a proof can raise the reference, never lower it).

What is *not* checked, by design: that `bits` is the difficulty the DAA required (a header proves work at
its own claimed target; the level does not depend on it), the claimed `blue_work` and `blue_score`, the
matrix rank, and chain membership of the first-parent headers beyond their hashes. The security argument
never rests on these: it rests on the count of attesting superblocks, each of which costs 2^61 hashes and
provably postdates the beacon. `docs/V4-DESIGN.md` (sections 2.11 onward) and `docs/REVIEW-*.md` carry the
forger model and the measured numbers; do not re-derive them from this README.

## The journal (KZO6: 310 bytes + 68 per burn, big-endian)

`KaspaRelayV5.parseJournal` reads it at these offsets; `kaspa-prover journal --file <journal.hex>` decodes it.

| offset | len | field |
|---|---|---|
| 0 | 4 | magic `KZO6` |
| 4 | 32 | T, the tip; 36: T's daa_score (8) |
| 44 | 32 | B, the chain block that accepted every burn; 76: B's daa_score (8) |
| 84 | 4 | r_bits; 88: number of headers (4); 92: number of levels (1) |
| 93 | 72 | 8 x (level 1, count 4, attesting 4) |
| 165 | 20 | target (the relay contract) |
| 185 | 32 | token covenant id; 217: token template hash (32) |
| 249 | 8 | anchor block number; 257: anchor block hash (32) |
| 289 | 20 | prover: the Ethereum address the relay pays the tips to |
| 309 | 1 | number of burns n |
| 310 | 68·n | per burn: tx id (32) ‖ amount (8) ‖ tip (8) ‖ recipient (20) |

## Layout

```
kaspa-prover/
  primitives/      the verifier in plain Rust (no kaspa crates): header parsing, the hashes, the matrix, target and
                   level (lib.rs); relay.rs: sequencing-commitment hashers, SMT proofs, transaction ids, the ladder
                   walks, the KCC-20 burn cell check, the witness and journal formats
  methods/guest/   kaspa-relay-guest (the live program) and kaspa-header-guest (the 2026-10 header-cost study)
  host/            the kaspa-prover CLI: relay | prove | wrap | verify | journal | ids | check | execute | sweep | synth
                   adversarial.rs: the adversarial suite (needs a real witness; see burnwitness)
  docker/          the CUDA image; its `ids` target prints the pinnable image id
  IMAGE_IDS.txt    the Docker build's ids at the time of the last build in this tree
```

## Use it

```
cd outbound/kaspa-prover && cargo build --release            # host build; its own image id is never the pinned one
docker build -f docker/Dockerfile.cuda --target ids --output type=local,dest=. . && cat IMAGE_IDS.txt   # the pinnable id

./target/release/kaspa-prover relay --witness W.json --prover 0x<eth address> --native-only --out-input job/relay-input.bin
RISC0_DEV_MODE=1 ./target/release/kaspa-prover prove --input job/relay-input.bin --no-wrap --out job/devexec   # cycles, journal
docker run --rm --gpus all -v $PWD/job:/work <image> kaspa-prover prove --input /work/relay-input.bin --no-wrap --out /work
./target/release/kaspa-prover wrap --receipt job/receipt.succinct.bin --out job
./target/release/kaspa-prover verify --bundle job --image-id $(cat job/image_id.hex)
./target/release/kaspa-prover journal --file job/journal.hex
```

`relay --native-only` recomputes every intermediate (hashes, ids, commitments) and compares them with the
values the witness recorded from the node before anything is proven. `bin/prove-exit.sh` at the repository
root runs the whole sequence and submits to the relay.

The adversarial suite (`host/src/adversarial.rs`) takes a real witness, changes one thing and asserts what
the guest does: the exact panic for what it detects (duplicate or missing headers, a rewired first parent,
a tampered burn, a wrong chain root, a real non-chain block as B, bad levels or burn counts) or a strictly
weaker journal for what it cannot tell from an honest witness (a forged B gets no honest attesters; a wrong
or shortened attestation chain loses attesters; a tampered first-parent header gains nothing):

```
RELAY_WITNESS=/abs/path/witness.json cargo test --release -p kaspa-prover-host -- adversarial --nocapture --test-threads 1
RELAY_ZKVM=1 ...      # also execute every case in the zkVM (dev mode) and require it to agree with the native run
```

Costs on the live instance: about 1.15M cycles per header; a 600-attester exit is about 700M cycles, 15 to
25 minutes on an RTX 4090 plus the 71 s wrap. The October 2026 study that sized this (header cost E1, the
superblock estimator E2, the first relay proofs O1 to O5) is in this repository's history before commit
`1f18c7e` and summarised in `docs/V4-DESIGN.md`.
