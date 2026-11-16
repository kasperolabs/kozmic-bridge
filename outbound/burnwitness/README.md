# burnwitness: the outbound witness, from a Kaspa node

`burnwitness` reads one or more burns of the bridge token and the DAG after them from a rusty-kaspa node
(v2.1.0 crates, wRPC Borsh, `--utxoindex`) and writes the witness `kaspa-prover relay` consumes. It records
the node's own value of every intermediate (hashes, transaction ids, sequencing commitments) so the host can
check its recomputation before anything is proven. It is a builder, not a verifier: nothing it writes is
trusted by the guest, which recomputes everything from the raw bytes.

```
cargo build --release
./target/release/burnwitness --url ws://127.0.0.1:17110 --txid <burn>[,<burn>...] --start <block hash at or before the burn's block> \
    --token <token covenant id> --levels 30 --min-attest 660 --min-count 660 --depth-daa 53000 --extra-nonchain 3 --out witness.json
```

What it does, in order: finds each burn and its accepting chain block C; picks B, the chain block that
accepted every burn, and T, a tip `--depth-daa` DAA later; walks `parents_by_level[L]` from T for each
level to collect the PoW set; follows each counted superblock's first parents (up to three hops) to a
chain block and records the path; builds the commitment chain of state roots from B to T; dumps every
header's exact preimage; and refuses to write a witness whose attesting count at the comparison level is
below `--min-attest`, printing how many DAA are still to go (a proof below the relay's rule would be wasted
GPU, so the robot and `bin/prove-exit.sh` simply wait and rerun).

`--extra-nonchain N` records N real non-chain blocks from the mergesets after B as `extra_headers`; the
guest never sees them, they feed the adversarial suite in `outbound/kaspa-prover/host/src/adversarial.rs`
(which presents them as B and expects the inclusion step to refuse). `--check-first-parent` measures the
first-parent premise on the live chain (every chain block's `parents_by_level[0][0]` is its selected
parent; measured 10,000 of 10,000 in October 2026).

The fixtures the tests use (`witness-*.json`, tens of megabytes) are release assets: `bash
fixtures/FETCH.sh burnwitness` at the repository root downloads and checks them.

The design this implements, with the measured numbers, is `docs/V4-DESIGN.md`; the October 2026 record of
how the witness format evolved (O1 to O5) is in this repository's history before commit `1f18c7e`.
