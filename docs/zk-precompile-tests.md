> Internal page: the Kaspa ZK precompile test suite this project grew out of (v1.0, 2026-10-11). Some statements here predate the bridge; the top-level README is current.

# kaspa-zk-tests  (v1.0)

ZK-opened UTXOs on Kaspa L1 after the Toccata hard fork (mainnet since 2026-06-30).

Three things, in the order they were proven on mainnet:

1. **A UTXO opened by a Groth16 proof and nothing else.** No key, no signer.
   Mainnet txid `8d7700f4c007c7f98082f03239416035b9af95b46e9015737f77a7e741097205`.
   The same transaction with one proof byte flipped was rejected by the node's script engine.
2. **The exact compute budget**, measured on mainnet with free under-budget rejections:
   a 5-input Groth16 P2SH spend needs **budget 1550** (`used=15,500,893` script units =
   14,000,000 precompile + 6 x 250,000 VK elements + 893 for hashing the redeem script).
   Mainnet txid `e1ee18140a6ec3a7e4745e9b175e5895bd6df45643ae41ea0f33e76866217a3b`.
3. **A covenant pinned to a program you wrote** (`prover/`): a RISC Zero guest that proves
   "this melody is in key and ends on the tonic" without revealing the melody, wrapped to
   Groth16 and spent through the SDK's `ZkScriptBuilder`.

## Status

| part | state |
|---|---|
| `test/` 32 offline tests | passing |
| `bin/live.mjs`, `bin/measure.mjs` | run on mainnet, results above |
| `bin/r0spend.mjs` with `fixtures/r0-example` (SDK's own RISC Zero receipt) | scripts build and match the SDK; address `kaspa:prr6mc7myqn2umzt758qhv2gnvahrqapq0d5zwul4y5t55gexw55geyupwjud`; not yet spent on chain |
| `prover/` (Rust, risc0-zkvm 3.0.4) | written against the 3.0 API, **not compiled in the authoring environment** (no crates.io there). Expect at most small API fixes on first build. |

## How the program-pinned covenant works (the thing to explain to others)

A RISC Zero guest is an ordinary Rust program. Proving it yields a receipt with three parts:
the **image id** (a hash of the program: *which* program ran), the **journal** (bytes the
program chose to publish: *what it said*), and the **seal** (the proof that this program really
produced this journal). Private inputs never appear. The Groth16 wrap is a proof about that
proof, 128 bytes, checkable by the BN254 pairing opcode.

On Kaspa, the redeem script pins the image id (`ZkScriptBuilder.commitToGroth16(imageId)`),
which embeds RISC Zero's fixed verifying key and the code to rebuild the receipt claim from
image id + journal hash in script. The spender pushes the journal hash and the proof
(`finalizeWithGroth16Proof(receipt, journalHash)`). `OpZkPrecompile` checks the pairing; it fails
for any other program, any other journal, or any altered byte. Anything the covenant then does
with the journal (pay the address it names, advance a counter) is ordinary script.

That structure is the bridge: private witness (melody / foreign-chain data), public rule (in key /
validly finalized), public output (hash / deposit amount and recipient), program pinned by image id.

No npm dependencies. Node 22+. The Kaspa WASM SDK v2.1.0 (the consensus code compiled to
wasm) is vendored under `vendor/kaspa`, taken from the rusty-kaspa v2.1.0 GitHub release.
The ZK precompile interface, pricing and limits are identical in v2.0.0, v2.0.1 and v2.1.0
(verified by diffing `crypto/txscript/src/zk_precompiles` across the tags).

## What is in here

| path | what |
|---|---|
| `fixtures/` | proof vectors copied verbatim from `rusty-kaspa/crypto/txscript/src/zk_precompiles/tests/` (commit 90dbf07, v2.0.0). One Groth16/BN254 proof (with VK and 5 public inputs) and one RISC Zero Succinct receipt. These are the vectors kaspad's own unit tests verify. |
| `src/zk-scripts.js` | builds the exact redeem / unlock scripts the engine expects, via the SDK's native `ScriptBuilder` with `covenantsEnabled` |
| `src/cost.js` | script-unit and mass model transcribed from `tags.rs`, `groth16/mod.rs`, `mass/units.rs`, `mass/mod.rs`, `params.rs` |
| `src/tx.js` | transaction v1 construction with `computeBudget`; plan (budget, masses, min fee) |
| `test/` | 31 `node:test` cases: script shape, cost constants vs the Rust tests, tx v1, mutation vectors |
| `bin/address.mjs` | prints the covenant addresses to fund and the spend plan |
| `bin/live.mjs` | the actual on-chain test: bad proof rejected, good proof accepted |

## Run

### 3. Your own program: the melody covenant

Needs an x86_64 Linux box with Docker (the STARK-to-Groth16 step runs in risc0's docker image)
and the risc0 toolchain at the version the Kaspa SDK pins:

```
curl -L https://risczero.com/install | bash && rzup install        # installs cargo-risczero, r0vm, rust toolchain
rzup install r0vm 3.0.4                                            # must match risc0-zkvm = 3.0.4
cd prover
RISC0_DEV_MODE=1 cargo run --release -- --melody 60,62,64,65,67,69,71,72 --root 0 --mode major   # logic dry run
cargo run --release -- --melody 60,62,64,65,67,69,71,72 --root 0 --mode major --out out       # real Groth16 receipt
cd ..
node bin/r0spend.mjs address --bundle prover/out                   # covenant address for YOUR program
# fund it with ~0.4 KAS, then:
node bin/r0spend.mjs spend --bundle prover/out --to kaspa:q... --url ws://127.0.0.1:17110 --decode
```

`spend` first submits the genuine proof with the journal hash's first byte flipped (a valid proof
for the wrong public input, so the pairing check itself fails: `VerificationFailed`, the other
failure mode from `live.mjs`), then the genuine spend, walking the budget up from 1550 on free
rejections if the SDK's claim-reconstruction script costs more than the raw fixture did.

Try a melody with a wrong note (`--melody 60,61,72`): the guest panics, no receipt, nothing to spend.
Try one that does not end on the tonic (`--melody 60,62,64`): same.

The bundle format (`image_id.hex`, `journal.hex`, `journal_hash.hex`, `receipt.hex`) is the contract
between any prover and `r0spend.mjs`; `fixtures/r0-example/` is the SDK's own receipt in that format,
useful to test the chain side before the Rust side builds.

### 1 and 2. Fixture proof, and measuring the budget

```
npm test                      # 31 tests, offline, < 1 s
node bin/address.mjs          # addresses + budget + fee
```

### Live test on testnet-10

1. Get testnet KAS (faucet or your own TN10 wallet). About 1.5 TKAS covers the Groth16 run.
2. Send it to the Groth16 covenant address printed by `bin/address.mjs`:
   `kaspatest:ppnsz9gete7gqg7lcez3dm4gnk6pusrucpplywwv0sdf4gs44z5pqf9kxarug`
3. Run, with an address of yours as destination:

```
node bin/live.mjs --to kaspatest:qq...            # public resolver
node bin/live.mjs --to kaspatest:qq... --url ws://127.0.0.1:17210   # your node (wRPC Borsh)
```

Expected output, in order:

```
[1/2] submitting spend with corrupted proof byte 0 ...
  rejected as expected:
    ... ZkIntegrity ... (verification failed)
[2/2] submitting spend with the genuine proof ...
  accepted: txid <64 hex>
  confirmed: output now in UTXO set of kaspatest:qq...
```

Both submissions spend the same UTXO. The first one fails script validation at the node's
mempool, so the UTXO is still there for the second. Nothing is signed with a private key at
any point; the signature script is the proof, the public inputs, and the redeem script.

`--fixture succinct` runs the RISC Zero Succinct variant (222 KB signature script, ~0.5 TKAS
min fee, ~90% of a block's transient mass).

## Stack contract (from the engine, v2.0.0)

`OpZkPrecompile` pops a tag byte, then by tag (top of stack first):

```
0x20 Groth16        vk | proof | n_inputs (i64) | input[0] ... input[n-1]        (BN254, arkworks compressed; Fr LE 32 bytes)
0x21 R0 Succinct    hashfn | control_id | image_id | journal | seal | control_digests | control_index | claim
```

P2SH split used here (same as rusty-kaspa's test helpers):

```
Groth16   redeem = push(vk) push(0x20) OpZkPrecompile
          unlock = push(input[n-1]) .. push(input[0]) push_i64(n) push(proof)
Succinct  redeem = push(image_id) push(control_id) push(hashfn) push(0x21) OpZkPrecompile
          unlock = push(claim) push(control_index) push(control_digests) push(seal) push(journal)
```

The redeem script is what the covenant trusts (the program). The unlock is what the spender
supplies (the proof). A proof for a different program is a proof for a different address.

Note: the v2.0.0 SDK's bundled `zkproof/risc0-succinct.js` example pushed the Succinct fields in a
different order than the engine pops them; v2.1.0 replaced those examples. This suite follows the
Rust test helpers that ship in the same commit as the consensus code.

## The 2.1.0 way: `ZkScriptBuilder`

v2.1.0 adds a RISC Zero-aware builder to the SDK, which is the primitive a bridge covenant wants:

```
commitToGroth16(imageId)                           // redeem: RISC Zero's fixed Groth16 VK + in-script claim reconstruction + precompile
finalizeWithGroth16Proof(receipt, journalHash)     // unlock: receipt -> compressed proof push
commitToSuccinct(imageId, controlId, hashFn?)      // redeem for Succinct receipts
finalizeWithSuccinctProof(receipt, journal)        // unlock for Succinct receipts
```

The covenant pins the *program* (image id); the spender supplies the journal and the proof. See
`examples/nodejs/javascript/zkproof/groth16_split.js` in the v2.1.0 SDK zip. This suite uses the
raw `ScriptBuilder` layout on purpose, so the stack contract is visible; for the bridge, use
`ZkScriptBuilder`.

## Numbers that matter (v2.0.0, mainnet and testnet-10 identical)

| | Groth16 (0x20) | RISC Zero Succinct (0x21) |
|---|---|---|
| precompile cost | 140,000 grams + 2,500 grams per public input (+1) | 250,000 grams |
| proof size | 128 B proof + 424 B VK | 222,668 B seal |
| compute budget (fixture, 5% margin) | 1627 | 2625 |
| compute mass of spend | ~164k grams | ~486k grams |
| transient mass of spend | ~3.7k grams | ~893k grams (block limit 1,000,000) |
| min relay fee (100 sompi/gram, on max(compute, transient/2)) | ~0.164 KAS | ~0.49 KAS |
| verifies per block (compute limit 500k) | 3 | 2 |

Budget math: an input with `compute_budget = b` may use `b * 10_000 + 9_999` script units and
costs `b * 100` grams of compute mass. Literal data pushes are free. Post-Toccata limits:
signature script 250,000 B, script element 1,000,000 B, script 1,000,000 B.

Design consequence: Groth16 is the production path. A RISC Zero guest can still be the prover;
wrap its receipt with RISC Zero's Groth16 wrapper and the 5 public inputs land in exactly the
shape of the Groth16 fixture here (control root ×2, claim digest ×2, BN254 control id).

## Known gaps

- The SDK's `calculateTransactionMass()` does not model v1 compute budgets
  (`wallet/core/src/tx/mass.rs`: "TODO: Add support for v1 transactions"). `src/cost.js`
  computes consensus masses instead; the node's actual metering is the final word.
- The compute budget is an estimate with 5% margin over the engine's documented charges.
  If the node answers `ExceededCommittedScriptUnits { used, limit }`, raise `--fee-mult` or the
  margin in `planZkSpend`; `used` tells you the exact number for next time.
- No local script execution: the SDK does not expose the engine. The node is the verifier.
