# bridge-v7: the Kaspa side

The Silverscript programs of the live instance and the Rust tool that builds every transaction for them
and runs it through the real rusty-kaspa 2.1.0 script engine before anything is broadcast.

| file | what |
|---|---|
| `bridge.sil` | the BRIDGE covenant: holds the Ethereum light-client state (header, committee hash, deposit cursor), verifies the inbound Groth16 proof with `OpZkPrecompile` against the pinned image id, checks that the journal continues from its own state and names its chain, vault, token and implementation, mints one KCC-20 cell per new deposit (consecutive nonces; a blacklisted deposit advances the cursor without a cell), requires each minted cell to carry at least `cell_value` KAS, and returns the successor with `input - max_fee - (the cells' floors)`. `init` is the genesis: three outputs, the successor, the family's `BridgeMint` authority (which must carry `cell_value`), and the unbound MinerDrip endowment. Permissionless: `advance` takes no signature, so anyone with a valid proof can advance it, and the pool pays the fee |
| `KCC20.sil` | the token cells: the unmodified KCC-20 reference program (argent-lang/kcc20-reference, template `9703112e…`), byte-identical to a Studio-launched token. A burn is a transfer to the burn owner (scheme 3, the hash of `OP_RETURN`), with the `KZB1` payload that names the Ethereum recipient and the beacon |
| `BridgeMint.sil` | the family's mint authority (template `dc96afcd…`): only the covenant's `advance` can mint; the KCC-23 declaration binds it to the token family; `bin/minter-artifact.py` reproduces the artifact hash Kascov verifies |
| `MinerDrip.sil` | the KAS endowment created at genesis that pays scheduled claims (first prize, halving period; helpers in `minerdrip/`) |
| `src/` | the tool: compiles the programs, assembles genesis, `init`, `advance` and burn transactions, computes compute mass by hand (`src/cost.js` at the repository root for the JavaScript side) and runs each transaction through the 2.1.0 engine |
| `tests/engine.rs` | the table of everything the covenant rejects: replay, wrong recipient, altered amount, skipped nonce, a heartbeat that mints, a wrong successor, an authority misuse, under-funded cells. `tipsy.rs` and `settled.rs` are smaller suites |

The crate's name carries its generation: v4 moved the token to KCC-20 Last Call, v5 added the per-deposit
mint maximum and the MinerDrip, v6 made deposit nonces consecutive (review of 2026-11-02, F5), v7 added the
KAS floor per minted cell (read from kUSDT's open code). The header comment of `bridge.sil` is the
changelog. Earlier generations are not in this tree.

Two things a reader should know, both in `RISKS.md`: a permissionless `advance` may pay itself the
difference between `max_fee` and the real network fee out of the covenant's KAS pool (operator money, not
user money; the pool is small and `max_fee` is set tight at genesis); and `init` pins the authority but not
the script of its third output, so a stranger who won the race to `init` at genesis could have redirected
the endowment. The live instance's `init` is on chain and its drip is the intended one.

```
cargo build --release
cargo test --release -- --test-threads=1
```

The tests need the pinned Kaspa SDK in `vendor/kaspa` and the reference fixtures in `tests/fixtures/`.
