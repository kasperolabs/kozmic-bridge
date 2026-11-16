# Kozmic Bridge

**USDC between Ethereum and Kaspa L1, both ways, checked by proofs instead of people.** A deposit into a
vault on Ethereum becomes the same amount of `kzUSDC` on Kaspa; a burn of `kzUSDC` on Kaspa releases
USDC on Ethereum. In each direction the receiving chain verifies a zero-knowledge proof of what the
other chain did: Kaspa verifies Ethereum's own finality (its sync committee signatures), and Ethereum
verifies Kaspa's proof of work and its blockDAG ordering. No custodian, no multisig, no signers, no
admin key, no pause button. The programs cannot be changed after deployment; a flaw means a new bridge,
never a patch to the old one.

Live on mainnet, both directions, since 2026-11-16 (instance 2). Instance 1 ran the same code with real
USDC from 2026-11-15 as the final rehearsal, settled every transfer, and was closed to deposits on
2026-11-16 (its holders can still exit).

> New and not audited by a paid firm. Move only what you can afford to lose; nobody can reverse a
> transfer, including us. Read [RISKS.md](RISKS.md) before using it. The user guide is
> [docs/GUIDE.md](docs/GUIDE.md), the plain-language terms are [docs/TERMS.md](docs/TERMS.md).

## The live instance

| | |
|---|---|
| token | `kzUSDC` (ticker `KZUSDC`), a KCC-20 token on Kaspa mainnet. Its identity is the covenant family id below, not the name |
| token family (Kaspa) | `cc9957fe0d485f79994ed583aa7e16bacf194d9b9d6d77aeedc129349ddad12c` |
| bridge covenant (Kaspa) | `bf6901190501d55274375960c4f119f6b5e8cbc933192838f4a1ffaed85b7158`, address `kaspa:ppsq6j9qhp3774c9rr4ene82qqzc8v4hec97jz8x2zsfetm465hc2f748x8nw` |
| vault (Ethereum) | [`0x1B9f6750d8b9776Ed9128DC48A7537019ecB2243`](https://etherscan.io/address/0x1B9f6750d8b9776Ed9128DC48A7537019ecB2243) (`UsdcVaultV4.sol`) |
| relay (Ethereum) | [`0xF626DcC984d12445ABdDAADA989855E66d3cDB3A`](https://etherscan.io/address/0xF626DcC984d12445ABdDAADA989855E66d3cDB3A) (`KaspaRelayV5.sol`) |
| factory (Ethereum) | `0x3749f442F27d195f34219E668058E151C29c16E2` (`RelayFactoryV3.sol`), creation tx [`0xe767fe1a…`](https://etherscan.io/tx/0xe767fe1ad0486d1b7f59f03dda0c1eb2b7f28a27074bd7189597260490a4d222), block 26,427,414 |
| inbound guest (Ethereum finality, verified on Kaspa) | image id `c320da505b41ffb3336a5bd4d995ead15590b75f4cb4b1ae3fa25353bacb955c` |
| outbound guest (Kaspa PoW and DAG, verified on Ethereum) | image id `c61fd96588598d7f9b2a16aae765932ea3648177f42ddb167370f18f7d9a97f2` |
| every parameter and transaction | [`usdc/deployments/2-0xF626DcC984d12445ABdDAADA989855E66d3cDB3A.json`](usdc/deployments) |

The parameters you will feel: deposits take about 25 minutes (Ethereum finality plus one proof); an exit
of up to about $1,200 takes about 90 minutes, and larger exits wait in proportion to the amount, because
the proof must carry more of Kaspa's work for them. The vault holds at most a cap that starts small and
doubles on a schedule, and exits are paid at most a fixed amount per proof and per day. The page shows
the live figures, read from the contracts; this README does not repeat numbers that the contracts own.

## How it works

```
 Ethereum                      provers (anyone; Kaspero runs one)                 Kaspa L1
 --------                      ----------------------------------                 --------
 UsdcVaultV4                   in:  prove Ethereum's finalized state            BRIDGE covenant (bridge-v7)
   deposit(amount, kaspa spk)       (sync committee BLS, storage proofs)          verifies the Groth16 proof with
   records (nonce, amount, spk)     -> journal: old header, new header,           OpZkPrecompile, continues from
   no owner, no withdraw               deposits                                   its own header, mints kzUSDC
                                                                                 to the address in the journal
 KaspaRelayV5                  out: prove Kaspa's work after the burn
   submit(seal, journal, rlp)       (headers, PoW, GHOSTDAG ordering,            burn = kzUSDC transfer to the
   verifies the proof via the       the attestation ladder)                       burn owner, payload names the
   RISC Zero router, pays the       -> journal: burn txids, amounts,              Ethereum recipient and a
   recipient from the vault,        recipients, attesting superblocks,           recent Ethereum block as the
   pays the prover the tip          the Ethereum beacon it is bound to           clock
```

**Ethereum to Kaspa.** The vault records the deposit. When Ethereum finalizes the block, a RISC Zero
program ([`eth-prover/`](eth-prover), on RISC Zero's audited r0vm-helios and a16z's Helios) verifies the
sync committee's signatures on the finality update and Merkle-Patricia proofs that the vault's storage
holds the deposit. The Kaspa covenant verifies the Groth16 proof against the pinned image id, checks
that the journal continues from the header and committee it holds, and mints one KCC-20 cell per new
deposit to the address the depositor named. The successor covenant carries the new state.

**Kaspa to Ethereum.** The user burns `kzUSDC`: a KCC-20 transfer to the burn owner, carrying the
Ethereum recipient and a recent Ethereum block hash as a clock. A RISC Zero program
([`outbound/kaspa-prover/`](outbound/kaspa-prover)) verifies the Kaspa headers from the burn's block
forward: proof of work, parent links, GHOSTDAG blue work, and a ladder of "attesting" superblocks (blocks
whose PoW hash clears a much higher difficulty than required; their count measures how much work the
network did after the burn). The relay verifies the proof, checks that enough attesting work has
accumulated for the amount and the time elapsed, and pays the recipient from the vault, less the fee.
The relay's rule is `required = max(FLOOR, time term, amount / ATTEST_UNIT)`; the design and the forger
odds behind FLOOR are in [`docs/V4-DESIGN.md`](docs/V4-DESIGN.md) and the review documents under
`docs/`.

Why nobody can cheat:

- a proof from another program fails: both chains pin the image ids;
- a forged Ethereum history fails: the covenant pins the last header *and* the committee that must sign the next;
- a forged Kaspa history must outwork the real network for the whole attestation window: at FLOOR 600
  a forger with 30% of Kaspa's hashrate has odds of about one in a billion per year of succeeding
  once (`docs/V4-DESIGN.md`, the first-passage tables);
- replays fail (the covenant's header moves; the relay records each burn txid);
- front-running gains nothing: the recipient is inside the proven journal on both sides;
- a malicious prover can at most refuse to work; it holds no keys and no funds.

## What you trust

Ethereum's sync committee (two thirds of 512 validators, the assumption every Ethereum light client
makes); Kaspa's proof of work (a forger needs a majority of the hashrate for hours); RISC Zero's proof
system, its Groth16 trusted setup and its on-chain verifier router; the code in this repository; and
that the image ids pinned on both chains were built from this source, which you can reproduce below.

You do not trust Kaspero Labs, the prover operator, the RPC endpoints a prover reads from, or anyone
holding a key. Circle can freeze the Ethereum vault under USDC's own terms; that is outside this
system and discussed in [RISKS.md](RISKS.md).

## Verify it yourself

**The contracts.** The vault, relay and factory are verified on Etherscan; compare the source with
[`usdc/src/`](usdc/src). `forge test` in `usdc/` runs the unit and fork tests, including the real
RISC Zero router on a mainnet fork.

**The covenant and the token.** [`bridge-v7/`](bridge-v7) compiles the Silverscript covenant and runs
real mainnet proofs through the real rusty-kaspa 2.1.0 script engine (`cargo test --release` there).
Kascov and Studio show the token's KCC-23 declaration and the `BridgeMint` authority; the authority's
artifact hash is reproduced by `bin/minter-artifact.py` from `bridge-v7/BridgeMint.*`.

**The program ids.** The ids pinned on chain come from the Docker builds; reproducing them is the
check no explorer can do for you. Without a GPU, from a clean checkout (x86_64, Docker, under an hour
each):

```
cd eth-prover            && docker build -f docker/Dockerfile.cuda --target ids --output type=local,dest=. . && cat IMAGE_IDS.txt
cd outbound/kaspa-prover && docker build -f docker/Dockerfile.cuda --target ids --output type=local,dest=. . && cat IMAGE_IDS.txt
```

Compare with the two ids in the table above and with `IMAGE_ID()` on the relay and the id in the
covenant's state. The pinned toolchain (risc0-zkvm 3.0.4, whose Groth16 control root Kaspa's SDK 2.1.0
embeds; the guest Rust toolchain; patched accelerated crates) is in the Dockerfiles. A different
toolchain builds a different program with a different id, which the chains reject.

**The journal of any proof.** `eth-prover journal --file <journal.hex>` and
`kaspa-prover journal --file <journal.hex>` decode the frozen layouts (`*/primitives/src/lib.rs`).

## Run a prover, or rescue your own funds

Anyone can prove. The relay pays the proof's tip to the Ethereum address inside the journal, and the
covenant mints for whoever brings a valid proof; neither needs permission. If Kaspero's prover stopped
tomorrow, these two scripts do by hand what it does in a loop, with your own GPU:

- [`bin/prove-exit.sh`](bin/prove-exit.sh): prove one burn and submit it to the relay (Kaspa to Ethereum);
- [`bin/prove-deposit.sh`](bin/prove-deposit.sh): prove a finality update and advance the covenant (Ethereum to Kaspa).

[`docs/SELF-RESCUE.md`](docs/SELF-RESCUE.md) walks through both, what they need, how long they take,
and what the relay's revert reasons mean. The inbound rescue needs the instance's current state file
and light-client store, which are public data and published alongside the instance (the doc says
where).

## Repository

| path | what |
|---|---|
| [`usdc/`](usdc) | `UsdcVaultV4.sol`, `KaspaRelayV5.sol`, `RelayFactoryV3.sol`, the settlement interface, Foundry tests (unit and mainnet fork), storage layouts, and `deployments/` with every instance's parameters and transactions |
| [`eth-prover/`](eth-prover) | the inbound RISC Zero guest (Ethereum finality and vault storage) and its host CLI: fetch, execute, prove, wrap, journal; the Docker build that produces the pinned id |
| [`outbound/kaspa-prover/`](outbound/kaspa-prover) | the outbound guest (Kaspa headers, PoW, GHOSTDAG, attestation ladder, KZO6 journal) and its host CLI; the Docker build |
| [`outbound/burnwitness/`](outbound/burnwitness) | reads a burn and the headers after it from a Kaspa node into the witness the guest consumes; the adversarial suite |
| [`outbound/kpow/`](outbound/kpow), [`outbound/dagwalk/`](outbound/dagwalk) | kHeavyHash and GHOSTDAG measurements and vectors that fixed the guest's design |
| [`bridge-v7/`](bridge-v7) | the Kaspa covenant (Silverscript), the KCC-20 token and `BridgeMint` authority, the Rust tool that builds every Kaspa transaction and runs it through the 2.1.0 engine first; the engine tests |
| [`bin/`](bin) | `bridge-v5.mjs` (the covenant driver: key, genesis, advance, burn, state), the two rescue scripts, `minter-artifact.py` |
| [`vendor/kaspa/`](vendor/kaspa) | the rusty-kaspa WASM SDK 2.1.0, pinned |
| [`docs/`](docs) | `V4-DESIGN.md` and its numbered increments (the design record with every measured number), the external reviews, the Gloas (Glamsterdam) work, the guide, the terms, the USDC blacklist study |
| [`fixtures/`](fixtures) | `FETCH.sh` and the hashes of the large test fixtures, which are release assets rather than tracked files |

Not in this repository: Kaspero's operating stack (the prover and relay robots, the watchdog, the web
page, GPU rental, deployment scripts). None of it is needed to verify the bridge or to rescue funds, and
[`PROVENANCE.md`](PROVENANCE.md) names the private commit this export was cut from. Earlier
generations of the covenant (`bridge` through `bridge-v6`) and the one-way KBT instance of October 2026
are retired and not included; `docs/V4-DESIGN.md` records what each changed.

## Status and record

- 2026-10-12: one-way bridge (Ethereum to Kaspa, test token) live on mainnet.
- 2026-11-02 to 11-14: outbound proof designed, measured and reviewed (`docs/REVIEW-*.md`, `docs/V4-DESIGN-2.*.md`).
- 2026-11-15: instance 1 with real USDC: deposit in 24.5 min, first exit in 71.6 min; a second exit took
  3 h 38 when the GPU provider's API quota ran out (the operating stack now has two providers).
- 2026-11-16: instance 2 (`kzUSDC`, FLOOR 600) deployed after an external review of the attestation
  floor; instance 1 drained and closed (`closeDeposits` tx
  [`0xe821f5c5…`](https://etherscan.io/tx/0xe821f5c59c42a09a7590a883408cb290416413e086ffc844e115dd6a466aad4b)).

Measured numbers live in `docs/V4-DESIGN.md` and are not re-derived here.

## License

[Business Source License 1.1](LICENSE). You may read, build, test, reproduce the ids, prove and settle
against Kaspero's instances (including rescuing your own funds) and deploy to test networks. Deploying
this code, or a derivative, as a bridge on Kaspa or Ethereum mainnet requires a commercial license from
Kaspero Labs until the Change Date (2030-11-16), after which it becomes MIT. The one-way bridge of
October 2026 (this repository's history through `1f18c7e`) was MIT and stays MIT. `eth-prover/` keeps the MIT
notices of r0vm-helios and sp1-helios; `vendor/kaspa` is rusty-kaspa's ISC-licensed SDK.

## Credits

Built by [Kaspero Labs](https://kasperolabs.com) with Claude. Standing on
[RISC Zero](https://github.com/risc0/risc0) and [r0vm-helios](https://github.com/risc0/r0vm-helios),
[Helios](https://github.com/a16z/helios) by a16z, [rusty-kaspa](https://github.com/kaspanet/rusty-kaspa)
and its ZK precompile, and [Silverscript](https://github.com/kaspanet/silverscript). The external
reviews of the design are in `docs/REVIEW-*.md`. Exported from private commit
`e1edd263b0496e6f0f564af344a4dd85bbddb6fc` on 2026-11-16.
