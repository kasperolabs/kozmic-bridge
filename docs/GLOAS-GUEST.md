# Gloas-aware inbound guest: plan and record

Started 2026-11-02. Pack: `gloas-pack-v0.1.tgz` + `gloas-apply.py`. Status 2026-11-02: applied and built on the node
box; the Fulu path re-proven on mainnet against the Wobbly.k covenant's own chain commitment; the Gloas path proven
across Sepolia's fork; the witness adversarial suite 8/8 (section 4). Next: the Docker build for the reproducible
image id, then testnet-10 end to end.

## 1. Why

Ethereum's Glamsterdam fork (consensus half: Gloas, EIP-7732 enshrined PBS) removes the execution payload
header from the light-client header. What is left is `execution_block_hash`, which the spec fills with
`signed_execution_payload_bid.message.parent_block_hash`. The pinned inbound guests (`4756d736…`, `c320da50…`)
read the state root from the payload header, so they stop proving deposits at the fork. Exits are unaffected.

Schedule as of 2026-11-02: Sepolia forked 2026-10-06 (epoch 353,024). The Hoodi activation set for 2026-10-26
was postponed on 2026-10-22 (EIP-8037 contract-compatibility review); no new Hoodi date, no mainnet date.

## 2. Design

- **One image for both sides of the fork.** Fulu and earlier headers: unchanged path (the payload header, whose
  branch helios checks against `body_root`). Gloas headers: the execution header arrives as an RLP witness;
  the guest requires `keccak(rlp) == execution_block_hash` (a hash helios has already checked against
  `body_root`) and reads the state root and number by position (fields 3 and 8). Nothing after field 8 is
  interpreted, so the Amsterdam header fields do not change the image.
- **Why the parent payload is safe to prove against.** The bid's `parent_block_hash` is the payload the block
  builds on; the Gloas state transition requires it to equal the state's latest processed payload hash. A
  withheld payload never becomes a parent, so it cannot be proven. Cost: the proven execution block trails the
  finalized beacon block by one slot or more.
- **Journal v2 unchanged byte for byte.** `exec_state_root` and `exec_block_number` come from the witness on Gloas.
  The covenant changes only by its two constants (image id, chain commitment): a new instance, no Silverscript
  change.
- **The chain commitment holds the fork schedule.** `keccak(genesis_root || cbor(forks))`, Gloas epoch included.
  Mainnet's epoch is unknown (helios 0.12 has it as `u64::MAX`), so `fetch --gloas-epoch N` sets it. The image
  does not depend on it; the covenant constant does, and is computed the day the epoch is announced. An instance
  born between the announcement and the fork works on both sides of it.
- **One function, two callers.** `primitives::exec_point` is called by the guest and by the host's dry run, so a
  bad witness fails on the host in a second with the same verdict the guest would give.
- **Witness source.** `debug_getRawHeader`, else a rebuild from `eth_getBlockByHash` in canonical order (known
  through Amsterdam as alloy-consensus 2.5 encodes it; unknown hex fields are tried in every order after the
  known ones). Accepted only if it hashes right; a bad provider stalls, never fools.

## 3. Off-box tests (2026-11-02, scratch workspace, helios 0.12.0, alloy 2.5)

| test | result |
|---|---|
| Ethereum mainnet genesis header RLP (hand-encoded) hashes to `0xd4e56740…cb8fa3`, decodes to state root `0xd7f8974f…0f0544`, number 0 | pass |
| malformed RLP (trailing byte, truncated, not a list, too few fields, bad long-length prefixes) refused | pass |
| non-canonical number (`0x00` for zero) refused, canonical (`0x80`) accepted | pass |
| rebuild from block JSON: genesis; Prague (21 fields, 625 B); Amsterdam (23 fields, 662 B); Amsterdam with the two new fields renamed and reordered (found by the order search); an RPC-style block object | all byte-identical to alloy's encoding |
| `exec_point`: Gloas with a correct witness; missing witness; a byte flipped at 4 positions; another real header; zero hash; junk that hashes right but is not a header; a witness on an Electra header | each accepted or refused as designed |
| `gloas-apply.py` on synthetic anchor files: `--check`, apply, span swap, second run refused as already applied | pass |

Not tested off the box: the host's edited `main.rs` as a whole (the expressions it uses were compiled in the
scratch workspace) and the guest under risc0.

## 4. Box record (to fill)

| step | evidence |
|---|---|
| apply + build + unit tests | 2026-11-02: anchors all matched; build clean; primitives 7/7 (4 U3 + 3 new); host `exec_header_rpc` 1/1. Native image ids (never pinned): mainnet spec `e40db448…a121bd`, minimal `4e9ce007…f0325c`. The guest step 4 line was changed on the box to `panic!("{}", e)`; the image id did not move (the `[lib]` target is edition 2021, so `{e}` was already formatted) |
| mainnet Fulu fetch from the Wobbly.k covenant header, nonce = cursor; chain commitment equals the covenant's `…b0c90b`; journal decodes | 2026-11-02: checkpoint `…f627ce` (slot 15,549,280, period 1898) to `…993b02` (slot 15,566,176), 2 rotations, 510/512. Chain commitment `…b0c90b` = the covenant's. Deposit 14 (1,000,000,000 units, depositor `…229105`, mint) proven at exec block 26,326,734, root `…9fb73a`; `exec point` and the old `exec block` line agree. 149,003,439 user cycles, 3.9 s execute |
| Sepolia fork crossing (period 1378 to now) with the witness; journal's exec block and state root | 2026-11-02: checkpoint `…49c27` (slot 11,296,000) to `…10a654` (slot 11,490,368), 24 rotations (1378..1401), 508/512. Witness rebuilt from `eth_getBlockByHash` (publicnode Sepolia RPC has no `debug_getRawHeader`), 681 B, matched on the known field list. Journal: exec block 12,047,775, root `…c66410`, header hash `…7c8b1c`, chain commitment `…67d95c`. 1,188,860,216 user cycles, 29.7 s execute |
| adversarial_gloas: honest accepted, 6 mutations refused; Fulu honest accepted, witness on Fulu refused | 2026-11-02: 8/8 on the crossing input. Refusals: witness missing ("witness is required"); first, middle, last byte flipped, trailing byte, empty witness ("does not hash"); witness on the Fulu header ("given for a pre-Gloas header"). 217 s |
| cycles: Gloas step vs Fulu step (the witness should add well under 1M) | 2026-11-02 (docs/SEPIA.md): a Sepolia post-fork step without a rotation, from a persisted store (no post-fork bootstraps exist), 687 B witness: 55,924,399 user cycles, 57 segments, 1.6 s execute. A Fulu step without a rotation is not yet measured for the side-by-side |
| end to end on Sepolia (Sepia.k: Sepolia contracts, a Kaspa MAINNET covenant with Sepolia's commitment; replaces the testnet-10 plan, docs/SEPIA.md) | 2026-11-02: deposit 1 (25 Sepia.k, Sepolia block 12,048,505) proven at exec block 12,048,506 from a persisted store, 58,988,321 cycles, GPU STARK + Groth16 wrap with `kasperolabs/eth-prover@sha256:af30a760…` (image `161f4b6c…`) in 271 s; minted on Kaspa mainnet by advance **`678187ba955bbe253c4a2dd08b8742239de40a1c654466b493fd8e0ad40fbc4d`** (node used=15,587,604) |
| Hoodi live crossing | |
| mainnet announcement: spec unchanged since Sepolia, image reproduced on the clean box and pinned, mainnet commitment computed with `--gloas-epoch` | |

## 5. Data sources (measured 2026-11-02)

- `ethereum-sepolia-beacon-api.publicnode.com` runs Lighthouse v8.3.1: bootstraps and pre-fork updates yes,
  nothing after the fork (period 1401 empty, finality and optimistic updates 404).
- `lodestar-sepolia.chainsafe.io` runs Lodestar v1.50.1: Gloas-form headers
  (`beacon`, `execution_block_hash`, `execution_branch`), post-fork updates and finality updates. Bootstraps only
  for some roots (a block four epochs back gave "syncCommitteeWitness not available").
- `ethereum-beacon-api.publicnode.com` (mainnet, first in the service's failover) also runs Lighthouse v8.3.1.
  **Launch gate:** two independent sources that serve Gloas light-client data, checked the week the epoch is
  announced. A missing source stalls the bridge; it cannot make it accept a false state.
- helios 0.12.0 verified 24 committee rotations across Sepolia's fork (periods 1378 to 1401) and a finality update
  at 508/512 participation; no helios bump needed.

## 6. Candidate image

| what | value |
|---|---|
| commit | `7645a72` on branch `gloas-guest` (2026-11-02), parent of the docs commit |
| image id, mainnet spec, Docker build (`--target ids`) | `161f4b6ce70f8ce7b55ca82bff25fc18b447fe8f35b98d2f07e4625b431e5f23` |
| image id, minimal spec, Docker build | `4213368ab3e76c18ea0011c717714c97a53f210a60e9978750b9ec69d8e753aa` |
| status | candidate: pinned by the Sepia.k instance only (Kaspa mainnet covenant `89d8a407…`, Sepolia factory `0x7909…B825`). Pinned for mainnet after the client releases are announced, the Gloas light-client spec is confirmed unchanged since Sepolia, and the clean box reproduces this id from `git archive 7645a72` |
