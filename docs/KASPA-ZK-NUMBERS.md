# Numbers for Kaspa ZK builders

Measured values from building the Kozmic bridge (Kaspero Labs, October 2026), collected here because most of them
are not about the bridge: they are what RISC Zero costs on Kaspa L1, what Kaspa costs inside RISC Zero, what the
Ethereum side charges, and what a rented GPU does with it. Every number was measured on mainnet (Kaspa mainnet,
Ethereum mainnet) with rusty-kaspa / SDK 2.1.0, risc0-zkvm 3.0.4, RTX 4090 and L40S pods on Runpod, unless marked
otherwise. Prices are what we paid in October 2026. The evidence for each row (txids, logs, bundles) is in the
READMEs under `bridge/`, `eth-prover/`, `vault/`, `relay/` and `outbound/`.

## 1. Verifying a RISC Zero Groth16 proof on Kaspa L1 (KIP-16 tag 0x20)

| item | value |
|---|---|
| Compute cost of one Groth16 verify | 140,000 grams + 250,000 script units per `gamma_abc` element; the RISC Zero wrapper has 5 public inputs = 6 elements, so the floor compute budget is **1550 units = 155,000 grams** |
| Block compute limit | 500,000 grams: **3 Groth16 verifies per block**, ~30/s network-wide at 10 bps |
| Compute budget encoding | u16 per input; allowed units = `budget * 10_000 + 9_999`; compute mass += `budget * 100` |
| Fee for a verify spend | min relay fee 100 sompi/gram on `max(compute, storage, transient/2)`: **~0.16 KAS** at 1x for a bare verify; a covenant step with one proof plus state handling ~0.33 KAS |
| Covenant budgets we measured | light-client step 1551; step + 1 deposit 1559; + 2 deposits 1562 (~3 units per extra journal entry); KCC-20 minter input 3 (2 outputs) / 5 (3 outputs); P2PK input in a v1 tx 10; a wallet token transfer 1 -> 2 outputs 12 |
| Under-budget spends | rejected at the mempool for free and the node reports `used=N`. Cheapest way to measure a budget |
| KIP-9 storage mass | an output of plurality 2 (covenant output, 63 + 35 + 32 bytes) holding `v` sompi costs `4e12 / v` grams: 0.2 KAS -> 200k grams. Token UTXOs in our design carry 1 KAS for this reason. **An ordinary output must exceed 0.1 KAS** (0.1 KAS alone hits the 100,000 g standard-tx ceiling) |
| Post-Toccata limits | sig script <= 250,000 B, script element <= 1,000,000 B; literal pushes are free |
| Script sizes (for sizing a design) | bridge redeem 4.2 KB (holds 108 B of state), advance sigscript 4.6 to 4.7 KB, init 6.8 KB (carries a token template), KCC-20 redeem 2.7 KB, token transfer sigscript ~2.8 KB |
| RISC Zero Succinct (tag 0x21) | verifiable, 222 KB per proof, 2 per block. Use Groth16 |
| SDK `calculateTransactionMass()` | ignores v1 compute budgets (TODO in `wallet/core/src/tx/mass.rs`). Compute mass by hand |
| Groth16 constants Kaspa 2.1.0 embeds | risc0 3.0.x: control root `a54dc85a…1f56`, BN254 control id `c07a6514…4404`. A receipt from any other zkVM major does not verify. Pin `risc0-zkvm = "=3.0.4"` |

## 2. Verifying the same proof on Ethereum

| item | value |
|---|---|
| Verifier | RISC Zero's `RiscZeroVerifierRouter` `0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319` on mainnet; the seal is 4 selector bytes + the 256-byte proof; selector `0x73c457ba` = the 3.0 Groth16 verifier (it is the head of the receipt's `verifier_parameters` digest) |
| Gas | **~265k for the verification** (a submit that verifies and writes a candidate: 371,210 gas, of which ~106k is our own parsing and storage); a native Kaspa header check in Solidity, by contrast, 617k gas per header |
| Deploy | a relay contract + an ERC-20 1.79M gas; a vault + test token 807k; at 0.3 gwei base fee all of it was under $2 |
| Same proof, both chains | one Groth16 receipt (695 bytes borsh, 256-byte seal) verifies on Kaspa (OpZkVerify) and on Ethereum (router) with the same image id and journal hash |

## 3. What things cost inside the zkVM (user cycles, risc0 3.0.4)

| program piece | user cycles |
|---|---|
| One Kaspa header, fully verified (blake2b x2 with shared prefix, PoW cSHAKE, matrix, heavy hash, target, level, parent link) | **~555k** marginal on 7.8 KB headers (454k of it blake2b, 92k matrix, 1.3k per keccak permutation with the coprocessor; software keccak +31k); scales with header size: 2.4 to 15 KB -> ~200k to 1M |
| A Kaspa transaction's acceptance via KIP-21 (activity digest, lane tip, SMT proof, state root, seq_commit chain, one blake3 per chain block) plus closed level walks over an hour | **~0.7M** total; a 33-step chain is inside that |
| One Ethereum light-client finality step (helios, mainnet spec, 512-member committee, BLS) | **~53 to 55M** |
| One sync-committee rotation (per 27-hour period crossed) | **+~47M**, linear (measured to 27 rotations) |
| One Ethereum storage proof of a contract slot pair at a finalized block (eth_getProof, account + 2 storage branches) | **+~1M** |
| A one-hour Kaspa work sample by superblock ladder | level 32 only: 125 headers, 75M; levels 30+32: 534 headers, 317M; 28+30+32: 2,216 headers, 1.30B |
| Full-header relays, for comparison | all headers ~11 GPU-hours per chain-hour; chain-only ~1.5 GPU-hours per hour for 13.6% of the work; genesis bootstrap ~500M headers, ~18 GPU-years |
| CPU proving memory | r0vm needed > 6 GB for a 37M-cycle session even at `RISC0_SEGMENT_PO2=18` |

## 4. Proving speed, overhead, price

| item | value |
|---|---|
| RTX 4090 | **1.4 to 2.0 s per million user cycles** (1.62 on the Kaspa relay guest over 304M cycles; 2.0 on the Ethereum guest including upload and download); L40S 1.9 s/M. Small proofs (37M) run at ~1.9 s/M because of fixed costs |
| Groth16 wrap (STARK -> SNARK) | **71 to 73 s on a CPU box**, independent of cycles, with RISC Zero's `risczero/risc0-groth16-prover` Docker image. The CUDA wrap crashed on every pod we tried; wrap on CPU |
| Rented pod overhead (Runpod REST, secure cloud) | create -> SSH **60 to 300 s**, almost all of it pulling the image (depends on whether the host has the layers); billing per second, no minimum |
| Pod price | RTX 4090 $0.89/h, L40S similar |
| Cost per proof | ~55M cycles (an Ethereum step): 3 to 7 min of pod, **$0.05 to $0.11**; 37M (a 5-minute Kaspa ladder): $0.066; 304M (an hour of Kaspa at levels 30+32): 13 min, **under $0.20**; 1.15B (3.4 hours of Kaspa): 31 min of STARK at the same 1.61 s/M, ~$0.50; 336M (a weekly Ethereum heartbeat with 6 rotations): $0.20 to $0.30 |
| An idle bridge | ~$1/month in GPU plus one Kaspa fee per heartbeat |
| Owned hardware | one 4090 does an hourly Kaspa update in ~8 min, so one card keeps up with the chain with margin |
| Reproducible image ids | build the guest in a pinned Docker image (`nvidia/cuda:12.6.3`, rzup rust 1.94.1, r0vm 3.0.4). A native build of the same source on a different toolchain gives a different image id. Never pin a native id |

## 5. Kaspa mainnet facts you can design against (October 2026)

| item | value |
|---|---|
| Block rate | 35,797 blocks per hour measured = 9.94/s; selected chain 14.1% of blocks (1.36/s); 99.94% blue; chain work 13.6% of blue work |
| Hashrate | 352 PH/s (miningboard agreed: 351) |
| Header size | 2.4 to 15 KB, ~7 to 8 KB typical (parents_by_level dominates) |
| Superblocks per hour (blocks whose PoW hash is at level >= L; each one costs 2^(31+L) hashes whatever `bits` says) | L >= 28: ~2,200; L >= 30: ~530; L >= 32: ~125; level parents per block 7.1 (L24), 1.75 (L28), 1.22 (L30), 1.00 (L34); base level today 24 |
| Superblock count as a work estimator | count x 2^(31+L) over actual work = 0.97 to 1.02 for L = 24..34; error 1/sqrt(count) |
| Closure of `parents_by_level[L]` | a closed walk from the sink reaches every level->=L block in the hour, reds included, at every level 24..34 (missed = 0) |
| Consensus params (v2.1.0 source) | max_block_level 225; k 124; finality 432,000 blocks (12 h); merge depth 36,000 (1 h); pruning 1,080,000 (30 h); difficulty window 661 samples 40 blocks apart (~44 min) |
| Cadence at level >= 32 | a level-32 block every ~29 s DAG-wide, but only ~14% of blocks are chain blocks, so a **chain** block at level >= 32 every ~3.5 min; waiting for one after your tx took 2 to 5 min |
| Renting kHeavyHash | NiceHash: $0.2762 per TH/day = ~$11.5 per PH-hour; 33 PH/s listed (< 10% of the network), so matching the network for an hour is ~$4k at list and not available |
| KIP-21 commitments | `accepted_id_merkle_root` is the sequencing commitment: seq_commit(X) = blake3_keyed(seq_commit(sp(X)), state_root(X)); every node serves `getSeqCommitLaneProof`, so transaction inclusion needs no indexer and no GHOSTDAG in the verifier |
| Node RPC load for a witness | a one-hour ladder at levels 28,30,32: ~2,900 wRPC calls, 17 MB of headers; levels 30,32: 4 MB |

## 6. Ethereum facts

| item | value |
|---|---|
| Light-client finality lag | the finalized header trails wall clock by **14 to 30 min** (17 typical), not the nominal 13 |
| Public light-client endpoints that work | `ethereum-beacon-api.publicnode.com`, `lodestar-mainnet.chainsafe.io` (bootstraps 120+ days back, updates 140+ periods back). lightclientdata.org down, nimbus.team gone. Two is thin |
| `eth_getProof` | Alchemy free tier serves it at recent finalized blocks and 7 days back |
| Ethereum -> Kaspa, no human step | deposit block to Kaspa mint **18.5 min** = 13.8 min finality + poll + 4.5 min cycle (pod 164 s, wrap 71 s, Kaspa tx 30 s) |
| Ethereum sends | an RPC can accept a transaction that never enters the mempool (pending nonce == latest minutes later); confirm by nonce, not by the send's return, and retry with an explicit fee |
| Kaspa -> Ethereum | burn to accepted proof on Ethereum **11 min** (5 waiting for a level-32 chain block, 5 of pod, 1 of wrap and submit), then whatever challenge window the contract uses (ours: 1 h; burn to wKAS balance 72 min); gas per cycle ~494k (submit 371k + finalize 123k) |

## 7. Rules of thumb

- Budget a Kaspa verify at 1550 units and 0.16 KAS; three per block is the hard ceiling for everyone combined.
- A Kaspa header is half a million cycles; verifying the chain block by block is dead on arrival (11 GPU-hours per
  chain-hour). Sample work with superblocks: an hour costs 2 to 35 GPU-minutes depending on how tight you want the
  count.
- A GPU-minute is $0.015 rented. Most proofs are dominated by the 1 to 5 minutes of pulling the image, not by proving.
- Pin the toolchain in Docker and publish the image id from that build; nothing else reproduces.
- Measure budgets with under-budget spends; they are free and the node tells you the answer.
