# eth-prover: Ethereum's finality, proven for Kaspa

A RISC Zero program that verifies one step of Ethereum's beacon-chain light client (the sync
committee's BLS signature over a finalized header, plus any committee rotations before it) and
proves deposits of `vault/src/Vault.sol` against the execution state root of the new finalized
block. Its output, the journal, is a fixed-width record the Kaspa covenant slices directly.

Derived from [risc0/r0vm-helios](https://github.com/risc0/r0vm-helios) (MIT, audited by zkSecurity,
April 2025), ported to **risc0-zkvm 3.0.4** (the version whose Groth16 control root the Kaspa SDK 2.1.0
embeds) and **helios 0.12.0** (Fulu and Gloas fork support; the 0.8.3 that r0vm-helios pins cannot
parse post-Fusaka updates). r0vm-helios' Solidity verifier is gone; the Kaspa covenant replaces it.

## What has been measured

All on Ethereum mainnet data unless noted; proving on rented GPUs, wrapping on an x86_64 CPU box.

| what | result |
|---|---|
| guest builds for `riscv32im-risc0-zkvm-elf` with accelerated `bls12_381`, `sha2`, `tiny-keccak` | yes; `risc0-bigint2` resolves to one copy |
| consensus-spec test vector (minimal spec, 32-member committee), offline | 35.4M user cycles; journal matches the vector's expected header |
| one finality step, no rotation, no deposits | 53.3M user cycles |
| one finality step plus one deposit plus one committee rotation | 104.5M user cycles |
| one finality step plus two deposits | 55.2M user cycles |
| 6 rotations (a step 7 days behind) / 27 rotations (30 days behind), dev-mode execute | 335.7M / 1,331.6M user cycles: **~47M per rotation, linear** |
| proving speed, RTX 4090 and L40S | 1.4 to 2.0 s per million user cycles (STARK and recursion) |
| proving on CPU only (12 cores), for reference | 1 h 56 min for the 35.4M-cycle test vector |
| Groth16 wrap on an x86_64 CPU with Docker | 71 to 73 s, independent of cycles |
| image id of the mainnet program, built in the Docker image | **`4756d736d00cc0e5b813fd9bbb8fe586dbfe9cee524e61e79335cc2585413a50`**, pinned by the live covenant |

Every proof that opened the mainnet covenant is kept as a bundle in `out-*/`, with the inputs to
re-prove it: `out-deposit-1`, `out-deposit-12`, `out-heartbeat-1`, `out-deposit-3`. The minimal-spec
test bundles (`out-fixture-gpu`, `out-fixture-step1`) opened the retired test instance.

## Layout

```
eth-prover/
  primitives/      ProofInputs, the Vault storage layout (vault_layout), the journal layout; shared by guest and host
  methods/guest/   the program: src/lib.rs (generic over the consensus spec), two binaries:
                     eth-bridge-guest          mainnet spec (the real one)
                     eth-bridge-guest-minimal  minimal spec (offline test vectors only)
  host/            the eth-prover CLI: fetch | execute | prove | fixture | wrap | journal | ids
  docker/          the CUDA image for GPU machines (Dockerfile.cuda, pod-start.sh)
  out-*/           proof bundles: image_id.hex, journal.hex, journal_hash.hex, receipt.hex, timing.txt, inputs.cbor
```

Guest dependency pins live in `methods/guest/Cargo.toml` (`[patch.crates-io]`) and are locked in
`methods/guest/Cargo.lock`. Do not bump risc0 without checking the control root in the Kaspa SDK
(`crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs`): a different control root and the
covenant rejects every proof.

## The journal (230 bytes + 49 per deposit, big-endian, frozen 2026-10-12)

| offset | len | field |
|---|---|---|
| 0 | 32 | chain_commitment = keccak256(genesis_validators_root ‖ cbor(forks)); the covenant pins this constant (mainnet `0xffc6300b…`) |
| 32 | 32 | prev_header: the finalized beacon header the covenant trusts |
| 64 | 32 | prev_committee: hash of the sync committee the covenant trusts |
| 96 | 32 | new_header: the newly finalized header |
| 128 | 32 | new_committee: sync committee hash after this step (changes at period boundaries) |
| 160 | 8 | new_slot |
| 168 | 32 | exec_state_root at new_header |
| 200 | 8 | exec_block_number |
| 208 | 20 | vault: the Vault.sol address whose deposits follow (all zero when none are proven) |
| 228 | 2 | deposit count n |
| 230 | 49·n | per deposit: nonce (8) ‖ amount (8) ‖ kaspa_spk (33 = version byte ‖ 32-byte payload) |

Deposit nonces are strictly increasing within one journal (the program enforces it), so the covenant
keeps a single "last minted nonce" cursor. The covenant turns `kaspa_spk` into KCC-20 token state,
not a plain output: owner = payload, owner type pubkey (version 0) or script hash (version 8).

Pinning the committee hash, not only the header, is what stops a prover from choosing the committee
that signs the next step (a zkSecurity finding on r0vm-helios). The chain commitment stops a proof
from another chain running the same program from opening the covenant.

## How a deposit is proven

`Vault.sol` stores `deposits[n]` in two words: `k0 = keccak256(abi.encode(uint256(n), 1))` holds
`amount | kaspaVersion << 64`, `k0 + 1` holds the 32-byte Kaspa payload (layout in `vault/README.md`,
asserted by `vault/test/Vault.t.sol`). The host fetches both words with one `eth_getProof` at the
execution block of the new finalized header; the program verifies the account proof against
`exec_state_root`, both storage proofs against the account's storage root, decodes word 0 with
`primitives::vault_layout::decode_word0` (bits above 71 must be zero, amount nonzero, version 0 or 8),
refuses a zero payload, and commits `(nonce, amount, version ‖ payload)`. The layout is compiled into
the program, so the image id pins it.

What the program refuses: an input store carrying `next_sync_committee` or `best_valid_update` (a
rotation must arrive as a signed update); a finality update that does not advance the finalized
header (participation below 2/3, or stale); a storage word claimed as zero; a word 0 that is not a
Vault deposit; nonces that are not strictly increasing.

## Trust assumptions

Ethereum's sync committee (512 validators, 2/3 supermajority) rather than full consensus, as in every
Helios-class light client; RISC Zero's proof system and Groth16 setup; the covenant's pinned image id,
chain commitment and vault address; the Vault.sol code. No signer, no relayer key, no admin. Data
sources (beacon endpoints, execution RPC) are untrusted: everything they serve is checked against
signatures and Merkle roots, so a bad source can stall the bridge but cannot make it accept a false
state.

## Use it

### With Docker (recommended)

The image carries the exact toolchain: risc0 3.0.4, the guest Rust toolchain 1.94.1, the patched
crates, and CUDA kernels for sm_80 to sm_90. A hand install that differs in any of these builds a
different program with a different image id, which the covenant rejects.

```
docker pull kasperolabs/eth-prover:cuda
# or build it: cd eth-prover && docker build -f docker/Dockerfile.cuda -t kasperolabs/eth-prover:cuda .   (x86_64, no GPU needed)

# prove on a GPU machine (NVIDIA driver + nvidia-container-toolkit):
docker run --rm --gpus all -v $PWD/job:/work kasperolabs/eth-prover:cuda \
    eth-prover prove --inputs /work/inputs.cbor --no-wrap --out /work
```

`bin/bridge-prover.mjs` does all of this automatically, on your own GPU (`--gpu local`) or a rented one
(`--gpu runpod`); see the top-level README.

### Native build (fetch, decode, wrap; the image id of a native build differs, never pin it)

```
curl -L https://risczero.com/install | bash
rzup install rust 1.94.1
rzup install r0vm 3.0.4
cd eth-prover && cargo build --release
```

### Commands

```
BEACON=https://ethereum-beacon-api.publicnode.com      # or https://lodestar-mainnet.chainsafe.io

# inputs for one step from a trusted header, with deposits:
./target/release/eth-prover fetch --network mainnet --consensus-rpc $BEACON --checkpoint 0x<trusted header> \
    --execution-rpc $(cat ../eth-rpc-url.txt) --vault 0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529 --nonce N [--nonce M] --out inputs.cbor

RISC0_DEV_MODE=1 ./target/release/eth-prover execute --inputs inputs.cbor     # no proof: cycle count + journal, seconds
./target/release/eth-prover prove --inputs inputs.cbor --no-wrap --out out    # STARK (use the GPU image)
./target/release/eth-prover wrap --receipt out/receipt.succinct.bin --out out # Groth16 wrap, Docker, ~71 s
./target/release/eth-prover journal --file out/journal.hex                    # decode any journal
```

`fetch` runs the program's checks on the host first, so a bad endpoint, a stale update or an
undeposited nonce fails in a second, not after proving. `wrap` verifies the receipt against
`image_id.hex` in `--out` before wrapping. Offline sanity check on the consensus-spec vector:

```
git clone --depth 1 -b 0.12.0 https://github.com/a16z/helios /tmp/helios
RISC0_DEV_MODE=1 ./target/release/eth-prover fixture --dir /tmp/helios/ethereum/consensus-core/testdata/electra/light_client_sync
# expect: user cycles 35391232, new_header 0x811ca9d0...
```

## Data sources (measured 2026-10-13)

- Beacon light-client endpoints: `ethereum-beacon-api.publicnode.com` and
  `lodestar-mainnet.chainsafe.io` both serve finality updates, bootstraps for checkpoints at least 120
  days old, and committee updates at least 140 periods back. Lodestar's `/config/spec` does not parse in
  helios 0.12; `fetch` tolerates that (signatures are checked against mainnet's genesis root anyway).
- Execution RPC for `eth_getProof`: any provider that serves recent state (a free Alchemy key works,
  also 7 days back). Keep the URL in a file, never on the command line.
- The finalized header trails wall-clock time by 14 to 30 minutes. A deposit is provable once its
  block is at or below the finalized execution block.

## Known limits

- **Gloas (Ethereum's Glamsterdam fork).** Gloas light-client headers carry only an execution block
  hash, not the execution payload header, so the state-root path fails there. Sepolia already runs
  Gloas; mainnet is on Fulu. Supporting it needs the execution header as an extra witness
  (`keccak(rlp) == execution_block_hash`, then read `state_root` and `number`), which is a new program
  and therefore a new image id and a new covenant instance.
- **The CUDA Groth16 wrap crashes** ("illegal memory access" in sppark) on the tested GPU boxes, so the
  working flow is STARK on the GPU, wrap on a CPU box with Docker.
- **CPU proving needs memory:** more than 6 GB for a 37M-cycle session even at `RISC0_SEGMENT_PO2=18`.
- The image ids of native builds differ from the Docker build's; only the Docker build's id is pinned.
