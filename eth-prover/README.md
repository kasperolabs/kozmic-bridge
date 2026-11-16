# eth-prover: Ethereum's finality, proven for Kaspa

The inbound half of Kozmic Bridge. A RISC Zero program verifies one step of Ethereum's beacon-chain
light client (the sync committee's BLS signature over a finalized header, plus any committee rotations
before it) and proves, against the execution state root of that finalized block, the deposits recorded
in `UsdcVaultV4` and the USDC blacklist status of each depositor. Its output, the journal, is a
fixed-width record the Kaspa covenant (`bridge-v7/bridge.sil`) slices directly and verifies with
`OpZkPrecompile`.

Derived from [risc0/r0vm-helios](https://github.com/risc0/r0vm-helios) (MIT, audited by zkSecurity,
April 2025), ported to **risc0-zkvm 3.0.4** (the version whose Groth16 control root the Kaspa SDK 2.1.0
embeds) and **helios 0.12.0**, with a Gloas (Glamsterdam) witness path of our own. r0vm-helios' Solidity
verifier is gone; the Kaspa covenant replaces it. This directory is MIT (see `LICENSE` here); it was
released under MIT in October 2026 and stays so.

## The live program

The image id pinned by the covenant of the live instance is in
`usdc/deployments/2-0xF626DcC984d12445ABdDAADA989855E66d3cDB3A.json`; it is the id the Docker build below
prints, and `eth-prover ids` prints the id of whatever build you have. A native build's id differs from the
Docker build's; only the Docker build's id is pinned. The digest-pinned image the operator proves with is
named in the top-level README.

Measured on mainnet: a plain step is about 55M user cycles, a step with one committee rotation about 105M,
each further rotation about 47M (so a covenant left for a week costs about 335M). Proving on an RTX 4090 or
L40S runs 1.4 to 2.0 s per million cycles; the Groth16 wrap takes 71 to 73 s on a CPU with Docker,
independent of size. Deposit to mint on the live instance: about 25 minutes, nearly all of it Ethereum
finality.

## Layout

```
eth-prover/
  primitives/      ProofInputs, the vault and token storage layouts, the journal layout; shared by guest and host
  methods/guest/   the program: src/lib.rs (generic over the consensus spec), two binaries:
                     eth-bridge-guest          mainnet spec (the real one)
                     eth-bridge-guest-minimal  minimal spec (offline test vectors only)
  host/            the eth-prover CLI: fetch | execute | prove | fixture | wrap | journal | ids
  docker/          the CUDA image for GPU machines (Dockerfile.cuda, pod-start.sh)
  stores/          (ignored) the persisted light-client store, one file per finalized root; see "Gloas" below
```

Guest dependency pins live in `methods/guest/Cargo.toml` (`[patch.crates-io]`) and are locked in
`methods/guest/Cargo.lock`. Do not bump risc0 without checking the control root in the Kaspa SDK
(`crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs`): a different control root and the
covenant rejects every proof.

## The journal (270 bytes + 50 per deposit, big-endian; v2, frozen 2026-10-16)

The constants are in `primitives/src/lib.rs`, module `journal`; `eth-prover journal --file <journal.hex>`
decodes any journal.

| offset | len | field |
|---|---|---|
| 0 | 32 | chain_commitment = keccak256(genesis_validators_root ‖ cbor(forks)); the covenant pins it, so a proof from another chain running the same program cannot open it |
| 32 | 32 | prev_header: the finalized beacon header the covenant trusts |
| 64 | 32 | prev_committee: hash of the sync committee the covenant trusts |
| 96 | 32 | new_header: the newly finalized header |
| 128 | 32 | new_committee: sync committee hash after this step |
| 160 | 8 | new_slot |
| 168 | 32 | exec_state_root at new_header |
| 200 | 8 | exec_block_number |
| 208 | 20 | vault: the UsdcVault whose deposits follow (zero when none are proven) |
| 228 | 20 | token: the ERC-20 (USDC proxy) whose blacklist was read (zero when none) |
| 248 | 20 | implementation: the token proxy's implementation at exec_state_root (zero when none); the covenant pins it, so an upgrade by Circle stalls the bridge rather than being misread |
| 268 | 2 | deposit count n |
| 270 | 50·n | per deposit: nonce (8) ‖ amount (8) ‖ kaspa_spk (33 = version byte ‖ 32-byte payload) ‖ status (1: 0 mint, 1 skip) |

Deposit nonces are strictly increasing within one journal and the covenant requires each one to be the
next after its cursor, so a prover can neither skip nor repeat a deposit. `status` 1 means the depositor
was blacklisted at `exec_state_root`: the covenant advances its cursor past that deposit without minting.
The covenant turns `kaspa_spk` into KCC-20 token state: owner = payload, owner scheme pubkey (version 0)
or script hash (version 8).

Pinning the committee hash, not only the header, stops a prover from choosing the committee that signs
the next step (a zkSecurity finding on r0vm-helios). Pinning the header stops replays: a journal must start
from the header the covenant holds and must advance it.

## How a deposit is proven

`UsdcVaultV4` stores `deposits[n]` in two words at `k0 = keccak256(abi.encode(uint256(n), 1))`: word 0 is
`amount | kaspaVersion << 64 | depositor << 72`, word 1 is the 32-byte Kaspa payload
(`usdc/LAYOUT-V4.md`). The host fetches both words, the token's implementation slot and one blacklist
word per depositor (`keccak256(abi.encode(depositor, 9))`, FiatTokenV2_2's `balanceAndBlacklistStates`,
bit 255) with `eth_getProof` at the execution block of the new finalized header. The program verifies the
two account proofs against `exec_state_root` and every storage proof against its account's storage root,
decodes word 0 (bits above 231 must be zero, amount nonzero, version 0 or 8, payload nonzero), and commits
`(nonce, amount, version ‖ payload, status)`. The layouts are compiled into the program, so the image id
pins them.

What the program refuses: an input store carrying `next_sync_committee` or `best_valid_update` (a
rotation must arrive as a signed update); a finality update that does not advance the finalized header;
a storage word claimed as zero; a word 0 that is not a vault deposit; nonces that are not strictly
increasing. The blacklist status is the status at the proven finalized state, which is at or after the
deposit; a prover may pick any finalized state between the covenant's header and now.

## Gloas

Since Ethereum's Glamsterdam fork, light-client headers carry only an execution block hash. The guest
takes the execution header as an extra witness, checks `keccak(rlp) == execution_block_hash`, and reads
`state_root` and `number` from it (`host/src/exec_header.rs`, `GLOAS-GUEST.md` in `docs/`). Two
consequences for anyone running this:

- The fork schedule is part of the chain commitment, so `fetch` must be given the Gloas epoch the
  covenant was built with (`--gloas-epoch`, as `eth-net.json` carries it for mainnet).
- No beacon node serves a light-client bootstrap for a post-Gloas header, so `fetch` keeps a persisted
  store (`--store-dir`, one file per finalized root). A file for `--checkpoint` there replaces the
  bootstrap and the store after the step is written for the next one. Losing the store file of the
  covenant's current header means nobody can build the next proof until it is restored; the operator
  publishes it, and `bin/prove-deposit.sh` refuses to start without it.

## Trust assumptions

Ethereum's sync committee (512 validators, 2/3 supermajority) rather than full consensus, as in every
Helios-class light client; RISC Zero's proof system and Groth16 setup; the covenant's pinned image id,
chain commitment, vault, token and implementation; the vault's code. No signer, no relayer key, no admin.
Data sources (beacon endpoints, execution RPC) are untrusted: everything they serve is checked against
signatures and Merkle roots, so a bad source can stall the bridge but cannot make it accept a false state.

## Use it

### With Docker (recommended)

The image carries the exact toolchain: risc0 3.0.4, the guest Rust toolchain, the patched crates, and
CUDA kernels for sm_80 to sm_90. A hand install that differs in any of these builds a different program
with a different image id, which the covenant rejects.

```
cd eth-prover && docker build -f docker/Dockerfile.cuda -t kasperolabs/eth-prover:cuda .   # x86_64, no GPU needed, ~30 min
docker build -f docker/Dockerfile.cuda --target ids --output type=local,dest=. . && cat IMAGE_IDS.txt   # the pinnable id

# prove on a GPU machine (NVIDIA driver + nvidia-container-toolkit):
docker run --rm --gpus all -v $PWD/job:/work <image> eth-prover prove --inputs /work/inputs.cbor --no-wrap --out /work
```

`bin/prove-deposit.sh` at the repository root runs the whole sequence (fetch, execute, prove, wrap,
advance the covenant) on your own GPU.

### Native build (fetch, execute, wrap, decode; never pin its id)

```
curl -L https://risczero.com/install | bash
rzup install rust 1.94.1
rzup install r0vm 3.0.4
cd eth-prover && cargo build --release
```

### Commands

```
BEACON=https://ethereum-beacon-api.publicnode.com      # or https://lodestar-mainnet.chainsafe.io

./target/release/eth-prover fetch --network mainnet --gloas-epoch <from eth-net.json> --store-dir stores/mainnet \
    --consensus-rpc $BEACON --checkpoint 0x<the covenant's header> --execution-rpc "$(cat ../eth-rpc-url.txt)" \
    --vault 0x<vault> --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --nonce N [--nonce M] --out job/inputs.cbor

RISC0_DEV_MODE=1 ./target/release/eth-prover execute --inputs job/inputs.cbor    # no proof: cycles, journal, mint/skip per nonce
./target/release/eth-prover prove --inputs job/inputs.cbor --no-wrap --out job     # STARK (use the GPU image)
./target/release/eth-prover wrap --receipt job/receipt.succinct.bin --out job      # Groth16 wrap, Docker, ~71 s
./target/release/eth-prover journal --file job/journal.hex                         # decode any journal
./target/release/eth-prover ids                                                    # this build's image ids
```

`fetch` runs the program's checks on the host first, so a bad endpoint, a stale update, an undeposited
nonce or a blacklisted depositor is reported in a second, not after proving. `wrap` verifies the receipt
against `image_id.hex` in `--out` before wrapping. Offline sanity check on the consensus-spec vector:

```
git clone --depth 1 -b 0.12.0 https://github.com/a16z/helios /tmp/helios
RISC0_DEV_MODE=1 ./target/release/eth-prover fixture --dir /tmp/helios/ethereum/consensus-core/testdata/electra/light_client_sync
```

## Data sources

- Beacon light-client endpoints: `ethereum-beacon-api.publicnode.com` and `lodestar-mainnet.chainsafe.io`
  serve finality updates and committee updates. Lodestar's `/config/spec` does not parse in helios 0.12;
  `fetch` tolerates that (signatures are checked against mainnet's genesis root anyway).
- Execution RPC for `eth_getProof`: any provider that serves recent state (a free Alchemy key works,
  also 7 days back). Keep the URL in a file and pass it with `"$(cat file)"`; never put the key in a script.
- The finalized header trails wall-clock time by 14 to 30 minutes. A deposit is provable once its block
  is at or below the finalized execution block.

## Known limits

- The CUDA Groth16 wrap crashes ("illegal memory access" in sppark) on the tested GPU boxes, so the
  working flow is STARK on the GPU, wrap on a CPU box with Docker.
- CPU proving needs memory: more than 6 GB for a 37M-cycle session even at `RISC0_SEGMENT_PO2=18`, and
  roughly 50 times the GPU's time.
- The history of this program (the one-way KBT instance of October 2026, journal v1, the measurements
  that sized it) is in this repository's git history before commit `1f18c7e` and in `docs/V4-DESIGN.md`.
