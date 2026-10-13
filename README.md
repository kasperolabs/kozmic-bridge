# Kozmic

**Kaspa L1 reads Ethereum.** A covenant on Kaspa holds a light client of Ethereum: it knows,
from a zero-knowledge proof of what Ethereum's own validators finalized, what is true on Ethereum,
and acts on it. The first thing it does with that knowledge is a trustless bridge: tokens
deposited into a contract on Ethereum appear as KCC-20 tokens on Kaspa. No custodian, no multisig,
no relayer with keys, no admin. Live on mainnet since 2026-10-12.

> **Status: Kaspa reads Ethereum; Ethereum cannot read Kaspa yet.** What runs today bridges KBT, a
> self-minted test ERC-20 with no value, from Ethereum to Kaspa. Tokens cannot go back: the
> Ethereum vault has no withdraw function. See [What it does not do (yet)](#what-it-does-not-do-yet).

## What happened on 2026-10-13

At 00:35:23 UTC we deposited 0.5 KBT into the vault on Ethereum, naming a Kaspa address as
the recipient, and then did nothing else. Eighteen and a half minutes later the token was on Kaspa:

| step | when (UTC) | evidence |
|---|---|---|
| deposit #3 into the vault on Ethereum: 0.5 KBT to `kaspa:qpdlx5hl9z6c6twxqwyf8u6yxpg885p8lpa2er363q95m009zl4w629zj9juj` | 00:35:23 | [tx `0x29e6f6a8…`](https://etherscan.io/tx/0x29e6f6a874164b38c556abd32dbcfb3adc262e06238b46bfb8f3ce4107a419b0), block 26,180,018 |
| Ethereum finalizes the block (sync committee signs a finalized beacon header covering it) | ~00:49 | finalized header `0x0d3f1e43…3a2b`, committed in the proof's journal |
| the prover service notices, rents a GPU for 164 s, proves, wraps the proof to Groth16 | 00:49 to 00:53 | bundle [`eth-prover/out-deposit-3/`](eth-prover/out-deposit-3) |
| the Kaspa covenant verifies the proof on chain and mints 0.5 KBT to the named address | 00:53:52 | [Kaspa tx `568bedc5…`](https://explorer.kaspa.org/txs/568bedc542e6ed51ce6ecbbef0968a730d43b049f95150d37960ca7a86f44aaf) |

Total cost of that mint: about $0.05 of rented GPU time and 0.33 KAS in Kaspa fees, plus 1 KAS
that travels with the token output (Kaspa's storage-mass rule). Every other mainnet transaction
of this bridge, including the rejected replays, is listed in [`bridge/README.md`](bridge/README.md#mainnet-record).

## How it works

```
 Ethereum                          prover (anyone can run it)              Kaspa L1
 --------                          -------------------------               --------
 Vault.sol                         1. read the light-client data           BRIDGE covenant
   deposit(amount, kaspa address)     Ethereum's validators signed           state: last trusted Ethereum
   stores (nonce, amount, address) 2. run the RISC Zero program:                    header + its validator set,
   no owner, no withdraw              - verify the validators' signatures         last minted deposit nonce
                                      - verify the deposit is in the       advance(journal, proof):
                                        finalized Ethereum state             - verify the Groth16 proof
                                      - publish a journal: old header,       - journal must start from the
                                        new header, deposits                   state it holds
                                   3. wrap the proof to Groth16            - mint each new deposit to the
                                      (128 bytes)                              address in the journal
                                   4. submit it to Kaspa                   KCC-20 token (KBT on Kaspa)
```

1. **Deposit.** `Vault.sol` takes the ERC-20 and records `(nonce, amount, Kaspa address)` in its
   storage. It has no owner and no other function: whatever enters stays.
2. **Finality.** Ethereum finalizes the block in 13 to 30 minutes. A rotating committee of 512
   validators (the sync committee) signs the finalized header. This is the data Ethereum's own
   light clients use, and it is self-verifying: a forged update fails the signature check.
3. **Proof.** A RISC Zero program (`eth-prover/`, a port of RISC Zero's audited
   [r0vm-helios](https://github.com/risc0/r0vm-helios) on top of a16z's
   [Helios](https://github.com/a16z/helios)) checks the committee's BLS signatures, follows any
   committee rotations, and checks Merkle-Patricia proofs that the vault's storage holds the
   deposit at the finalized state root. Its output, the journal, is 230 bytes plus 49 per deposit.
   The proof is wrapped into a 128-byte Groth16 proof.
4. **Mint.** The Kaspa covenant (`bridge/bridge.sil`, Silverscript) verifies the proof with
   Kaspa's `OpZkPrecompile` against a pinned program id, then checks that the journal continues
   exactly from the header and committee it holds, names Ethereum mainnet and this vault, and
   mints one KCC-20 output per deposit it has not minted before, to exactly the address the
   depositor named. The successor covenant carries the new state.

Why nobody can cheat:

- **A proof from another program** fails: the covenant pins the program's image id
  (`4756d736…`).
- **A proof that skips or invents Ethereum history** fails: the covenant pins the last finalized
  header *and* the hash of the validator committee that must sign the next one, so a prover cannot
  pick its own committee.
- **A replayed proof** fails: its starting header is no longer the covenant's state (tested on
  mainnet, rejected by the node).
- **Front-running** gains nothing: the recipient is part of the proven journal, and the covenant
  enforces it.
- **A double mint** fails: the covenant keeps a deposit cursor; deposits at or below it are skipped.
- **A malicious prover** can at most stall the bridge, never move or create tokens. The prover
  holds no keys.

## What it does not do (yet)

- **No way back.** Redeeming KBT on Kaspa for the ERC-20 on Ethereum needs Ethereum to verify a
  proof of Kaspa's consensus (PoW and GHOSTDAG) that a burn happened. Nobody has built such a proof
  yet; the open questions are written up in [`docs/KASPA-OUTBOUND-STUDY.md`](docs/KASPA-OUTBOUND-STUDY.md).
  The current vault cannot release anything, by design, and never will.
- **Test token only.** The vault accepts KBT, a test ERC-20 with no value. A capped USDC instance
  is planned after the redemption design is settled.
- **No cap on the vault.** Its only limit is that it accepts KBT and nothing else.
- **Wallet display.** The token is Silverscript's covenant-state KCC-20 (`kcc20.sil`). Wallets
  that do not recognize its template (Kasla, today) do not show it, though it exists and is
  spendable.
- **Latency is Ethereum's finality**, 15 to 35 minutes, plus a few minutes of proving. There is no
  fast path, and there will not be one inside the bridge itself.
- **Ethereum's next fork (Glamsterdam, "Gloas")** changes the light-client header format. This
  program reads the execution state root from it and will need a new version, which means a new
  covenant instance.

## What reading Ethereum is good for, even one way

The light client is the product; the token bridge is its first use. Anything provable from
Ethereum's finalized state can become a condition a Kaspa covenant acts on, and none of these need
a way back:

- **Pay on Ethereum, receive on Kaspa.** A vault that forwards each payment to a seller's Ethereum
  address (instead of locking it) and records it; a covenant on Kaspa releases what was bought: a
  token allocation, access, an asset. Checkout in the stablecoin the buyer already holds, delivery
  on Kaspa, no custody anywhere.
- **Migration.** A project moving its token from Ethereum to Kaspa for good wants exactly a one-way
  door.
- **Ethereum facts as Kaspa conditions.** "Release this escrow if that address paid", "settle on that
  on-chain outcome": the same program, different storage slots.

## How this differs from other Kaspa bridges

Bridges make different trade-offs, and saying which one you are is more useful than claiming to be
the best:

| | most bridges today | Kozmic |
|---|---|---|
| who approves a transfer | a committee or multisig signs messages | Kaspa L1 verifies a proof of Ethereum's own consensus |
| what you trust | the signers and their key security | Ethereum's sync committee, RISC Zero, the code here |
| who can pause or change it | the operators | nobody; the covenant is immutable and has no admin |
| where the tokens live | often an L2 or a sidechain | Kaspa L1, as KCC-20 covenant UTXOs |
| assets and directions | many, two-way | one test token, Ethereum to Kaspa only |
| speed | minutes | Ethereum finality plus proving, ~18 minutes |

A committee-secured bridge is faster to extend and can go both ways today; a proof-secured one is
narrower and slower but removes the people in the middle. Both can exist side by side.

## Trust assumptions

You trust: Ethereum's sync committee (two thirds of 512 validators, the same assumption every
Ethereum light client makes); RISC Zero's proof system and its Groth16 trusted setup; the code
of the vault, the program and the covenant, all in this repository; that the program id pinned on
Kaspa (`4756d736…`) was built from this source (reproduce it, below).

You do not trust: us, the prover operator, the beacon or RPC endpoints the prover reads from, or
anyone holding a key. There are no keys.

## Verify it yourself

**On chain.** The Ethereum deposit and vault are on Etherscan. On Kaspa, read transactions from a
node (explorers only partly decode Kaspa's v1 transactions with covenants yet). The bridge is
covenant id `ac21e83194b0beb1ae8c932a4734984f692ab982f6739037af6f979aef0dea0b`, the token is
covenant id `87b503510d715acfa3cca82f245e696593c30d78dde70e11e69afa88b3d03a3f`.

**The proof, locally, without spending anything.** `bridge/` runs the real rusty-kaspa 2.1.0
script engine over the real mainnet proofs: valid spends accepted, replays, wrong recipients,
inflated amounts, foreign programs and flipped journal bytes rejected.

```
cd bridge && cargo test --release -- --test-threads=1
```

**The journal of any proof:**

```
cd eth-prover && cargo build --release
./target/release/eth-prover journal --file out-deposit-3/journal.hex
```

**The program id.** The id pinned on Kaspa comes from the Docker build below. Reproducing it is
the one check no explorer can do for you: build the image, print the id, compare it with
`4756d736…` and with `image_id.hex` in any bundle under `eth-prover/out-*/`.

Without a GPU, from a clean checkout (x86_64, Docker, about 40 minutes from an empty cache):

```
cd eth-prover
docker build -f docker/Dockerfile.cuda --target ids --output type=local,dest=. .
cat IMAGE_IDS.txt   # eth-bridge-guest (mainnet spec) image id: 4756d736d00cc0e5b813fd9bbb8fe586dbfe9cee524e61e79335cc2585413a50
```

Verified 2026-10-13 with a fresh BuildKit builder and no cache. The command also prints the id of a
minimal-spec test program; only the mainnet id above matters for the live covenant.

## Docker: the pinned toolchain

The prover depends on exact versions that must agree with each other and with Kaspa:
`risc0-zkvm 3.0.4` (the version whose Groth16 control root Kaspa's SDK 2.1.0 embeds), the guest
Rust toolchain 1.94.1, patched crates pinned in `Cargo.lock`, and accelerated BLS12-381, SHA-2 and
Keccak forks. Installing this by hand is possible (`eth-prover/README.md`) but easy to get subtly
wrong: a different toolchain builds a different program with a different id, which the covenant
rejects. **Use the image.**

```
docker pull kasperolabs/eth-prover:cuda
```

| | |
|---|---|
| Dockerfile | [`eth-prover/docker/Dockerfile.cuda`](eth-prover/docker/Dockerfile.cuda) |
| build it yourself | `cd eth-prover && docker build -f docker/Dockerfile.cuda -t kasperolabs/eth-prover:cuda .` (x86_64, no GPU needed, ~30 min first build) |
| what it contains | `eth-prover` built with CUDA kernels for sm_80, sm_86, sm_89, sm_90 (A100, RTX 30xx, RTX 40xx / L40S / L4, H100); sshd for rented GPU machines |
| what it is used for | `eth-prover prove --no-wrap` on a GPU: ~2 s per million cycles on an RTX 4090 or L40S; a plain step is ~55M cycles |
| what runs elsewhere | the Groth16 wrap (`eth-prover wrap`, 71 s on CPU) uses RISC Zero's own `risczero/risc0-groth16-prover` image on any x86_64 Docker host |
| image id it produces | `4756d736d00cc0e5b813fd9bbb8fe586dbfe9cee524e61e79335cc2585413a50` |

No GPU of your own? The prover service rents one per proof through the Runpod API and deletes it
when the proof is done: a few cents per proof (`bin/bridge-prover.mjs`).

## Run a prover

Anyone can run one; it holds no keys and cannot mint anything a valid proof does not carry. Every
60 seconds it reads Ethereum's latest finalized header and the vault's deposit counter. When a new
deposit is final, it proves and submits; when nothing happens for a week, it submits a heartbeat so
the covenant keeps up with Ethereum's validator rotations.

### What every prover needs

- An x86_64 Linux machine with Docker and Node 20. It wraps proofs to Groth16 on the CPU (71 s,
  RISC Zero's `risczero/risc0-groth16-prover` image, pulled automatically).
- This repository, with `eth-prover` and `bridge` built (`cargo build --release` in each; Rust
  stable, plus `rzup install rust 1.94.1` and `rzup install r0vm 3.0.4` from
  [risczero.com/install](https://risczero.com/install)). These host builds fetch data, decode
  journals and build Kaspa transactions; the proof itself always comes from the Docker image.
- A Kaspa node (rusty-kaspa 2.1.0 or later, Toccata active) with its wRPC Borsh port open to the
  prover and `--utxoindex`.
- An Ethereum execution RPC that serves `eth_getProof`. A free Alchemy or Infura key works. Put the
  full URL in `eth-rpc-url.txt` in the repository root (`chmod 600`; it is git-ignored and the
  service redacts it from its logs). No Ethereum node: beacon data comes from public light-client
  endpoints and is verified by signature.
- The bridge state file, `bridge-cp6-state.json`, in the repository root. For the live mainnet
  instance, copy [`deployments/kaspa-mainnet-bridge-ac21e831.json`](deployments) and make sure it
  matches the covenant's current state on chain (two provers advancing one covenant from stale
  state files will see each other's transactions as "input not found").
- A GPU, in one of the two modes below.

### Mode 1: your own NVIDIA GPU (`--gpu local`)

Needs the NVIDIA driver and the [NVIDIA Container
Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html),
so that this works:

```
docker run --rm --gpus all kasperolabs/eth-prover:cuda nvidia-smi
```

Supported cards: RTX 30xx, RTX 40xx, A100, L40S, L4, H100 and similar (sm_80 and newer), 24 GB of
VRAM recommended. Then:

```
pm2 start "node bin/bridge-prover.mjs --url ws://127.0.0.1:17110 --gpu local" --name bridge-prover
```

Cost: electricity. A plain proof is about 2 minutes on an RTX 4090; a weekly heartbeat about 11.
This mode runs the same image and command as the pods, but has not yet driven a mainnet advance
itself; every mainnet proof so far came from Mode 2.

### Mode 2: rented GPU per proof (`--gpu runpod`, the default)

For a machine without a GPU. The service creates a GPU pod on [Runpod](https://www.runpod.io)
through its REST API, proves, copies the result back over SSH and deletes the pod, every time.
One-time setup:

1. Create a Runpod account and add a **small prepaid balance** ($10 is months of proofs). Leave
   automatic top-up off: the balance is your hard spending cap.
2. In the console, open **Settings, API Keys** ([console.runpod.io/user/credentials](https://console.runpod.io/user/credentials)),
   click **Create API Key**, permission **All**, and copy the key (it is shown once).
3. On the prover machine, save it without leaving it in your shell history:
   ```
   read -rs RP && printf '%s' "$RP" > runpod-api-key.txt && chmod 600 runpod-api-key.txt && unset RP
   curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $(cat runpod-api-key.txt)" https://rest.runpod.io/v1/pods   # 200
   ```
4. Make sure the machine has an SSH key (`ls ~/.ssh/id_ed25519.pub || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519`).
   The service hands its public half to each pod at creation; nothing to configure in Runpod.

Then:

```
pm2 start "node bin/bridge-prover.mjs --url ws://127.0.0.1:17110" --name bridge-prover --kill-timeout 20000
```

Measured on mainnet: pod ready in 1 to 5 minutes (image pull), proof in about 2, pod deleted
right after; $0.05 to $0.11 per proof, about $0.25 for a weekly heartbeat. Pods are named
`bridge-prover-*`; any such pod still alive between proofs is deleted on the next tick.

### Try it without spending anything

```
node bin/bridge-prover.mjs --once --dry-run --force heartbeat
```

Fetches the light-client data from the covenant's current header, runs the program in dev mode,
checks the journal continues from the covenant's state, and prints the cycle count. No GPU, no
transaction. Log events and costs: [`bridge/README.md`](bridge/README.md#the-prover-service).

## Numbers

| | |
|---|---|
| deposit to mint | 18.5 min measured (13.8 min Ethereum finality, 4.5 min proving and submitting) |
| proof size on Kaspa | 128-byte Groth16 proof, journal 230 + 49 bytes per deposit |
| Kaspa compute budget | 1553 heartbeat, 1559 one deposit, 1562 two deposits (about 3 per extra deposit) |
| Kaspa fee per mint | ~0.33 KAS, plus 1 KAS carried by each minted token output |
| GPU per proof | $0.05 to $0.11 rented; a weekly heartbeat ~$0.25 |
| throughput | up to 4 deposits per proof, one proof per Ethereum finality update |

## Where the bridge actually is

Most of this repository is plumbing: fetching data, building transactions, running a GPU, keeping
logs. The bridge itself is three files, about 450 lines together. Read these first.

**1. [`eth-prover/methods/guest/src/lib.rs`](eth-prover/methods/guest/src/lib.rs): the proven
program (~190 lines).** It runs inside the zkVM; its hash is the image id the covenant trusts.
`run()` reads top to bottom:
- the two `assert!`s at the top: the prover may not supply its own validator committee
- steps 1 and 2: verify the sync committee's BLS signatures on any committee rotations and on the
  finality update (Helios does the cryptography)
- step 3, `assert_ne!(new_header, prev_header, "no progress")`: this one line makes every proof
  single-use
- step 5 and `verify_vault_deposits()`: Merkle-Patricia proofs that the vault's storage holds each
  deposit at the finalized state root
- `env::commit_slice(&journal.encode())`: the only output

**2. [`bridge/bridge.sil`](bridge/bridge.sil): the covenant on Kaspa (~200 lines).** The `advance`
function is the bridge rule:
- `r0.g16.verify(sha256(journal), proof, image_id)`: this journal came from that program
- the four `require`s after it: Ethereum mainnet, continues from my header, signed by my committee,
  about my vault
- the `for` loop: one token output per deposit beyond the cursor, to exactly the address in the
  journal
- `if (mints == 0)`: a heartbeat leaves the token untouched
- `keepValue()`: one spend can never drain the covenant
- `return(State {...})`: the successor carries the new header, committee and cursor

**3. [`vault/src/Vault.sol`](vault/src/Vault.sol): the deposit side (~70 lines).** One function,
`deposit()`. No other function exists, which is the point.

The glue between them: the journal layout in
[`eth-prover/primitives/src/lib.rs`](eth-prover/primitives/src/lib.rs) (230 bytes plus 49 per
deposit; the guest writes it, the covenant slices it), and the vault's storage layout (documented
in `Vault.sol`, hardcoded in the guest, so the image id pins it).

Everything else, by role:
- `eth-prover/host/` (~750 lines): fetches beacon data and storage proofs, runs or proves the guest,
  wraps the proof to Groth16. A CLI around file 1.
- `bridge/src/` (~800 lines): compiles file 2, assembles complete Kaspa transactions and runs them
  through the real rusty-kaspa 2.1.0 script engine before anything is sent; `bridge/tests/engine.rs`
  is the table of everything the covenant rejects.
- `bin/bridge.mjs` (~400 lines): talks to the Kaspa node, computes fees, keeps the state file.
- `bin/bridge-prover.mjs` (~350 lines): the operator. Decides mint or heartbeat, chains the tools
  above, rents or uses a GPU. Choose your GPU mode with `--gpu`; the branch is in `cycle()`, step 3.

The service is operations, not the bridge: the first mint on mainnet was done by hand, command by
command. If every prover stopped tomorrow, the covenant would sit unchanged until anyone ran one
again.

## Repository

| path | what |
|---|---|
| [`eth-prover/`](eth-prover) | the RISC Zero program (guest) and its host CLI: fetch, prove, wrap, decode; the Docker image |
| [`bridge/`](bridge) | the Kaspa covenant (`bridge.sil`), the KCC-20 token (`kcc20.sil`), the Rust tool that builds every transaction and runs it through the 2.1.0 engine, the mainnet record |
| [`vault/`](vault) | `Vault.sol` and the test token, Foundry project, storage layout |
| [`bin/`](bin) | `bridge-prover.mjs` (the prover service), `bridge.mjs` (deploy, advance, transfer), helpers |
| [`deployments/`](deployments) | the mainnet instances: covenant ids, parameters, every transaction |
| `eth-prover/out-*/` | proof bundles of every mainnet advance, with the inputs to re-prove them |
| [`docs/`](docs) | research on the way back: what Ethereum would need to verify about Kaspa ([`KASPA-OUTBOUND-STUDY.md`](docs/KASPA-OUTBOUND-STUDY.md)) |
| `src/`, `test/`, `fixtures/`, `prover/`, `vendor/` | the Kaspa ZK precompile tests this project grew out of, a toy RISC Zero program, the Kaspa WASM SDK 2.1.0 |

## Roadmap

1. **USDC instance**: a new capped vault and a new covenant whose token has a burn entry from day
   one, so that burns are recorded on Kaspa in a form a future Ethereum-side proof can read.
2. **Redemption**: a proof of Kaspa consensus verifiable on Ethereum. Research first: what must be
   proven, at what cost, at what depth.
3. **Gloas support** before Ethereum's Glamsterdam fork reaches mainnet.

## License

MIT, see [`LICENSE`](LICENSE). `eth-prover/` derives from RISC Zero's r0vm-helios and Succinct's
sp1-helios, both MIT; their notices are kept in [`eth-prover/LICENSE`](eth-prover/LICENSE).

## Credits

Built by [Kaspero Labs](https://github.com/kasperolabs) with Claude. Standing on:
[RISC Zero](https://github.com/risc0/risc0) and [r0vm-helios](https://github.com/risc0/r0vm-helios)
(audited by zkSecurity), [Helios](https://github.com/a16z/helios) by a16z,
[rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) and its ZK precompile (Toccata),
[Silverscript](https://github.com/kaspanet/silverscript).
