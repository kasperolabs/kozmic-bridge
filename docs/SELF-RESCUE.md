# Self-rescue: proving without Kaspero

The bridge does not need Kaspero to settle. Both chains accept a valid proof from anyone, the relay pays
the proof's tip to whoever's address is in the journal, and the covenant mints for whoever advances it.
This document is for the day Kaspero's provers are down, or for anyone who wants to be a second prover.

Status at export: both scripts were assembled from the exact steps the robots run and the commands are
the robots' commands, but nobody outside Kaspero has run them end to end yet. If you do, open an issue
with what you hit.

## What every rescue needs

- An x86_64 Linux machine with Docker and the NVIDIA Container Toolkit, an NVIDIA GPU with 24 GB
  (RTX 3090/4090, L40S, A100; a 600-attester exit is about 700M cycles, 15 to 25 minutes on a 4090;
  an inbound step is about 60M cycles, 2 minutes). Without a GPU, RISC Zero's CPU prover works and is
  roughly 50 times slower.
- Rust stable with `rzup install rust 1.94.1` and `rzup install r0vm 3.0.4` (risczero.com/install),
  then `cargo build --release` in `outbound/burnwitness`, `outbound/kaspa-prover`, `eth-prover`
  and `bridge-v7`. These host builds read chains, decode journals and build transactions; the proof
  itself comes from the pinned Docker images, so the image id is the right one.
- Node 20 for `bin/bridge-v5.mjs` (`npm ci` at the repository root).
- Foundry's `cast` for the Ethereum side.
- A Kaspa node, rusty-kaspa 2.1.0 or later, with `--utxoindex` and its wRPC Borsh port reachable.
- An Ethereum execution RPC URL in a file (a free Alchemy or Infura key serves `eth_getProof`), and for
  the inbound direction a beacon node with the light-client endpoints
  (`/eth/v1/beacon/light_client/*`; publicnode and Lodestar's public nodes serve them).

Never paste a key or an RPC URL on a command line; the scripts read them from files.

## Kaspa to Ethereum: `bin/prove-exit.sh`

You burned `kzUSDC` (or someone did) and the exit has not been paid. You need the burn's txid and the
hash of a block at or before the block that included it (your wallet or explorer shows the block).

```
KASPA_URL=ws://127.0.0.1:17110 TXID=<burn txid> START=<block hash> \
RELAY=0xF626DcC984d12445ABdDAADA989855E66d3cDB3A TOKEN=cc9957fe0d485f79994ed583aa7e16bacf194d9b9d6d77aeedc129349ddad12c \
PROVER=0x<your Ethereum address> ETH_RPC_FILE=eth-rpc-url.txt ETH_KEY_FILE=eth-key.txt \
bash bin/prove-exit.sh
```

What it does, in order: reads FLOOR, ATTEST_UNIT and the pinned image id from the relay; runs
`burnwitness` to collect the headers and the attestation ladder after the burn; runs `kaspa-prover
relay --native-only` to build the guest input with every intermediate checked against your node; runs
the guest in dev mode for the cycle count and the expected journal; proves on your GPU in the pinned
Docker image; wraps to Groth16 and verifies the bundle; then makes a free `eth_call` of
`submit(seal, journal, headerRlp)` and only on success asks before sending the transaction.

The relay's rule is `required = max(FLOOR, alpha-term(time since the burn's clock), amount/ATTEST_UNIT)`.
The script asks `burnwitness` for FLOOR plus 10 percent. If the free call reverts with
`not enough attestation`, the chain has not done enough work yet or the time term has grown: rerun with
`NEEDED=<larger>`; the message suggests a value. Waiting alone never helps, only a deeper ladder does.

Revert reasons you may see:

| reason | meaning | what to do |
|---|---|---|
| `not enough attestation` | the proof carries fewer attesting superblocks than the rule wants now | rerun with a larger `NEEDED` |
| `already settled` | another prover paid this burn | nothing; check the recipient's balance |
| `history window` or `not Ethereum's block` | the burn's Ethereum clock is older than about 27 hours | a rescue burn is needed, below |
| `no prover` / `not this relay` / `not this token` | wrong RELAY, TOKEN or PROVER | fix the environment |

After a successful `submit`, the recipient has been paid the first installment (less the fee) and your
tip share with it; both continue with each later installment. If an installment was deferred (bucket
empty), anyone can trigger the next one with `cast send <relay> 'claim(bytes32)' 0x<burn txid>`; the
tip of each installment goes to the PROVER address inside the journal, whoever calls.

**Rescue burn.** Every burn's payload names a recent Ethereum block as its clock, and the relay can
only check clocks Ethereum still remembers (EIP-2935, about 27 hours). A burn whose proof did not land
in time cannot be settled alone; it is settled together with a fresh burn (any amount, even the
minimum) made to the same recipient, whose clock is current. `burnwitness --txid <old>,<new>` builds
the combined witness and the rest of the script is unchanged. The robot does this automatically for
burns older than 22 hours; by hand, make the fresh burn from the bridge page or with
`node bin/bridge-v5.mjs burn --help`.

## Ethereum to Kaspa: `bin/prove-deposit.sh`

A deposit has been final on Ethereum for an hour and nothing was minted. You need the vault's deposit
nonces to mint (the page shows them; `cast call <vault> 'nonce()(uint64)'` gives the latest), the
instance's current **state file** and its **light-client store**. You need no KAS and no Kaspa key: the
covenant's own pool pays the advance.

The state file (`bridge-<instance>-state.json`) holds the covenant's current outpoint, Ethereum header,
sync-committee hash and deposit cursor; the store holds the light-client state for that header, one
file per finalized root. Both are public, deterministic data. No beacon node serves a bootstrap for a
post-Gloas header, so without the store file for the covenant's current header the fetch cannot start.
Kaspero will publish both for the live instance next to the bridge page; at the time of this export
that publication is an open item (RISKS.md, item 5) and the files are available on request.

```
ETH_RPC_FILE=eth-rpc-url.txt BEACON=https://ethereum-beacon-api.publicnode.com \
VAULT=0x1B9f6750d8b9776Ed9128DC48A7537019ecB2243 TOKEN=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
STATE=bridge-kzusdc-state.json STORE=eth-prover/stores/mainnet-kzusdc \
KASPA_URL=ws://127.0.0.1:17110 NONCES="14 15" \
bash bin/prove-deposit.sh        # ETH_PROVER_IMAGE defaults to the digest README.md names
```

What it does: reads the covenant's header from the state file and the pinned image id from the
deployment record; `eth-prover fetch` (with the Gloas epoch from `eth-net.json`, which is part of the
chain commitment) pulls the finality updates from the header to the latest finalized one and the storage
proofs of the requested deposits (a blacklisted depositor or a wrong nonce is reported here, before any
proving); dev-mode execute; GPU prove in the pinned image; wrap; then `bridge-v5.mjs advance` builds
the Kaspa transaction, runs it through the real 2.1.0 script engine, and sends it. The network fee and the
KAS parked in each minted cell come out of the covenant's pool, as the covenant's rules allow.

If two provers advance the same covenant from the same state, the second sees `input not found`: the
covenant moved. Refresh the state file (`node bin/bridge-v5.mjs state --help`) and prove again from the
new header, or simply check whether the deposit was minted.

## Costs

An outbound proof at FLOOR 600 is about 700M cycles: 15 to 25 minutes on an RTX 4090, electricity or
about $0.30 of rented GPU, plus the Ethereum submission (about 520,000 gas; $0.15 at 0.2 gwei, $35 at
50 gwei). An inbound step is about 60M cycles, 2 minutes, plus about 0.5 KAS. The relay's tip for an
exit goes to the prover; there is no tip on the inbound side beyond the satisfaction.
