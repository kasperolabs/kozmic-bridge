# BRIDGE covenant (CP-4 to CP-7)

A Silverscript covenant that holds an Ethereum light-client state on Kaspa L1, advances it only
on a RISC Zero Groth16 proof (tag 0x20) from the pinned guest program, and mints a KCC-20 token
for every Vault.sol deposit the proof carries. Sources: `bridge.sil` (the bridge) and `kcc20.sil`
(the token, a verbatim copy of silverscript's `tests/examples/kcc20.sil` at the pinned rev).
Driver: `../bin/bridge.mjs`. Prover service: `../bin/bridge-prover.mjs` (CP-7, runs the whole loop
with no human step). This crate compiles both contracts, assembles the complete init / mint /
transfer transactions and runs every input through the rusty-kaspa 2.1.0 script engine before the
driver submits anything.

## Verifier: native builtin, which is the SDK fragment

Silverscript (kaspanet/silverscript @ `a0dd7448`, the commit that moved to rusty-kaspa 2.1.0
crates) has `r0.g16.verify(journal_hash, proof, image_id)`. Its lowering calls
`kaspa_txscript_zk_sdk::append_r0_groth16_verifier_dynamic_image_id` from SDK 2.1.0 directly,
and the lock pins `risc0-zkvm 3.0.4`: the compiler emits the SDK fragment (pinned VK, claim
reconstruction assuming Halted(0), 5 public inputs, tag 0x20). The contract computes
`sha256(journal)` itself, so every field it reads afterwards is a byte the guest committed.

## The token: KCC20 state, not an output script

In `kcc20.sil` a token UTXO is a P2SH covenant output whose *state* is
`{ownerIdentifier: byte[32], identifierType: byte, amount: int, isMinter: bool}`. Ownership modes:
`0x00` pubkey (spent with a Schnorr signature over the 32-byte x-only key), `0x01` script hash
(spent by including an input whose spk is that P2SH), `0x02` covenant id (spent by including an
input of that covenant). A non-minter branch must conserve `amount` across a transfer and cannot
create minter branches; a minter branch may change supply. The template (the redeem script minus
the state) is shared by every UTXO of a token; the covenant id (KIP-20, fixed at genesis)
distinguishes tokens. Template parameters here: `maxCovIns 4`, `maxCovOuts 5`; template hash
`b5323a04194ba2343adf8fc08da9cfe746aa2a4baef74b1a18ee518b508b45cf`, 2616 bytes. Decimals: 6,
the vault's uint64 amounts are the token amounts unchanged.

So the recipient named on Ethereum (`kaspa_spk` = version byte + 32-byte payload) becomes the
token state `{owner: payload, type: version 0 -> 0x00 / version 8 -> 0x01, amount, isMinter: false}`.
The P2PK key a depositor named spends it with the same key Kaspa P2PK uses.

Wallet support: this is silverscript's covenant-state KCC-20, not the token format Kasla displays
today (checked 2026-10-13). The UTXOs exist and are spendable (`bridge.mjs transfer`); wallets need
to recognize template `b5323a04…` and decode its state to show them.

The token's only minter branch is owned by the bridge's covenant id. kcc20.sil lets it create
supply whenever a bridge input is in the same transaction; the bridge input dictates the exact
set of token outputs.

## What the bridge contract enforces

State: `header`, `committee`, `cursor` (last minted Vault nonce), `token` (KCC20 covenant id,
zero until init). Constructor constants: `image_id`, `chain_commitment`, `vault` (20 bytes),
`max_fee`, and the token template (`token_prefix_len`, `token_suffix_len`, `token_template_hash`).
Two entries, both `#[covenant.singleton(mode = transition)]` (auth binding, exactly one successor
of the same template and covenant id, no termination):

`init(token_prefix, token_suffix)`, once, no proof:
1. `state.token == 0`; the tx has exactly two outputs; ours is output 0
2. output 1 is bound to a covenant id that is not zero and that **no input carries**
   (`OpCovInputCount == 0`), so by KIP-20 it is a fresh genesis whose group is exactly this output;
   nobody can add a second minter branch of the same token, now or later
3. output 1's script is the KCC20 template with state `{owner: this covenant id, 0x02, 0, true}`
   (`validateOutputStateWithTemplate` against the pinned template hash)
4. successor value >= input value - `max_fee`; successor state = same, `token` = that id

`advance(journal, proof)`:
1. `journal.length >= 230`, `r0.g16.verify(sha256(journal), proof, image_id)`
2. `journal[0..32] == chain_commitment`, `[32..64] == state.header`, `[64..96] == state.committee`,
   `[208..228] == vault`
3. `n = journal[228..230]` (big-endian), `journal.length == 230 + 49n`, `n <= 4`
4. for each deposit `i` (nonce, amount, version, payload at `230 + 49i`, big-endian u64s read by
   byte reversal): if `nonce > state.cursor`: nonce strictly increasing, amount > 0, version 0 or 8,
   and the `(1 + k)`-th token output (`OpCovOutputIdx(token, 1 + k)`) is the KCC20 template with
   state `{payload, type, amount, false}` (`validateOutputStateWithInputTemplate`, template bytes
   taken from the token input and checked against the pinned hash); `k` counts the mints
5. if no mints (heartbeat): no token input and no token output in the tx at all
   (the minter branch can neither be burned nor moved under cover of an advance)
6. else: exactly one token input, exactly `1 + mints` token outputs, and token output 0 is the
   continuing minter branch `{this covenant id, 0x02, 0, true}`
7. successor value >= input value - `max_fee` (fee and the KAS the token outputs carry both come
   out of this allowance)
8. successor state = `(journal[96..128], journal[128..160], last minted nonce, token)`

Deposits at or below the cursor are skipped, never minted twice; the light-client step still
applies. Replay of a whole proof fails earlier, on `prev_header`. No key, no admin path.

**Heartbeats must carry a deposit.** Rule 2 checks the vault field on every advance, and a journal
with no deposits has an all-zero vault field, so it can never open the covenant. A heartbeat
re-proves the deposit at the cursor (`eth-prover fetch --nonce <cursor>`): it is skipped by rule 4
and the advance takes the heartbeat path of rule 5. A new instance cannot heartbeat before its
first mint.

### KIP-9 note

Covenant outputs are 63 + 35 + 32 bytes, plurality 2, so a token UTXO holding `v` sompi costs
`4e12 / v` grams of storage mass when created. Token UTXOs here carry 1 KAS (`--token-kas`),
paid by the bridge; a wallet transfer that splits one into two costs about 0.16 KAS at the
minimum fee rate for the same reason. The driver's fee is `max(compute, storage, transient/2)`.

## Local evidence (rusty-kaspa 2.1.0 engine, real proofs)

`cargo test --release -- --nocapture --test-threads=1` (tests/engine.rs), with
`eth-prover/out-deposit-1` (mainnet-spec image `4756d736…`, journal 279 bytes, deposit #1) and
`eth-prover/out-fixture-gpu` (minimal-spec image, 210-byte journal):

| test | result |
|---|---|
| init from genesis state | accepted, 55,812 units (budget 5); token id = KIP-20 genesis id of output 1 |
| init with two minter branches in the group / foreign owner / bound to an existing token | rejected |
| mint of deposit #1 (bridge + minter-branch inputs; successor, minter, recipient outputs) | accepted: bridge input 15,592,137 units (budget 1559), token input 29,219 (budget 2); cursor 0 -> 1 |
| recipient with other owner / script-hash type / double amount / isMinter | rejected by the bridge input |
| no minter continuation, extra token output, minter handed over, mint skipped | rejected |
| same proof against cursor 1 (heartbeat shape) | accepted, 15,534,722 units (budget 1553), no mint; the mint shape against cursor 1 rejected |
| replay after the mint (state = journal's new pair) | rejected |
| successor with wrong header / committee / cursor 0 / cursor 2 / token / unchanged | rejected |
| 9 flipped journal bytes incl. inside the deposit | rejected (`Groth16 verification failed`); flips that break the layout are not even buildable |
| other chain commitment / vault / image; the fixture proof | rejected |
| drain of exactly max_fee accepted, max_fee + 1 rejected | as stated |
| minter branch spent without a bridge input | rejected (kcc20 rule) |
| wallet transfer of a pubkey-owned UTXO into two | accepted, 129,572 units (budget 12), sigscript 2826 bytes; wrong key / inflation / self-promotion to minter rejected |

Sizes: bridge redeem 4216 bytes (state at bytes 1..108), advance sigscript 4636 bytes (1 deposit),
init sigscript 6844 bytes (carries the token template), token redeem 2662 bytes.

## Mainnet record

### CP-4/CP-5 test instance (consensus-spec chain)

Covenant id `4e97879a4fe9fee3814ccd1576ef9743fa511a42abd6eff4580abd66140c42a7`, pinned to the
minimal-spec guest `d7c73376…` and the test chain's commitment `aa4a6036…`. Its state file is
`bridge-state.json`; it is left as the CP-4/5 record. Retired: it does not reflect Ethereum mainnet.

| what | txid / result |
|---|---|
| genesis, 1.5 KAS | `9bece8dffc7066cc969eebfeebd0bfb66ea8babaf8a22d40e599560e811ea5b6` |
| transition 1, fixture step 0, budget 1551 (node used=15,510,880 at 1550) | `0fda7120a9fba8565edc5741da59d526e5d2aced9271ae17b49485e2ddbca26d` |
| replay of step 0 after transition 1 | rejected: `script ran, but verification failed` (`9a15bcec…`) |
| transition 2, fixture step 1 (sync-committee rotation), budget 1551 | `d5fd63b5933952fd2ffd629d7806a4ac659bb03328e117d8c94ae8df52f8ca52` |
| replay of step 0 after transition 2 | rejected (`f81cfb8d…`) |

### CP-6 production instance (Ethereum mainnet, KBT)

Deployed 2026-10-12, 20:52 to 20:58 UTC, from the state fetched at the old checkpoint_out
`0xa63ca480…` (slot 15,417,408, period 1882) and a fresh proof carrying deposits #1 and #2
(`eth-prover/out-deposit-12/`: 55,191,707 user cycles, 56 segments, 208.3 s STARK on a rented RTX 4090,
71.1 s wrap, journal 328 bytes, hash `777a6894…04bb`, receipt 745 bytes borsh, image `4756d736…`).

| item | value |
|---|---|
| bridge covenant id | `ac21e83194b0beb1ae8c932a4734984f692ab982f6739037af6f979aef0dea0b` |
| constructor | image `4756d736…`, chain commitment `0xffc6300b…`, vault `0x3DD8Cd71…`, max_fee 5 KAS, token template `b5323a04…` (1 + 2615 B) |
| genesis state | header `0xa63ca480…8e72`, committee `0xc68d24d7…8e72`, cursor 0, token 0 |
| KCC-20 token covenant id (KBT on Kaspa, 6 decimals) | `87b503510d715acfa3cca82f245e696593c30d78dde70e11e69afa88b3d03a3f` |
| minter branch (owner = bridge covenant id, type 0x02, amount 0, isMinter) | first at `kaspa:ppfk57wxszm8p98nxwh6altu9assmdj6geslruvazy0lsww04d8wcvz0ye432`, 1 KAS; moves with every mint (output 1 of the mint tx) |

| what | txid / result |
|---|---|
| genesis, 20 KAS at `kaspa:prc7qzgt7zr5qrjj20yjfnu7hcyhj99aw2kxsfsgtv356medzjdnxrs840rv3` (address reproduced on the node box and in the build sandbox), budget 10 | `6f98c736fbc661a5affbda8cf86d27760f0c4e9bfdfad55a8a897ebf220be080` |
| init: KCC-20 genesis as output 1 (the token id above, KIP-20 id confirmed by the node), state.token set. Node used=55,663 at budget 4 (local engine 55,812), accepted at **budget 5**; storage mass 40,114 g, fee 0.0802 KAS at 2x | `004a4d280e5fc64b2072d0408df7c78df61c5ca01cbfd33ffc413f28bb8e8ad9` |
| advance with out-deposit-12: `0xa63ca480… -> 0x6dc6c279…` (slot 15,417,696, exec block 26,178,742), **mints #1 and #2 in one tx**, cursor 0 -> 2. 2 inputs (bridge, minter branch), 4 outputs (successor 16.587 KAS, minter branch 1 KAS, 1 KBT -> `kaspa:qzzkh3…`, 2.5 KBT -> `kaspa:qpdlx5…`). Node used=15,627,605 at budget 1561 (local 15,627,754), accepted at **budget 1562**; token input budget 5 (local 40,709 units); mass 166,284 g (storage 114,379), fee 0.3326 KAS at 2x | `e108d4161c14883e05940c933b616acbc119a0163e2380e16ef9782481d00f99` |
| replay of the same bundle after the advance (state header `0x6dc6c279…`, cursor 2) | rejected: `script ran, but verification failed` (tx `f6d8f759…`, never accepted) |
| wallet-side transfer: the 1 KBT UTXO `e108d416…:2` (owner = the genesis key) -> 0.4 KBT to `kaspa:qpdlx5…` + 0.6 KBT change, signed with that key, budget 12 (node used=121,428; local 129,572), 1x fee: storage mass 147,730 g, fee 0.1477 KAS, each token output 0.426 KAS | `6cf4a2afa5e732473d532cf6d34ec22f5e9f991d4344ad4c5810bc722debdf33` |

### CP-7: the prover service on the same instance (no human step)

`bin/bridge-prover.mjs` under pm2 on the node box: polls the light-client finality update
(publicnode, then Lodestar) and the vault nonce at its execution block, and when a deposit is
provable (or a weekly heartbeat is due) fetches from the covenant's header, runs a dev-mode
preflight, rents a Runpod GPU pod through the REST API, proves, deletes the pod, wraps on the node
box and calls `bridge.mjs advance`. It holds no Kaspa or Ethereum key.

| what | txid / result |
|---|---|
| first automated advance, 2026-10-13 00:24 to 00:33 UTC (`--once --force heartbeat`): re-proves deposit #2, mints nothing. `0x6dc6c279… -> 0x63d72f9f…` (slot 15,418,848), no rotation, 57.9M cycles. Pod RTX 4090: IP 301 s, prove 117 s, deleted at 427 s ($0.106); wrap 73 s; advance 30 s. **Node budget 1553** (= local), fee 0.321 KAS at 2x | `e7fc633a760c9f7731dec8dd799f772bb046e7aede858b6c81fdb80e93fcd5e1` |
| **deposit #3 bridged with no human step.** Ethereum: 0.5 KBT to `kaspa:qpdlx5…`, tx `0x29e6f6a874164b38c556abd32dbcfb3adc262e06238b46bfb8f3ce4107a419b0`, block 26,180,018, 00:35:23 UTC, made with the service running and nothing else done. The service started at 00:49:24 on the first finality update covering it (exec block 26,180,019, lag 13.8 min): 54.9M cycles, no rotation; GPU fallback L40S ($1.09/h): IP 58 s, prove 103 s, deleted at 164 s ($0.050); wrap 71 s; advance 30 s; cycle 268 s. `0x63d72f9f… -> 0x0d3f1e43…`, cursor 2 -> 3. **Node budgets 1559 (bridge, 1 deposit) and 3 (minter branch, 2 token outputs)**; fee 0.3305 KAS at 2x plus 1 KAS into the token UTXO. **Deposit block to mint: 18 min 29 s** | `568bedc542e6ed51ce6ecbbef0968a730d43b049f95150d37960ca7a86f44aaf` |

Live after CP-7: bridge UTXO `568bedc5…:0` (14.935652 KAS, state header `0x0d3f1e43…`,
committee `0xc68d24d7…`, cursor 3); minter branch `568bedc5…:1` (1 KAS); token UTXOs
`e108d416…:3` (2.5 KBT, Oz's Kasla key), `6cf4a2af…:0` (0.4 KBT, same key), `6cf4a2af…:1` (0.6 KBT,
genesis key), `568bedc5…:2` (0.5 KBT, Kasla key). Vault on Ethereum holds 4.0 KBT from 3 deposits;
KBT supply on Kaspa is 4.0. The bridge address changes with every advance (state is in the redeem
script); `node bin/bridge.mjs show` prints the current one.

Costs per spend on mainnet: heartbeat 1553 (node), 1 deposit 1559 (node), 2 deposits 1562 (node),
so about 3 budget units (30k script units) per deposit on top of the 1551 light-client step.
Minter input: budget 3 for 2 token outputs, 5 for 3. Each mint drains 1 KAS per deposit (carried
by the token UTXO) plus ~0.33 KAS fee from the bridge's balance; each heartbeat ~0.32 KAS.
A transfer that splits a 1 KAS covenant UTXO in two is storage-mass bound (about 0.15 KAS at the
minimum rate); at a 2x multiplier the fee and the shrinking outputs have no fixed point, hence
`--fee-mult 1` for transfers.

## Run

```
cd bridge && cargo test --release -- --nocapture --test-threads=1 && cargo build --release && cd ..
node bin/bridge.mjs key                      # throwaway key; fund it with genesis amount + 0.5 KAS
node bin/bridge.mjs genesis --url ws://127.0.0.1:17110 --amount 20 --max-fee 5 \
    --image-id <guest image id> --chain-commitment <mainnet commitment> --header <finalized root> --committee <committee hash>
    # or --bundle <dir>: takes image id, commitment and the prev pair from the journal
node bin/bridge.mjs init     --url ws://127.0.0.1:17110                      # creates the KCC-20 (token id printed)
node bin/bridge.mjs advance  --bundle eth-prover/out-deposit-12 --url ws://127.0.0.1:17110   # mints what the journal carries
node bin/bridge.mjs replay   --bundle eth-prover/out-deposit-12 --url ws://127.0.0.1:17110   # must be rejected
node bin/bridge.mjs transfer --from-key bridge-key.json --to kaspa:... --amount 0.4 --fee-mult 1 --url ws://127.0.0.1:17110
node bin/bridge.mjs show
```
State: `bridge-cp6-state.json` (covenant id, token id, state, live UTXOs, every minted token UTXO,
history). The Rust tool (`bridge-covenant script|journal|token-script|init|advance|transfer`)
prints the complete transaction and the engine verdict as JSON; compute budgets are not part of
the v1 sighash, so the driver walks them up without re-signing.

### The prover service (CP-7)

Needs, in the repo root: `eth-rpc-url.txt` (execution RPC with `eth_getProof`), Docker (for the
wrap), the node-box build of `eth-prover`, a Kaspa node's wRPC (Borsh) port, and a GPU mode:
`--gpu runpod` (default; `runpod-api-key.txt`, chmod 600, the prepaid balance is the spend cap,
plus `~/.ssh/id_ed25519`) or `--gpu local` (this machine's NVIDIA GPU through
`docker run --gpus all`, no Runpod key). Step-by-step setup for both is in the top-level README.

```
pm2 start "node bin/bridge-prover.mjs --url ws://127.0.0.1:17110" --name bridge-prover --kill-timeout 20000
pm2 save
pm2 logs bridge-prover --lines 20 --nostream
node bin/bridge-prover.mjs --once --dry-run --force heartbeat                    # fetch + preflight only, no pod, no tx
node bin/bridge-prover.mjs --url ws://127.0.0.1:17110 --once --force heartbeat   # one real cycle (stop pm2 first)
```

Log events (`bridge-prover.log.jsonl`, one JSON object per line): `idle` (hourly; cursor, vault
nonce, finality lag, next heartbeat), `wait-finality` (work is due, the finalized header has not
moved past the covenant's), `cycle-start`, `preflight-ok` (cycles, rotations, new header),
`pod-created`, `pod-deleted`, `advanced` (every timing, pod cost, txid, budgets, fee, cursor, bridge
balance), `fetch-failed` (one endpoint; the next is tried), `cycle-failed` (retried after 10 min,
doubling to 2 h), `alarm-balance` (bridge below 6 KAS), `ALARM-pod-delete-failed` (delete that pod
in the Runpod console), `ALARM-no-execution-header` (a Gloas header: deposits cannot be proven by this
guest). Each cycle keeps its logs and bundle in `eth-prover/out-auto-<stamp>/`.
