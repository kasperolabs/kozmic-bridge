# MinerDrip in the USDC.k genesis

For the Claude working on the Kozmic bridge. Written by the SilverScript Studio session. Goal: the bridge's token genesis does what every Studio launch does: the same transaction that creates the token also funds a MinerDrip, a keyless covenant that pays Kaspa's miners on a halving schedule. The amount it carries is the token's "miner support", one number anyone can read from the genesis.

Background and the public convention: `MineDrip.md` in the Studio's GitHub repo (kasperolabs/silverscript-studio). Live feed of every drip: silverscriptstudio.com/drips.html.

## Files

| File | What |
|---|---|
| `minerdrip_v2.sil` | **Use this one.** v1 plus `require(tx.inputs.length == 1)` in both entries. Engine-tested; the bridge's reveal will be its first mainnet spend. |
| `minerdrip.sil` | v1, the Studio's current script (claim and reveal spent on mainnet Oct 10-11, 2026). Kept for reference: it has the equal-coin merge below. |
| `minerdrip.js` | Dependency-free helpers: schedule, constructor args, redeem check, reveal/claim sigScripts and amounts. |
| `minerdrip_v2_tests.rs` | Engine test: the equal-coin merge passes on v1 and is refused on v2; all single-coin paths pass on v2. |
| `minerdrip_js_tests.rs` | Engine test: the sigScripts `minerdrip.js` builds, run through the Kaspa script engine (8 cases, all as designed). |

## The covenant in one paragraph

`MinerDrip(int period, int divisor, int minPrize, byte[32] tokenId, int endowment)`. No key. `claim()`: once the coin is `period` DAA old, anyone spends it into exactly one output back to the same address holding `balance - prize`, `prize = max(balance / divisor, minPrize)`; the prize can only become the fee, so it goes to a miner. `reveal()`: valid only while the coin still holds the whole endowment (so once), no age requirement, pays `minPrize`; fired right after the genesis so the script, and the stamp inside it, is on chain from the start. `tokenId` is the token's covenant ID: the claim ignores it, but it makes the script (and the address) unique to USDC.k and lets anyone read which token endowed it.

Dispatch tags (the same for every drip): claim `26aa3fc0`, reveal `fcffbcc1`. The compiled script starts with `7604 26aa3fc0` and is 190 bytes.

Compiler check (Oct 17, 2026): the Studio's silverc (kaspanet/silverscript 3ed9733, v1.0.0) and the bridge's (a0dd744, v1.0.1, rusty-kaspa 2.1.0 crates) produce byte-identical MinerDrip scripts and the same tags for the same arguments, so the mainnet proof applies to drips compiled with either.

## v2: the equal-coin merge (found by the bridge session, Oct 17, 2026)

In v1 each input checks only its own balance against the one output. Two coins of the same value at the drip address can be spent together into a single output that satisfies both inputs, so the second coin's whole value becomes the fee (two 1 KAS coins: 1.05 KAS fee instead of 0.05). The money still goes to a miner, but all at once instead of on the schedule. Exposure: only equal-value coins, which in practice means equal community top-ups. v2 adds `require(tx.inputs.length == 1)` to claim and reveal: every coin drips on its own schedule and can never be merged. Dispatch tags are unchanged (`26aa3fc0`, `fcffbcc1`), the script grows from 190 to 198 bytes, `checkRedeem` accepts both. The Studio adopts v2 for new launches.

## Steps (mirrors routes/kcc20.js /build and /broadcast)

1. **Pick the terms.** Oz chooses three numbers: endowment (KAS into the drip), starting prize, halving time. `schedule(endowSompi, firstPrizeSompi, halvingDays)` derives `period`, `divisor`, `minPrize`. Example: 1,000 KAS, 1 KAS, 180 days gives divisor 1000, a claim every ~6.2 h, floor 0.05 KAS. Bounds enforced: endowment at least 1 KAS, starting prize 0.01 KAS to a tenth of the endowment, halving 7 days to 8 years, period at least 600 DAA.

2. **Draft the genesis with a placeholder endowment output.** Same inputs as the real genesis (if there is a KCC-23 metadata prep tx, the genesis's authorizing input spends its output, as now). Outputs in this order: the token's bound outputs (the BridgeMint authority and anything else in the covenant group), then the endowment output paying a stand-in P2SH (the Studio uses the P2SH of `51`, OP_TRUE), then change. Bind with `populateGenesisCovenants([{ authorizingInput, outputs: [bound indices] }])`. Read the covenant ID from the draft's first bound output. Never broadcast the draft.

3. **Compile the drip with that covenant ID.** `ctorArgs(schedule, covenantId)` gives the silverc `--constructor-args` JSON. Run `checkRedeem(redeemHex, covenantId)` on the result: it refuses anything that isn't the MinerDrip program or lacks the stamp. Address = P2SH of the redeem script (`aa20 <blake2b-256(redeem)> 87`, `kaspa:p...`), from your SDK.

4. **Build the real genesis** with the endowment output now paying the drip address, same bound indices, same authorizing input. Check the covenant ID is unchanged. It is fixed by the authorizing input and the bound output indices, not by unbound outputs' bytes (the Studio checks this on every launch and refuses if it ever moves). The endowment output is **unbound**: it is not part of USDC.k's covenant family.

5. **Fees.** Price the genesis as you do now; the node adds each input's committed compute budget (100 g per unit) and ~35 bytes per bound output to the mass. Relay floor is 100 sompi per gram of compute/transient mass, never storage mass. Keep the endowment at 1 KAS or more (KIP-9: small outputs are heavy).

6. **Broadcast, then reveal.** Right after the genesis is accepted, spend the endowment coin with `reveal()`:
   - one input: the endowment outpoint, `sequence 0`, `sigOpCount 0`, signatureScript = `revealSigScript(redeemHex)` (`04 fcffbcc1` + push of the redeem script);
   - one output: the drip's own address, `revealSpend(balance, schedule).keepSompi` (= endowment − minPrize). The difference is the fee.
   - If the node hasn't indexed the genesis output yet, retry for a few seconds; a coin only a few DAA old can also fail the node's sequence-lock check, so retry until it passes. `minPrize` must cover the reveal's network fee; at the floor above it does with plenty to spare.

7. **Claims afterwards.** Anyone can claim. A claim is `claimSigScript(redeemHex)`, input `sequence = period`, one output back to the drip with `claimSpend(balance, schedule).keepSompi`. `claimSpend` returns null once only the last sliver is left.

## Why the genesis and not the metadata prep tx

`PLAN_usdc-adoption.md` mentions "optional MinerDrip as a second prep output". Don't: the stamp needs the covenant ID, the covenant ID depends on the genesis's authorizing input, which is the prep tx's output, so a drip inside the prep tx would need its own ID before that ID exists. In the genesis there is no cycle, and the token's birth and its miner support are one transaction, which is the convention. (The indexer accepts an endowment in either place; a stamped drip in the genesis is the strong form.)

## After launch: tell the Studio

The Studio's keeper and its `/api/kcc20/drips` feed only know drips it compiled itself. Send the Studio session the genesis txid, the drip address, the redeem script hex and the three terms, so it can register the drip: the keeper then claims on schedule if no miner does, and USDC.k shows its miner support on the feed, the launchpad and the token card.

## What to report back to Oz

Covenant ID, genesis txid, drip address, endowment, reveal txid. The reveal's input on any explorer shows the full script with USDC.k's covenant ID inside it: that is the proof, no indexer needed.
