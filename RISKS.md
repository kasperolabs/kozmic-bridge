# What can go wrong

This is the honest list. Every item is either something that happened to this bridge on mainnet,
something the design was measured against, or something we cannot rule out. The caps exist because
of this list: they bound what any single failure can cost in total, and they protect no individual
holder from loss. Use amounts you can afford to lose while the bridge is new.

Each item says what it is, what we did about it, and what is left.

## 1. A bug in an immutable program

The vault, the relay, the covenant and both guests cannot be changed after deployment. A flaw in any
of them stays until the instance is closed and a new one deployed. The vault and relay were reviewed
by independent models and tested on a mainnet fork against the real RISC Zero router; the covenant runs
every transaction through the real rusty-kaspa 2.1.0 engine before it is sent; the guests are built on
RISC Zero's audited r0vm-helios. **No paid audit has been done.** Left: the cap is the damage bound.
If a flaw is found, deposits are closed (the one thing the operator can do) and holders exit through
the still-working side; funds taken through a flaw cannot be returned. The cap bounds what is in the
vault at any one time, not what can be lost over the instance's life: a flaw exploited repeatedly while
deposits keep refilling the vault can take more than one cap's worth, which is why closing deposits is
the first response to any sign of one.

## 2. Forged Kaspa history (the outbound proof)

An exit is paid when a proof shows enough of Kaspa's work after the burn. A forger who builds a private
chain containing a fake burn must produce that work alone. The relay requires at least FLOOR attesting
superblocks, more for large amounts and more as time passes. At FLOOR 600 with alpha 0.5 the modeled
odds for a forger holding 30% of Kaspa's hashrate (the largest pool today) are about one in a billion
per year of ever succeeding once; a majority of the hashrate can forge, as on any proof-of-work chain,
and the vault's cap is what such a majority would gain. The attestation levels are absolute (computed
from the raw PoW hash), so a difficulty change does not move them. Details and the review that moved
the floor from 450 to 600: `docs/V4-DESIGN.md`, `docs/REVIEW-*.md`.

## 3. Forged Ethereum history (the inbound proof)

The covenant trusts a finality update signed by two thirds of Ethereum's sync committee, the same
assumption every Ethereum light client makes, and it pins the committee that must sign the next update
so a prover cannot supply its own. A compromised sync committee could mint unbacked `kzUSDC` up to the
vault's cap. We consider this Ethereum's risk, not ours, and accept it.

## 4. RISC Zero

Both chains verify Groth16 proofs produced by RISC Zero's prover (zkVM 3.0.4, the version whose control
root Kaspa's SDK embeds). A soundness bug in the zkVM or its Groth16 wrapper would let a prover prove
false statements on either side, bounded by the cap. Ethereum verifies through RISC Zero's verifier
router; Kaspa through its `OpZkPrecompile`. We cannot verify this ourselves; we rely on RISC Zero's
audits.

## 5. The operator disappears, or its provers stop

The bridge keeps working without Kaspero: anyone can prove and be paid the tip, and the covenant mints
for anyone with a valid proof. `bin/prove-exit.sh` and `bin/prove-deposit.sh` are the by-hand versions
of what the robots do. **Left:** the inbound rescue needs the instance's current state file and its
light-client store (no beacon node serves a bootstrap for a post-Gloas header). Both are public data;
publishing them automatically next to the instance is an open item at the time of this export, and
until it is done an inbound rescue needs them from us. The outbound rescue needs nothing from us. The
rescue scripts were assembled from the robot's steps and have not yet been run end to end by someone
outside Kaspero; that test is open.

## 6. The GPU rental fails

Every proof runs on a rented GPU. On 2026-11-15 one exit took 3 h 38 instead of 72 minutes because the
provider's daily API quota ran out and every retry burned time. Fixed in the operating stack (quota
accounting, a second provider), but a provider outage still delays exits; it never loses them, because
a burn that is not yet proven simply waits, and the proof can be made later by anyone.

## 7. Ethereum gas

The robot refuses to submit above a gas-price ceiling and waits. An exit submitted at 0.2 gwei costs
about 520,000 gas; at 50 gwei the same submission costs more than a small exit is worth. Left: on a
very expensive day exits wait; the bridge pays the submission, not the user.

## 8. The burn's clock runs out

Each burn carries a recent Ethereum block hash as its clock. Ethereum keeps block hashes for about 27
hours (EIP-2935 window); a burn whose clock falls out of the window before its proof lands cannot be
settled by that proof. The robot builds a fresh "rescue" burn to re-anchor it; `docs/SELF-RESCUE.md`
describes the manual version. Large exits whose proving time approaches the window are the case to
watch; the page's exit table shows the expected wait before you sign.

## 9. USDC itself

Circle can blacklist addresses, including the vault. A blacklisted vault cannot pay exits; `kzUSDC`
would then be claims on frozen USDC. `docs/USDC-BLACKLIST-STUDY.md` measures how often this happens
and to whom. The inbound guest proves each depositor's blacklist status at the finalized state the proof carries
(at or after the deposit; a blacklisted depositor's deposit is skipped, not minted); the page checks a
recipient before a burn is signed. A recipient blacklisted *after* the burn cannot be paid: the vault's
transfer fails, the debt stays recorded to that address, and there is no way to redirect it. Left: a
freeze of the vault is a total loss for holders who have not exited, a freeze of a recipient is a loss of
that exit, and nothing in this system can prevent either.

## 10. Caps and buckets

The vault refuses deposits above its cap, and the relay pays at most a fixed amount per proof and per
day across everyone. On a busy day an exit may arrive in parts over more than a day (anyone can call
`claim(txId)` for the next installment). Nothing is lost; it is slower. The cap is a limit on what the
vault holds at any moment, not a lifetime total (item 1).

## 11. Ethereum or Kaspa changes

A hard fork that changes the light-client header format (Ethereum's Glamsterdam, "Gloas", is already
handled by the current guest) or Kaspa's header, PoW or the ZK precompile ends an instance: deposits
stop first, and exits continue for as long as proofs of Kaspa can still be made. A Kaspa change that
alters what the outbound guest reads would end exits too. Such a date is announced on the bridge page
in advance; move out before it. The fix is always a new instance.

## 12. Griefing the operator

Anyone can burn tiny amounts repeatedly to make the robot pay for proofs and gas. The relay enforces a
minimum burn (`MIN_BURN`; smaller burns are not paid and the tokens are gone), burns are batched into
one proof when they arrive together, and the robot may decline to prove below a service minimum, in
which case the holder can self-prove. Griefing costs the operator money, never the users their funds.

## 13. Racing provers

Several provers may prove the same burn. The relay pays the first valid submission and reverts the
rest with `already settled`; a robot checks with a free call before sending, so the loser spends GPU
time, not gas. The tip goes to the address inside the proven journal, so copying someone else's
transaction from the mempool pays them, not you.

## 14. Phishing and copies

A copy of this code that changes nothing produces the same image ids and covenant hashes and is just a
second honest instance. A copy with a backdoor produces different ids. The identity of the real token
is the family id `cc9957fe0d485f79994ed583aa7e16bacf194d9b9d6d77aeedc129349ddad12c`, shown on Kascov
and Studio; the real vault and relay are the addresses in the README, verified on Etherscan. Nothing
with a different id is this bridge, whatever it is called. We will never ask for your recovery words
or a private key.

## 15. The user's own mistakes

The Kaspa address given at deposit and the Ethereum account connected at burn are final. A burn below
`MIN_BURN` is lost, and so is a burn whose payload names the zero address (the page never builds one; a
hand-built burn can). A burn larger than the daily bucket is paid in installments. One exit uses one
coin, so a wallet holding many small cells can send at most its largest at once. The guide
(`docs/GUIDE.md`) says all of this before you sign; the page repeats it.

## 16. What the operator holds

Kaspero holds: the fee address on Ethereum (where exit fees accumulate, and where a tip goes when the
prover's own address cannot receive it), the robot keys (which pay gas and Kaspa fees and receive tips),
the web page and its domain, and the close preimage that lets it stop new deposits. None of these can
move a user's funds, redirect an exit, or mint.

The covenant's KAS pool is also operator money with a known leak: `advance` takes no signature and the
covenant lets the successor keep `input - max_fee - cell floors`, so whoever advances it with a valid
proof may pay the gap between `max_fee` and the real network fee to an output of their own. `max_fee` is
set tight at genesis, the gap is worth far less than the proof that earns it, and the pool holds tens of
KAS; if it ever ran dry, advances would stop until it is refilled, and no user funds move. The same
permissionless `init` left the third genesis output's script unpinned, so a stranger who had won the
race to `init` could have redirected the miner endowment; the live instance's `init` is on chain with the
intended drip, and the next covenant generation pins it.
