# V4 design note (S1)

Status: draft 3. Section 2 (the outbound rule) written, with the first measured day in 2.8; sections 3 to 9 outlined. Nothing here is frozen until S2.
Author of record: Oz (Kaspero Labs). Built with Claude. Plan of record: `docs/REVIEW-2026-11-02.md` (sha256
`160a83c4…e69`). Code read for this note: `outbound/kaspa-prover/primitives/src/relay.rs` (v2, `KZO3`),
`usdc/src/KaspaRelayV3.sol`, `usdc/src/UsdcVaultV2.sol`, `bridge-v5/bridge.sil`, as in the project library on
2026-11-04 (the 10-17 Tipsy.k set; nothing changed in code since).

Number labels used below: **measured** (a record holds it; the record is named), **computed** (arithmetic from
measured numbers or from a stated model, done in this note), **assumed** (a guess, to be replaced by S1b).

## Outline

1. Inputs and the numbers this note stands on
2. **The outbound acceptance rule (F1, D1)**: the current rule as code; 4.1 burn-anchored freshness, exact; attacks;
   the rate reference; 4.2; 4.3; comparison and recommendation
3. Round shape and deadline (F4, D2)
4. After a forged settlement (F2, D3)
5. Pricing as the second layer (F3, D4): floor vs latency vs cost table
6. Inbound nonce continuity (F5)
7. Payouts: tip rule, cumulative pro-rata installments, dust (F6)
8. Ordering: debit before the call (F7)
9. Pre-mainnet items: cap0 $5k, `MIN_BURN`, artifact host, ~120M post-fork deploy gas, robot V3 event decoding and
   the `proof-ok` beat flag
10. S1b measurement plan (scripts in `tools/s1b/`)
11. Decisions D1 to D5 (filled when Oz decides)
12. Questions for S2 (one per rule, for fresh chats)

---

## 1. Inputs and the numbers this note stands on

| quantity | value | label and source |
|---|---|---|
| level-30 superblock rate, DAG-wide, λ | **9.17 per minute** (17,031 in 30.9 h, 2026-11-03/04); 9.6 in the handoff, 9.9 in the O5 hour | measured; S1b run 1 (2.8) |
| honest attesting share at level 30, q | **0.9793** (76.0% direct, 2,958 at 2 hops, 772 at 3, 352 none) | measured; S1b run 1. The O6 figure (computed 0.974) agrees |
| hashrate, and the level rule | 3.57e17 H/s mean; level-30 count / (work / 2^61) = 0.992 | measured; S1b run 1. Levels are absolute, so the level-30 rate moves with hashrate |
| cost of one level-30 superblock | ~2^61 hashes, ~125 KAS forgone, ~$5 at $0.04 | computed from the emission schedule, not measured (review F3) |
| outbound proof time, P | STARK 16 to 36 min + 72 s wrap on one 4090 | measured; review 4.4 |
| outbound proof time with ~16 GPUs | a few minutes + wrap | computed (segment parallelism), not measured; review 4.4 |
| EIP-2935 history window | 8,191 block hashes, ~27 h | stated in the review; **confirm on the deploy fork** |
| pruning horizon of our node | ~21 to 30 h | Oz's estimate; handoff section 5 |
| Kaspa DAA score rate | 9.9968 per second over 30.9 h; hourly 9.69 to 10.25 | measured; S1b run 1 |
| burn to acceptance lag (wallet builds, signs, broadcasts; chain accepts), δ | 5 min | assumed; S1b and the page logs replace it |

Model used for the probabilities in 2.3: level-30 arrivals are a Poisson process with rate proportional to
hashrate, at λ = 9.6/min. Section 2.8 checks it against the first measured day: it holds for arrivals within 30 min
and fails over hours, because hashrate drifts; 2.8 gives the corrected odds.

---

## 2. The outbound acceptance rule

### 2.1 What the code does today (v2 guest, V3 relay)

The guest (`run_with`) proves, for checkpoint K and tip T: a closed level-L walk from T reaches K; per level, the
`count` of superblocks with `daa > K.daa`, and the `attesting` subset whose first-parent path reaches the commitment
chain `c_0 = B.aimr, c_i = H_seq(c_{i-1}, root_i)` within `MAX_FP_STEPS = 3` hops. Every burn's sequencing
commitment chain ends at `B.aimr`.

The relay (`submit`) accepts when `count >= FLOOR` and `attesting >= requiredAttest(amount)`, and ranks a
replacement by `count` only (`jn.count > c.count`). `count` is borrowable: a private T may list honest
superblocks as level-30 parents, and the closed walk then counts them. O5's forged B' carried the honest 4,958
with 0 attesting. That is F1.

What is not borrowable is `attesting`. An attesting superblock S is PoW-verified at level >= 30, and its mined bytes
contain the hash of its first parent, whose header contains some `c_i`. `c_i` descends from `B.aimr`, which commits
to every burn's transaction id. So **every attester was mined after every burn in the proof existed**. 4.1 builds
on exactly this fact and nothing else.

### 2.2 4.1, burn-anchored freshness: the exact definition

**Burn payload v3** (93 bytes; v2 is 53):

```
"KZB1" | 0x03 | target(20) | tip(8, BE) | recipient(20) | beacon_number(8, BE) | beacon_hash(32)
```

`beacon_number = 0` with `beacon_hash = 0` means "no beacon" and is valid. A wallet that can read Ethereum fills the
beacon with a recent Ethereum block (head minus a few blocks, so a one-block Ethereum reorg does not void it). A
wallet that cannot leaves it zero.

**Guest v3** (changes to `run_with`, nothing else in steps 1 to 5 moves):

- parse payload v3; `tip < amount` (F6, section 7);
- the **anchor** is the burn beacon with the highest Ethereum block number; at least one burn must carry a beacon,
  and two beacons naming that block must agree;
- the journal adds K's daa score, difficulty bits and blue work (from K's PoW-verified header; trusted because the
  relay requires K == its checkpoint), and the anchor's `(number, hash)`. Header 278 + 76 = 354 bytes (`KZO4`);
- `count` and `attesting` stay as they are; the guest enforces no minimum, as today. Built and unit-tested
  2026-11-04 (`primitives/src/relay.rs`, branch `guest-v3`); not pinned.

Why the guest may choose the anchor: every attester is after every burn, so the attesters are after every beacon in
the proof, whichever is the anchor. An older anchor would only make the requirement larger; the freshest is what the
honest prover wants and what the forger would pick anyway. Choosing it in the guest means no witness change. A burn
with a garbage or reorged beacon can never strand a proof: the robot adds a fresh anchor burn of its own (the beat
is one), which then has the highest number; a beacon number above Ethereum's head is excluded by the robot, and the
page never builds one. User burns need no beacon at all (payload v2 is still read, as beaconless); a beacon in a user
burn only saves the robot an anchor transaction.

**Relay V4, acceptance** (in `submit`):

1. `beacon_hash == HISTORY.get(beacon_number)` (EIP-2935 system contract), with `beacon_number < block.number` and
   within the window. Outside the window the proof is refused; the anchor is replaced, never the rule.
2. The caller passes the anchor block's header RLP; the relay checks `keccak256(rlp) == beacon_hash` and reads the
   timestamp (field 11). Exact time, not `12 s x blocks` (which undercounts by the missed-slot rate in the forger's
   favour). Post-Gloas: the execution header is still RLP with the same hash rule (`GLOAS-GUEST.md` relies on it);
   confirm field order on the deploy fork.
3. `tau = block.timestamp - beacon_time + SLOT_SLACK` (12 s: the most a proposer can see its own block hash before
   it is public; section 2.3).
4. Accept when `attesting >= max(F, alpha * r * DAA_RATE * tau)`, at `CMP_LEVEL = 30`. `F` is the attestation floor,
   `alpha` the required hashrate share, `r` the rate reference (section 2.4), `DAA_RATE = 10`.

`count` and `FLOOR` no longer carry security; `count` is kept because it feeds `r`.

**What the requirement means.** The forger's attesters all date from after his own anchor beacon and he mines them
at rate `f * lambda`. The requirement grows at `alpha * lambda` from the same instant. Starting early is impossible
(the beacon did not exist), and waiting does not help (the requirement keeps pace). Below `f = alpha` his expected
count falls behind the line forever; he can only win on variance, which `F` bounds.

### 2.3 Attacks on 4.1

**Minority miner, share f.** He opens a private branch at a fresh beacon and submits the first moment his
attesters reach `max(F, alpha * lambda * tau)` (his proving time taken as zero; ours is not). That is a first-passage
problem; the bound below is per attempt, then per year with a fresh attempt every `F / (alpha * lambda)`. Computed,
Poisson model, λ = 9.6/min, attacker attesting share 1:

| alpha | F | first legal moment | f = 0.20 | f = 0.25 | f = 0.33 | f = 0.40 |
|---|---|---|---|---|---|---|
| 0.40 | 150 | 39 min | 4e-10 / yr | 1e-3 / yr | certain within a year | n/a |
| 0.40 | 300 | 78 min | 3e-23 | 3e-10 | certain | n/a |
| 0.45 | 300 | 69 min | 3e-31 | 1e-16 | 2e-3 / yr | certain |
| 0.50 | 150 | 31 min | 4e-18 | 5e-10 | 3e-2 / yr | certain |
| **0.50** | **300** | 62 min | 3e-39 | 4e-23 | **1e-7 / yr** | certain |
| 0.50 | 600 | 125 min | 7e-81 | 1e-48 | 7e-18 | 6e-4 / yr |

Today's rule, for comparison: a 10% miner forges in ~104
min with nobody challenging (review F1). Under 4.1 at alpha 0.5, F 300, the same miner's odds are below 1e-100.

**The O5 forged ladder, replayed.** B' with 4,958 borrowed honest superblocks and 0 attesting: refused at rule 4
whatever its count, because `0 < F`. Under V3 it lost only to the attestation floor; under 4.1 the floor is the
smallest part of what it fails.

**Forger choosing beacons.** An old beacon gives a larger `tau` and a larger requirement against attesters he could
only start mining after it: strictly worse. A future beacon cannot be known. A beacon from a fork of Ethereum fails
rule 1. A beacon whose header he makes up fails rule 2. So he always uses the freshest real one, which is what the
table assumes.

**Multi-burn proofs.** All burns precede B, so all attesters follow every beacon. The anchor is any burn the prover
names; security does not depend on which. A proof mixing old user burns and a fresh anchor is the normal case.

**Ethereum proposer grinding.** The forger does not need an unpredictable value, only one that did not exist before
`beacon_time`. A proposer knows its own block hash up to one slot before it is public; `SLOT_SLACK = 12 s` adds that
to `tau` (computed: under 2 superblocks at 9.6/min, ~1% of F = 150). Several consecutive slots by one proposer would
add 12 s each; rare, and still small against F. A withheld Ethereum block is orphaned and fails rule 1.

**Withholding to move the rate reference.** See 2.4: with an adaptive `r`, a miner who stops publishing for days
lowers `r` to the public rate `(1 - f) * lambda`, and then needs only `f > alpha / (1 + alpha)` (0.333 at alpha
0.5). The defence is how slowly `r` may fall, priced in 2.4.

**Hashrate drop (honest liveness).** The honest robot passes while `q * lambda_now > alpha * r * DAA_RATE`. Computed
tolerance of a drop between two settlements: 58.9% at alpha 0.40, 53.8% at 0.45, **48.7% at 0.50**. A faster drop
stalls outbound until hashrate returns. Section 2.4 says why the stall cannot safely be broken by a timer.

**Hashrate growth.** With a fixed `lambda` in an immutable contract, security erodes as Kaspa grows: if hashrate
doubles, the effective threshold halves (0.25 at alpha 0.5). This is the reason for 2.4.

**Variance.** Covered by F for the forger. For the honest side it is not a probability at all: the robot reads its
own `attesting` from the witness before it rents a GPU, so it never submits a failing proof; a slow stretch only
delays its cut. S1b measures how long the slow stretches are.

**Proving latency is on the honest side of the scale.** Attesters freeze at the witness cut; the requirement keeps
growing until `submit`. The honest cut must satisfy `q (tau_w - delta) >= alpha (tau_w + P)`. Computed exit times
(burn accepted to settled, δ = 5 min assumed):

| alpha | F | P = 36 min (4090, measured upper) | P = 16 min (measured lower) | P = 5 min (16 GPUs, computed) |
|---|---|---|---|---|
| 0.40 | 300 | 74 min | 54 min | 43 min |
| 0.45 | 300 | 77 min | 54 min | 43 min |
| **0.50** | **300** | **85 min** | 54 min | 43 min |
| 0.50 | 600 | 106 min | 86 min | 75 min |

Alpha costs little latency once proving is fast; F sets the floor of it. This makes 4.4 (parallel or standing proofs)
a latency item, not a security item.

**Ethereum-side limits.** A proof must land within the EIP-2935 window of its anchor (~27 h); the pruning horizon
(~21 to 30 h) is the tighter limit anyway, and the 3-hour beat keeps both far away.

### 2.4 The rate reference r

The requirement needs "the honest rate" in an immutable contract. Four choices; the fourth is proposed (Oz's
question, 2026-11-04: "can we adjust hardness by hash rate without a timer?").

- **Read from Kaspa's own difficulty at trusted headers (proposed).** The checkpoint K is the one header the relay
  already trusts (it is the T of the last settled honest proof, PoW-checked by the guest and bound to `checkpoint`).
  The guest copies K's `bits` and `blue_work` into the journal; the relay stores `(blue_work, daa)` of every
  checkpoint it settles. Two readings, no timer and no tuned smoothing:
  - `r_fast` = expected level-30 rate at K's difficulty: `2^256 / (target(K.bits) + 1) x DAA_RATE / 2^61` per second.
    Difficulty follows hashrate within minutes, so drift is caught one beat late at most.
  - `r_slow` = average over the last ~24 h of checkpoints: `(K.blue_work - K_old.blue_work) / (K.daa - K_old.daa)`,
    same conversion. Exact work, from headers the relay trusted when it settled them.
  - Requirement: `attesting >= max(F, alpha x tau x max(r_fast, beta x r_slow))`, beta ~0.8. `r_fast` alone would let
    a miner who stops publishing pull the difficulty down within minutes and reach the `alpha / (1 + alpha)`
    threshold cheaply; the floor holds the requirement at 0.8 of the day's average unless he hides for a day
    (computed: ~$24k of forgone reward at share 0.35, comparable to the whole vault, for at most a 20% easier bar).
  - Measured (2.8): difficulty predicts the next hour's level-30 rate with mean ratio 0.991 and a spread equal to
    the Poisson noise of an hour's count, and it removes most of the drift advantage the fixed reference gave.
  - Honest drops under 1 - beta (20%) cost nothing; a faster, larger crash stalls until hashrate returns, as in every
    variant without a timer.
- **Fixed at genesis** (`r0` from S1b). Simple; erodes with hashrate growth (2.3); stalls on a 48.7% drop. Acceptable
  only for a short-lived instance.
- **Adaptive EMA from settled rounds (the first proposal, superseded by the difficulty reading).** Each settled journal gives `r_obs = count / (T.daa - K.daa)`
  (superblocks per DAA unit). `count` in an honest journal is a closed walk over PoW-verified headers, so it can be
  neither inflated nor deflated; a forged journal that settles has already won (section 4), so `r` adds no new
  exposure. Update only when `T.daa - K.daa >= 36,000` (one hour), as `r <- (3r + clamp(r_obs, r * d_down, r * 2)) / 4`.
  `d_down` bounds how fast `r` can fall; it prices the withholding attack: computed, at ~125 KAS per superblock a
  miner of share 0.35 forgoes ~0.6M KAS a day while withholding (~$24k at $0.04, computed from the schedule), and at
  `d_down` set to allow 10% a day he withholds ~4 days to reach the 0.333 threshold: ~$100k against a vault capped at
  $50k. S1b measures normal day-to-day hashrate swings so `d_down` sits above them.
- **Adaptive plus a stall timer** (the requirement decays after N hours without a settlement). Rejected: a timer turns
  our robot's downtime into the forger's discount (after a 12 h outage a 0.15 miner would suffice), and robot
  downtime has happened (Wobbly.k).

So a hashrate crash faster than the tolerance stalls outbound until hashrate returns. Stated in the README next to
forks (F13 class); inbound is unaffected. A Kaspa BPS change is a hard fork, so `DAA_RATE` moving is already an exit
deadline (handoff section 5).

### 2.5 4.2, fixed-depth attestation ranking

Acceptance as today (count floor, attestation priced by amount); replacement ranked by superblocks attesting a fixed
depth D of chain below T. It removes borrowing from the comparison (F1) but only matters when an honest challenger
submits inside the window. With nobody challenging, the forger pays the floor in dollars (F3: ~$5 per attester
against $15 of value per attester today; pure pricing at 3x margin needs ~6,000 attesters for $10k, ~10.4 h, review
F3). It keeps the window, the replacement race, F4 and D2, and it needs the standing proof (4.4) to be safe against a
late forger.

### 2.6 4.3, fork-point relation proof

A challenge guest takes both candidates' headers and compares work after the split; borrowed superblocks cancel
exactly. The strongest comparison rule, but it is still a comparison: safety rests on a watcher, it needs data
availability (~1,800 headers per submit in blobs, journal committing to blob hashes) and a second guest. Its value
is as the dispute layer if 4.1 ever needs one.

### 2.7 Comparison and recommendation

| | 4.1 burn-anchored freshness | 4.2 fixed-depth ranking | 4.3 relation proof |
|---|---|---|---|
| a minority forger with nobody watching | needs f > alpha; odds in 2.3 | wins at the floor price | wins at the floor price |
| needs an honest watcher | no | yes | yes |
| fixes F1 | yes, count leaves the rule | yes, in the comparison | yes, exactly |
| F4 and D2 | dissolve if there is no window (below) | stay | stay |
| new data | 40 bytes of journal, one RLP header per submit | none | blobs per submit |
| new failure mode | stall on a fast hashrate crash; `r` calibration | none new | DA and a second guest |
| change size | guest v3 (payload, anchor), relay V4 | guest v3, one relay line | guest v3, challenge guest, relay V4 |

**Recommendation: 4.1, alpha 0.5, F 450 (2.8), the rate read from difficulty at the checkpoint with a 24 h floor (2.4), and no window.** Under 4.1 the window has almost nothing left to
protect: a forger who passes the rule already holds about half of Kaspa's hashrate, and against a majority nothing
in this design helps (review 4.5). Removing the window means `submit` verifies and settles in one transaction:
compare-and-swap stays (two honest robots never both pay gas for one round), the candidate struct and its deadline
go, F4 cannot exist, D2 has nothing to decide, and a round costs one transaction instead of two (gas measured in S4,
not estimated here). If S2 finds 4.1 broken, 4.2 with the F4 fix is the fallback and 4.3 the dispute layer.

The alternative inside 4.1 is to keep a short fixed window with 4.2 ranking, for the band where a forger of share
0.45 to 0.5 passes the rule and an honest challenger could still outweigh him. It costs the window's latency on
every exit and brings back F4 and D2. Worth it only at alpha 0.4 or lower.

Cost outside the contracts: payload v3 in the beat and the robot's anchor burns (S6); Kasla's burn builder and the
page may stay on payload v2 shape with a zero beacon until they adopt it, at the price of one anchor burn per proof
(~0.24 KAS fee + 0.2 KAS parked, measured, handoff section 8).

### 2.8 S1b, first measured day (run 1, 2026-11-04)

`outbound/sbmeter` run 1 read everything the node held: 30.9 h, 1,112,529 blocks, 4,520 pages, 744 s, no gaps.
`tools/s1b/s1b.py` on that record. Everything in this subsection is measured unless marked computed.

**Arrivals are Poisson over minutes, not over hours.** Sliding-window counts of level-30 superblocks:

| window | mean | variance / mean | lowest | lowest / mean |
|---|---|---|---|---|
| 30 min | 275.5 | 1.06 | 228 | 0.828 |
| 60 min | 551.8 | 1.36 | 481 | 0.872 |
| 120 min | 1,106.1 | 1.87 | 1,005 | 0.909 |
| 180 min | 1,661.7 | 2.36 | 1,541 | 0.927 |
| 360 min | 3,338.2 | 3.43 | 3,165 | 0.948 |

A pure Poisson process gives 1.0 at every width. The excess grows with the window, which is the signature of a rate
that wanders, not of clumping: hourly hashrate ranged 3.19e17 to 3.70e17 (about -11% to +4% of the mean). Computed:
the 6 h excess corresponds to a ~2.7% standard deviation of the 6 h average rate.

**The honest floor wait is exactly Poisson.** Minutes to collect F attesting superblocks from any minute: F = 150
median 16.6, max 20.6; F = 300 median 33.3, max 38.9; F = 600 median 66.9, max 75.3. Poisson means (computed) 16.7,
33.4, 66.8.

**Honest exit latency on the real arrivals** (δ 5 min assumed, P as in section 1), median / p99 / max, minutes; no
start in 30.9 h got stuck:

| alpha | F | P = 36 | P = 16 | P = 5 |
|---|---|---|---|---|
| 0.50 | 150 | 84 / 96 / 98 | 44 / 51 / 52 | 28 / 31 / 32 |
| 0.50 | 300 | 84 / 96 / 98 | 55 / 59 / 60 | 44 / 48 / 49 |
| 0.50 | 600 | 109 / 115 / 116 | 89 / 95 / 96 | 78 / 84 / 85 |
| 0.45 | 300 | 77 / 85 / 86 | 55 / 59 / 60 | 44 / 48 / 49 |
| 0.40 | 300 | 75 / 79 / 80 | 55 / 59 / 60 | 44 / 48 / 49 |

These match the computed table in 2.3 to within a minute.

**The forger does better on the real record than on Poisson.** Per attempt, 300 starts x 100 thinnings (resolution
3e-5), forger owning each real superblock with probability f, against a fixed r equal to the record's mean:

| alpha | F | f = 0.33 real / Poisson | f = 0.40 real / Poisson | f = 0.45 real / Poisson |
|---|---|---|---|---|
| 0.40 | 300 | 3.1e-3 / 1.7e-4 | n/a | n/a |
| 0.45 | 300 | below / below | 9.1e-2 / 2.5e-2 | n/a |
| 0.50 | 300 | below / below | 3.3e-4 / 6.7e-5 | 1.3e-1 / 4.4e-2 |
| 0.50 | 600 | below / below | below / below | 4.5e-2 / 1.9e-3 |

Nothing below f = 0.33 was observable at this resolution. Where it is observable, real is 2 to 20 times Poisson,
and above the analytic bound in 2.3 (which gave 2e-4 per attempt at alpha 0.5, F 300, f 0.40). The cause is the
same drift: the rule compares the forger's count with a reference rate, and when the network runs above the
reference, his share of the real rate counts for more. In the contract the reference is the adaptive r of 2.4,
which tracks a 3 h to 12 h average; over this record the rate moved -12.1% / +5.2% in 3 h, -11.9% / +7.0% in 6 h,
-13.8% / +7.7% in 12 h. So the forger's effective share is up to ~8% above his real one (measured on one day).

**Corrected odds, computed:** the 2.3 first-passage bound with the forger's share raised 10% (a reference-error
budget above everything measured so far), per year:

| alpha | F | f = 0.25 | f = 0.30 | f = 0.33 | f = 0.36 |
|---|---|---|---|---|---|
| 0.45 | 300 | 2e-11 | 2e-3 | certain | certain |
| 0.45 | 600 | 3e-25 | 2e-9 | 1e-3 | certain |
| 0.50 | 300 | 4e-17 | 1e-7 | 1e-3 | 0.8 |
| **0.50** | **600** | 7e-37 | 7e-18 | **4e-10** | 2e-4 |

Drift costs about three points of hashrate share at the threshold. At alpha 0.5 the property "a third of Kaspa's
hashrate cannot forge" holds at F = 600 with margin and at F = 300 only to about 1e-3 a year. F = 600 costs 25 min
of median exit at today's proving time (109 vs 84) and 34 min with fast proving (78 vs 44).

**The reference read from difficulty removes most of the drift** (`s1b.py ref`, same record, 260 starts x 100):

- **Calibration:** realized level-30 over the next hour divided by the rate implied by the 10 minutes of difficulty
  before: mean 0.991, sd 0.042, p1 0.903, p99 1.088. Computed: an hour's count of ~550 has a Poisson sd of 0.043, so
  the spread is the count's own noise; difficulty adds no measurable error. The 0.9% bias is in the safe direction
  (the requirement comes out slightly high).
- **Forger per attempt on real arrivals, by reference:**

| reference | a 0.45 F 300 f 0.40 | a 0.50 F 300 f 0.40 | a 0.50 F 300 f 0.45 | a 0.50 F 600 f 0.45 |
|---|---|---|---|---|
| record mean (fixed) | 1.0e-1 | 6.2e-4 | 1.5e-1 | 5.1e-2 |
| difficulty at K, fresh | 2.7e-2 | 7.7e-5 | 4.6e-2 | 6.8e-3 |
| difficulty at K, 180 min old | 2.7e-2 | 3.8e-5 | 4.3e-2 | 5.4e-3 |
| Poisson arrivals (from `mc`, other starts) | 2.5e-2 | 6.7e-5 | 4.4e-2 | 1.9e-3 |

  With the difficulty reference the real record behaves like Poisson, except a ~3x residual at F = 600, f = 0.45.
- **Honest exits unchanged** (alpha 0.5, P 36): F 300 median 85 to 86, max 94 to 97; F 600 median 108, max 113; none
  stuck under any reference.
- **Corrected odds, computed,** with the forger's share raised 5% (the largest 3 h hashrate rise measured is +5.2%;
  that is what a K one beat old can miss), per year:

| alpha | F | f = 0.30 | f = 0.33 | f = 0.36 |
|---|---|---|---|---|
| 0.50 | 300 | 9e-10 | 2e-5 | 3e-2 |
| 0.50 | 450 | 5e-16 | 1e-9 | 8e-5 |
| 0.50 | 600 | 3e-22 | 1e-13 | 2e-7 |

  With the difficulty reference, F = 300 holds a third of Kaspa's hashrate to about 2e-5 a year, and F = 450 to
  1e-9 at 16 more minutes of exit than F = 300 (computed from the floor wait). The 24 h floor (beta) cannot be
  tested until the record is ~33 h longer than the attack window; the cron runs reach that on 2026-11-05.

**Liveness margin:** the worst measured hashrate drop was 12.1% in 3 h against the 48.7% that alpha 0.5 tolerates.
One day is not the tail; the 6-hourly runs (cron, `flock`-guarded) extend the record, and this subsection is redone
on 5 to 7 days before D1.

**Open from the data:** the rule stands; the reference changes from an EMA to the difficulty reading (2.4), which
the data supports. Parameters for D1 after 5 to 7 days: F (leaning 450 at alpha 0.5 with the difficulty reference;
600 under the EMA) and beta (the 24 h floor, testable from 2026-11-05).

### 2.9 First v3 burn, proven in dev mode (S3b, 2026-11-04)

Branch `guest-v3` (worktree `~/kaspa-zk/kz-guest-v3`; the live Sepia.k services stay on the main tree and on
payload v2, which their robot's scan is limited to). Measured:

- **Burn:** Kaspa mainnet txid `55071f63ac9737d671f56377ecd3c9a656b0d98ef876a24690116574b75a18b6`, 0.01 Sepia.k
  (token `13af6019…d58d`) from the beat key, target `0x…dead` (no relay can claim it), tip 0, payload v3 with
  beacon Sepolia block 12,062,939 `0x47a253f3…0f32` (three blocks behind head when built). Fee 23,665,900 sompi, the
  same as a v2 burn; the local engine and the node accepted it on the second budget step.
- **Witness:** `burnwitness` (patched in the branch) read the v3 payload and its beacon; every inclusion hash equal
  to the node's. K `ba71ef02…bad0` (the Sepia.k relay's checkpoint, level 33), B `7865ad51…7063`, T `da653868…cd2d`
  25.7 min after B, K to T 146.2 min, 1,253 level-30 superblocks counted, 202 attesting (hops 155/38/9; 7 join at
  hop 4).
- **Guest v3 in dev mode:** 870,619,867 user cycles, 921 segments, 20.7 s to execute, 693,721 cycles per PoW header
  all in; journal 422 bytes (354 + 68, `KZO4`), sha256 `ccb17569…6aed`, **equal to the native run**.
- **Attest rate after B:** 70 attesting in the first 11.8 min (a `burnwitness` run with its default depth), 202 in
  25.7 min, so 132 in the following 13.9 min (9.5/min). Expected from 2.8: ~9.0/min. The ladder's total count was
  also thin in the first window, which points at a slow stretch of the network rather than at attestation near B;
  `sbmeter`'s next run covers this window and settles it.

### 2.10 Relay V4 and vault V3, built and tested (2026-11-04)

`usdc/src/KaspaRelayV4.sol`, `UsdcVaultV3.sol`, `ISettlementV3.sol` on branch `guest-v3`. Not deployed.

- **Rule as code:** `submit(seal, journal, headerRlp)` checks K and K's daa against the checkpoint, the target and token,
  then the anchor: `HISTORY` (EIP-2935) must return the anchor hash for its number, `keccak256(headerRlp)` must be
  that hash, the header's number field (item 8) must equal it, and its timestamp (item 11) times `tau`. Requirement
  `max(F, alpha x max(r_fast, beta x r_slow) x tau [, amount / ATTEST_UNIT])`, r_fast from K's bits, r_slow from blue
  work against the newest settled checkpoint at least `SLOW_SPAN_DAA` behind K (or `RATE0`). Then the verifier, then
  settlement in the same transaction. No candidate, no window, no deadline.
- **Payouts:** each installment's tip part is `floor(tip x paid' / amount) - floor(tip x paid / amount)`, so the sums
  are exact and a tip near the amount pays out; installments under `MIN_INSTALLMENT` wait unless they finish the burn;
  the relay debits before the vault's transfer and restores on refusal; the vault does the same; a transient lock
  refuses re-entry. `MIN_BURN` skips a burn for good.
- **Tests:** 23 unit tests (`test/KaspaRelayV4.t.sol`), all pass on the box with the existing V1 to V3 suites
  unchanged (14, 6, 13, 26). Fork test on Sepolia (`test/KaspaRelayV4Fork.t.sol`) against block 12,062,939, the
  first v3 burn's beacon: the real 678-byte post-Glamsterdam header parses to number 12,062,939 and time 1793801616,
  hashes to the block hash, and Sepolia's EIP-2935 contract agrees. **Beacon check: 21,326 gas** (measured).
- **Gas:** `submit` for one burn with the mock verifier 255,596 (measured, unit test). With the real Groth16 router,
  computed ~540k for the whole round in one transaction, against V3's 728k + 369k on Sepolia (measured). To be
  measured on Sepolia.
- **What the tests made concrete for D1:** at alpha 0.5 the floor binds for the first ~65 min after the beacon at
  F = 300 and ~97 min at F = 450; past that the rate term rules (557 at 2 h, 1,114 at 4 h at today's difficulty).

---

## 3. Round shape and deadline (F4, D2)

*To write next.* Under the recommendation: no window, settle in `submit`. Under the fallback: one deadline per round
set when the round opens, replacements never extend it; (b) adds a bounded response period after a successful
challenge, sized from P.

## 4. After a forged settlement (F2, D3)

*To write.* (a) terminal, stated; (b) keyless recovery anchored to a pre-forgery checkpoint. With 4.1 a forgery is a
majority event, which changes what (b) would have to prove.

## 5. Pricing as the second layer (F3, D4)

*To write.* Whether `requiredAttest(amount)` survives under 4.1 at all; table of F vs exit latency vs forger odds vs
our cost per proof, measured numbers only.

## 6. Inbound nonce continuity (F5)

*To write.* `require(nonce == last_nonce + 1)` for every journal entry above the cursor; skipped entries consume
their nonce; heartbeat unchanged; the `bridge-v6` test list.

## 7. Payouts (F6)

*To write.* Guest `tip < amount`; vault tracks paid-so-far per burn; each installment pays recipient and tip pro rata
of the new cumulative total; the dust rule; worked examples at the bucket edge.

## 8. Ordering (F7)

*To write.* Debit before `TOKEN.transfer` in `KaspaRelayV4._pay` and `UsdcVaultV3.release`; what a refused transfer
rolls back.

## 9. Pre-mainnet items

*To write.* cap0 $5k (the box's `u7.sh` has $500); `MIN_BURN = MIN_DEPOSIT`, compared on the burned amount;
artifact host any client can read; ~120M post-fork deploy gas and the budget for it; robot V3 event decoding and the
`proof-ok` beat-flag fix.

## 10. S1b measurement plan

*To write.* (1) level-30 superblock arrivals on the selected chain from our node, windows 30 min to 6 h, variance and
worst stretches, plus DAA rate drift; (2) Monte Carlo of the forger against 2.2 with first passage, calibrated by (1);
(3) the private simnet attack: two node groups, a controlled hashrate split, low `CMP_LEVEL`, relay on Anvil.

## 11. Decisions

*Filled when Oz decides.*

## 12. Questions for S2

*To write; one per rule, each for a fresh chat with this note attached.*

### 2.11 Burn-anchored ladder and the history reference (S1c, 2026-11-08; corrected by S2 the same day)

Supersedes 2.4 (the rate reference read from the checkpoint), the checkpoint K as the ladder anchor, the 3-hour
beat as the relay's liveness, the archival-node requirement, and F2 (checkpoint poisoning), which has nothing left
to poison. Measured on 124.8 h of the sbmeter record (2026-11-03 07:00 to 11-08 11:00 UTC, no gaps, 68,312 level-30
superblocks, q 0.9814); the tool is `tools/s1b/stale.py`, the raw reports `docs/s1b/stale*.txt`. Every number below
says measured or computed. Three points were corrected after the guest was built (2.12): the reading is a median,
not a maximum (2.11.3); the per-burn clock is softer than first written (2.11.6); S2 item 4 is answered (2.11.7).

#### 2.11.1 Why the checkpoint is not what makes a proof safe

Under 4.1 the burn payload carries a recent Ethereum block hash (the beacon). Every attesting superblock descends
from the chain block B that accepted the burn, so every attester was mined after the Ethereum moment of the beacon,
and the relay measures elapsed time tau on Ethereum's clock (the beacon header's timestamp against
`block.timestamp` at `submit`). A level-L superblock is 2^(31+L) expected hashes on any chain at any difficulty
(measured: realized level-30 per hour divided by hashrate x 3600 / 2^61 is 0.997). So "N attesters within tau of the
beacon" is a direct measurement of hashrate spent after the beacon, and it holds whatever chain the attesters sit on.

A forger can fork from wherever he likes. It does not help him: he must still produce alpha x r x tau worth of
real hashes after the beacon. Where his chain joins the honest one is irrelevant to the requirement. So the proof
does not need to begin at the last settled checkpoint, and nothing in the relay needs to chain from proof to proof.

What K used to supply, besides an anchor, was a trusted difficulty reading for r (2.4). That reading now comes
from the relay's own history of settled proofs (2.11.4). Nothing the new proof says about its own chain can lower
r; it can only raise it, and only by a majority of its own ladder (2.11.3).

#### 2.11.2 The rule

A proof settles when

    attesting >= max(F, alpha x r x tau)

with alpha = 0.5, F = 450, tau = seconds from the beacon block's timestamp to `block.timestamp` at `submit`, and
r = max(r_hist, r_own), in level-CMP_LEVEL superblocks per second, where

- r_hist is the largest stored reading whose settlement time is within SLOW_SPAN (7 days) of `block.timestamp`,
  or the newest stored reading if none is (2.11.4);
- r_own is the reading the proof carries about its own ladder (2.11.3).

No beta, no checkpoint, no candidate, no window, no deadline. One transaction: beacon check, verifier, settlement.
The amount term of F3 stays as the second layer where D4 keeps it.

Readings are compact targets (`bits`); the relay converts with `workOfBits` (hashes per block), the BPS constant
(10) and 2^(31+CMP_LEVEL). The measurement used realized blocks per minute instead of the constant; the hourly DAA
rate ran 9.41 to 11.18 per second (measured), so the constant costs the honest side at most 6% in a slow hour,
inside alpha's headroom.

#### 2.11.3 What the guest proves (outbound v4, `KZO5`, built in S2)

- The ladders are walked from T down to B, the chain block every burn's commitment chain ends at. Headers at or
  below B's daa are leaves: PoW-verified, not expanded, not counted. K, its daa, bits and blue work are gone from
  the witness and the journal. T must be at the top ladder level and after B. B need not be a superblock.
- The burns are checked first (their commitment chains must end at B's `accepted_id_merkle_root`), then the
  ladders; a wrong B is refused before any walk.
- Attesting is counted as v2: superblocks of level >= L on the walk whose first-parent path reaches, within 3 hops,
  a block whose commitment is on the chain from B. Membership is by commitment equality, not by block hash; a block
  whose commitment equals `c_i` was made after chain block i existed (the commitment is unpredictable before), so
  the timing bound holds through it. Twin commitments exist in practice (a non-chain sibling with the same selected
  parent, an empty mergeset and the same context); see 2.12.
- The anchor is as v3: the burn beacon with the highest Ethereum block number. All attesters follow B, B accepted
  every burn, and a burn cannot carry a future block hash, so every attester was mined after the freshest beacon
  and its tau is the tightest bound for every burn in the batch.
- **r_own, `r_bits` in the journal: the median compact target over the expanded superblocks, ordered by target.**
  A median and not a maximum. `bits` is a free field of a header as long as the hash is under its target, and a
  superblock's level is set by the hash alone, so a miner can stamp any difficulty up to 2^(31+level) hashes per
  block on his own level-30 superblock at no extra cost (a 64x reading at today's difficulty). With a maximum, one
  such superblock planted in an otherwise honest proof would settle a 64x reading and stall every honest exit for a
  week. The median moves only when more than half of the expanded superblocks are the forger's, which is more than
  half of the hashrate over the window. Unit test: 1 and 5 planted hard superblocks among 11 leave the reading;
  7 of 13 move it.
- The witness is headers from B forward only (about 1.5 h at F 450), so the pruning horizon no longer bounds
  anything. Journal: 290 bytes plus 68 per burn (layout in `relay.rs`).

#### 2.11.4 What the relay stores and checks

- Storage: `readings[]` of `(uint64 ethTime, uint32 bits)` (or the converted rate), appended on every settlement
  with `block.timestamp` and the settled proof's `r_bits`. The genesis entry is a recent header's bits, supplied at
  deployment. `points`, `slowRate`, `BETA_BPS`, `checkpoint`, `checkpointDaa` are removed.
- r_hist: the maximum among readings with `ethTime >= block.timestamp - SLOW_SPAN`; if there is none, the newest
  reading. The window runs on Ethereum's clock, so a forger cannot shrink it by choosing B.
- Beacon: each proof's anchor is checked through EIP-2935 (the last 8,191 blocks, about 27 h), as the 11-04 V4
  does; the header is parsed for its number and timestamp (measured 21,326 gas on Sepolia).
- Everything else of the 11-04 V4 stays: the bucket and refill, owed and permissionless `claim`, `MIN_BURN`,
  pro-rata installments, debit-before-transfer, the transient lock.

A forged settlement stores the forger's reading. A low reading cannot lower a 7-day maximum; a high one costs him a
majority of his own ladder (2.11.3). The newest-reading fallback is reached only after 7 days in which nothing but
forgeries settled, and a forger who has settled repeatedly has already taken what the caps allow. That is the whole
of F2 now.

#### 2.11.5 Measurements

Model: forger owns each real level-30 superblock with probability f (rides the real fluctuations), attesting
share 1, proving time 0, keeps an attempt going 6 h; alpha 0.5, F 450; 100 thinnings at starts every 5 min.
"age" is minutes from the last settlement to the burn. Honest: real attesting arrivals, delta 5 min, P = proving
minutes; "stuck" = no cut within 12 h. Forger cells are per attempt; 0 is below the age's resolution (9e-6 at age 0
and 180, 1e-5 at 1 d, 2e-5 at 2 d, 4e-5 at 3 d). Rows of different ages use different start sets (a 3-day age can
only be tested on the last 20 h of the record), so forger cells compare within a row, not down a column; the drift
line (r_now / r_hist over the row's starts) is the cross-age measure.

Honest exits were stuck in 0 of 60 cells below. Drift minimum over everything: 0.624 (the 11-05 dip against the
day before it); the honest stall line at alpha 0.5 is about 0.51.

**(a) r_hist = the 24 h difficulty-implied mean ending `age` before the burn, by beta** (`stale.txt`)

| age | beta | f=0.36 | f=0.40 | honest P36 med / max | honest P16 med / max |
|---|---|---|---|---|---|
| 0 | 0.8 | 7.6e-2 | 7.4e-1 | 92 / 118 | 72 / 98 |
| 0 | 0.9 | 4.7e-4 | 5.4e-2 | 92 / 130 | 72 / 98 |
| 0 | 1.0 | 0 | 3.9e-4 | 92 / 149 | 72 / 98 |
| 180 | 1.0 | 0 | 4.1e-4 | 92 / 153 | 72 / 98 |
| 1440 | 1.0 | 0 | 1.2e-5 | 92 / 153 | 72 / 100 |
| 2880 | 1.0 | 0 | 1.8e-5 | 92 / 102 | 72 / 80 |
| 4320 | 1.0 | 0 | 0 | 92 / 101 | 72 / 79 |

Age 0 and age 180 are indistinguishable: a 3-hour beat buys nothing over the stored history. beta 0.8 hands a 36%
miner 6 to 8% of attempts for a liveness benefit that never materialized. Drift max 1.12: the forger's remaining edge
is hashrate above the stored day-mean.

**(b) r_hist = the 24 h peak hour ending `age` before the burn, beta 1.0** (`stale-peak.txt`)

| age | f=0.33 | f=0.36 | f=0.40 | drift max | honest P36 med / max | honest P16 med / max |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 1.031 | 92 / 158 | 72 / 103 |
| 180 | 0 | 0 | 9.1e-6 | 1.046 | 92 / 158 | 72 / 103 |
| 1440 | 0 | 0 | 0 | 1.033 | 92 / 160 | 72 / 110 |
| 2880 | 0 | 0 | 0 | 1.001 | 92 / 106 | 72 / 80 |
| 4320 | 0 | 0 | 0 | 1.003 | 92 / 107 | 72 / 79 |

For comparison, 2.8's checkpoint design, max(r_fast at K 180 min old, 0.8 x 24 h), measured 3.8e-5 at alpha 0.5,
F 300, f 0.40. The peak reference at F 450 is at or below the resolution line at every age.

**(c) What the relay really has: r_hist = the max of 10-minute readings at the settlements of the previous
7 days, settlements every 3 h, 24 h or 72 h; beta 1.0** (`stale-c3.txt`, `stale-c24.txt`, `stale-c72.txt`)

| cadence | age | f=0.33 | f=0.36 | f=0.40 | drift max | honest P36 max | honest P16 max |
|---|---|---|---|---|---|---|---|
| 3 h | 0 to 4320 | 0 | 0 | 0 | 1.029 | 168 | 110 |
| 24 h | 0 | 0 | 0 | 0 | 1.000 | 158 | 102 |
| 24 h | 180 | 0 | 0 | 3.6e-5 | 1.092 | 150 | 98 |
| 24 h | 1440 | 0 | 0 | 0 | 1.041 | 158 | 102 |
| 24 h | 2880, 4320 | 0 | 0 | 0 | 1.043 | 105 | 80 |
| 72 h | 0 | 2.5e-3 | 8.3e-3 | 1.3e-2 | 1.000 | 118 | 98 |
| 72 h | 180 | 8.6e-3 | 1.6e-2 | 4.4e-2 | 1.592 | 149 | 98 |
| 72 h | 1440 | 5.4e-3 | 1.9e-2 | 5.2e-2 | 1.502 | 158 | 101 |
| 72 h | 2880 | 1.3e-2 | 2.0e-2 | 7.4e-2 | 1.500 | 103 | 80 |
| 72 h | 4320 | 0 | 0 | 3.7e-5 | 1.148 | 101 | 79 |

The 72 h rows are the trough-sample failure: a single reading taken in the 11-05 dip (263 PH/s against 375 after
it, plus 10-minute noise) gives the forger a bar 60% too low, and a third of the hashrate forges at the 1e-2 level.
With daily readings the 7-day maximum absorbs the dip; with 3-hourly readings the reference equals the
perfect-knowledge peak of (b). beta below 1.0 is worse in every row of every table and is dropped. The guest's
reading covers the whole ladder (about 1.5 h of superblocks), not a 10-minute point; it can only be less noisy.

**Honest cost.** Median exit is unchanged at 92 min (P 36) and 72 min (P 16), the same as the 11-04 K design at
F 450. The tail grows: P 36 max from 118 to about 160 to 168, P 16 max from 98 to 110. Faster proving (4.4) remains
a latency item, not a security item.

#### 2.11.6 Operating rules and liveness

- **Liveness is independent of the operator.** A burn after a month of silence settles. No archival node.
- **Safety degrades slowly with idle time.** The forger's margin is below measurement with a reading at least daily
  in the last 7 days; at one reading per 3 days a 40% miner reaches 1e-2 per attempt. The operating rule is one
  settlement per day. In use, the users' burns provide it. Idle, a maintenance burn of 0.01 token: one proof a day,
  $0.175 on a 3090 (measured) or $0.55 on a 4090, against $4.20 a day for the 3-hour beat. A missed day costs
  margin, never liveness.
- **The beacon clock, per proof, not per burn.** The anchor (the freshest beacon in the batch) must be inside
  EIP-2935's window at `submit` (about 27 h from its block). A burn whose own beacon has aged out is still settled
  by any proof that batches it with a fresher burn, the daily maintenance burn included, because every attester
  follows every burn in the batch (2.11.3). The page and the CLI build burns with a beacon at most 1 h old; the robot
  proves within 12 h of seeing a burn and mails at 18 h; and the daily maintenance burn is what rescues a burn that
  somehow waited longer. Stated in the README as a property, not an edge.
- **Kaspa hard forks** that change BPS, the header or the sequencing commitment stay exit deadlines (handoff
  section 5). Ethereum forks are a setting (2.10, `eth-net.json`; the Gloas mask in the inbound commitment,
  GLOAS-GUEST.md section 7, precedes any genesis).

#### 2.11.7 For S2, the attack pass (sprint 4)

1. A forger forking far below B: confirm the burn-acceptance commitment binds the burn to a chain descending from
   a block whose sequencing commitment the beacon predates, so no attester can be re-used from before the beacon.
2. The newest-reading fallback: confirm it is reachable only through 7 days of exclusively forged settlements, and
   state what that costs against the bucket and refill.
3. Batches: a burn with an old beacon riding in a batch whose newest beacon is fresh gets the fresh tau; confirm
   that is strictly more attestation for the old burn, never less, and that the batch's B accepts all of them.
4. The planted-superblock stall against r_own: answered in the build by the median (2.11.3). Confirm the remaining
   version: a forger with f of the ladder can shift the median only within the honest spread; bound the shift at
   f 0.45 from the measured spread of honest `bits` over a 1.5 h window.
5. Twin commitments (2.12): confirm a forger gains nothing from them beyond what a real chain block gives, and that
   a fabricated hash-only header carrying a chain commitment still binds its superblock's time to that commitment.

#### 2.11.8 Recommendation for D1

alpha 0.5, F 450, CMP_LEVEL 30, SLOW_SPAN 7 days, no beta, r = max(7-day maximum of stored readings, the proof's
own median reading), readings stored on every settlement, daily settlements as the operating rule. A forgery needs
more than half of Kaspa's hashrate whenever the true rate is at or below the last week's peak; F covers the variance
below that. Deployment: USDC.k #1 at cap0 $5,000 is the first and only instance of these contracts; the U5 list runs
against it with the operator's own dollars before the cap schedule moves (handoff 4.3). No testnet instance.

#### 2.11.9 Limits of the data

5.2 days from one node, one real dip (11-05, 25% for 4 h). The forger model gives the forger attesting share 1 and
zero proving time and lets him ride the real fluctuations. The resolution floor is about 1e-5 per 6-hour attempt;
per-year figures stay with the computed table in 2.8. The 7-day window has been exercised on at most 5 days of
history; the cron reaches 7 days of record on 2026-11-10 and the three cadence runs are repeated then, and again
before the pin. Nothing here was tested across a Kaspa hashrate rise larger than 33% in 24 h (the largest measured).

### 2.12 Guest v4 built and run on mainnet (S2, 2026-11-08)

Branch `guest-v4` (worktree `~/kaspa-zk/kz-guest-v4`, off `guest-v3` 17b2be5), applied as `s2-apply.py` and
`s2b-apply.py`. Changed: `outbound/kaspa-prover/primitives/src/relay.rs` (the program, `KZO5`), `host/src/witness.rs`
(formats 3 and 4), `host/src/main.rs`, `host/src/adversarial.rs`, `outbound/burnwitness/src/main.rs` (no K, walks to
B, writes format 4). Live services untouched (main tree, v2 images).

- **Tests:** primitives 23 of 23, two new (`synthetic_run_without_k_and_tip_must_follow_b`,
  `difficulty_reading_is_the_median_of_the_expanded_superblocks`). Adversarial suite 31 of 31 on the real witness
  below, two cases rewritten (`tip_below_top_level_or_at_b`, `difficulty_reading_matches_the_ladder`), the K cases
  removed.
- **Burn:** Kaspa mainnet txid `83167eff649d669f605bf1584b0fe001424df5129865a98ddfbe4aaa5bf2fcd9`, 0.01 Sepia.k
  from the beat key, target `0x…dead`, tip 0, payload v3 with beacon Sepolia block 12,090,822
  `0xd9dc38cc…91ed` (13:17:48 UTC). Accepted in C `bb82e3d1…` (daa 587,235,457); B is C (level 25).
- **Witness (format 4, the first):** `outbound/kaspa-prover/out-s2/witness.json`. T `c55d73ce…` (level 30, daa
  587,254,029), 31.0 min after B, 2,635 chain blocks; level 30: 284 counted, 274 attesting (hops 211/52/11, 8 join at
  hop 4), 1 leaf; 286 PoW headers, 322 first-parent headers. No K anywhere in it.
- **Guest in dev mode:** 327,638,396 user cycles, 345 segments, against 870,619,867 for the 11-04 K-anchored
  proof of a comparable window (the K-to-B stretch, 120 min of ladder, is no longer walked). Journal 358 bytes
  (290 + 68), sha256 `a5c6eadf007b2669ed7e8734acf35a917715abe38f48e33db104a9059c6cde1d`, equal to the native run.
  `r_bits 0x1a021416`, equal to an independent median over the 284 top-level superblocks; B's own bits 0x1a021250.
  Dev image id `090ea092…` (host build; the pin is the Docker build, sprint 5).
- **Findings.** (1) `bits` is free up to the hash, so the reading had to be a median (2.11.3); found by reading
  the PoW code while writing the patch, before any test. (2) Twin commitments: adding the 28 hop-4 path headers to
  the witness raised attesting 274 to 275, because one non-chain block among them carries a chain block's
  `accepted_id_merkle_root`; the guest's membership rule is commitment equality and that is the sound rule (the
  commitment is unpredictable before its chain block), so the test now tolerates it and S2 item 5 records it.
  (3) An old witness in which the relay's K sat after B (`witness-u5-thin.json`) has no ladder below K and fails the
  v4 closure check, as it should; v4 witnesses come from the v4 burnwitness only. (4) The burns' chain check moved
  ahead of the walks so a wrong B fails with its own message before any ladder work.
- **Cost of the sprint:** one burn (0.24 KAS fee, 0.2 KAS parked), no GPU.
- **Not in this sprint:** the relay contract (sprint 3 reads the `KZO5` layout, stores readings, drops `slowRate`
  and `BETA_BPS`), `relay-prove.mjs` and the robot's journal offsets (sprint 6), the Groth16 proof and the pin
  (sprint 5), `burnwitness --pick-genesis` printing a recent header's bits for the relay's first reading (sprint 3).

### 2.13 The contracts for the burn-anchored design, built and tested (S3, 2026-11-08)

Branch `guest-v4`, applied as `s3-apply.py`. New files beside the 11-04 set, which stays as the record of that
iteration: `usdc/src/KaspaRelayV5.sol`, `UsdcVaultV4.sol`, `RelayFactoryV3.sol`; `usdc/test/KaspaRelayV5.t.sol`,
`RelayFactoryV3.t.sol`, `KaspaRelayV5Fork.t.sol`; `bridge-v6/` (bridge-v5 with F5); `burnwitness --pick-k` prints
`GENESIS_BITS`. Not deployed. Decisions taken by Oz the same morning and built in: a 0.1% release fee to a fixed
address; a one-way deposit close held by one party; attestation priced per dollar (D4) as the second layer; no
address binding of exits, no automatic breaker, no sunset, no key that can touch a release.

#### 2.13.1 KaspaRelayV5

- **Journal `KZO5`** (2.11.3): offsets 4 T, 36 T.daa, 44 B, 76 B.daa, 84 r_bits, 92 n_levels, 93 levels, 165 target,
  185 token, 217 template, 249 anchor number, 257 anchor hash, 289 n_burns, 290 burns. No checkpoint state anywhere.
  A journal settles once (`seen[sha256(journal)]`); `T.daa > B.daa`; target, token and template as before.
- **The difficulty memory** (2.11.4): eight daily slots `(day, work)`, each holding the hardest reading settled on
  that UTC day, plus `lastWork`/`lastTime`, the newest reading. `historyWork(t)` is the maximum over slots with
  `day >= (t - SLOW_SPAN) / 1 day`, else `lastWork`. Sixteen storage reads, no loop over history. The constructor
  seeds it with `genesisBits`, a recent header's compact difficulty supplied at deployment (`burnwitness --pick-k`).
  Every settlement records the proof's `r_bits`; a day's slot keeps the harder of its readings.
- **The rule:** `requiredAttest(tau, rBits, amount) = max(FLOOR, ceil(alpha x max(historyWork, workOfBits(rBits)) x
  DAA_PER_SECOND x tau / 2^(31+CMP_LEVEL)), ceil(amount / ATTEST_UNIT))`. `ATTEST_UNIT` is mandatory (nonzero).
  `beta`, `slowRate`, `points`, `checkpoint`, `checkpointDaa`, `RATE0` and `DAA_PER_SECOND`-from-K are gone.
- **Settlement:** V4's (owed, installments pro rata, `claim`, `MIN_BURN`, `MIN_INSTALLMENT`, debit-first, the
  transient lock), unchanged.
- **Measured in the unit tests:** at the 11-04 difficulty (`0x1a020526`, 9.28 level-30 a minute) and alpha 0.5,
  F 450 binds until about 97 min after the beacon, then 557 at 2 h and 1,114 at 4 h, as 2.10 computed. A proof
  reading twice the difficulty needs 1,114 at 2 h and, once settled, so does everyone for 7 days; a later reading
  of a quarter lowers nothing; on day 9 the window is empty and the newest reading rules (557 again). `submit` with
  one burn: 457k gas against the mock verifier; the real router adds about 300k (2.10 computed ~540k for the round).

#### 2.13.2 UsdcVaultV4

- V3's deposits, cap schedule, `MAX_DEPOSIT`, bucket and `release` (F6, F7); storage slots 0 to 3 unchanged (the
  inbound guest reads 0 and 1); `depositsClosed` packs into slot 3, `feeOwed` is slot 4.
- **Fee:** `FEE_BPS` (10 for USDC.k #1) of the recipient's part of each installment, accrued in `feeOwed`; anyone
  calls `claimFees()` to move it to `FEE_ADDRESS`. Never paid inside a release: a blacklisted or non-receiving fee
  address refuses the sweep and nothing else (tested). A refused installment accrues no fee.
- **One-way close:** `closeDeposits(preimage)` with `sha256(preimage) == CLOSE_HASH`, once; afterwards `deposit`
  reverts and `room()` is 0; `release`, the bucket and `claim` are untouched (tested: a burn settles after the close).
  Whoever holds the preimage can only shrink the bridge.

#### 2.13.3 RelayFactoryV3

RelayFactoryV2's shape (two deployers, CREATE2, `predictVault`/`predictRelay`, `isInstance`) for the new pair.
Limits an instance cannot cross: `MAX_CAP0`, `MAX_CEILING` ($1M for #1), `MIN_DOUBLING`, `MIN_MIN_DEPOSIT`,
`MIN_FLOOR` (450), `MIN_ALPHA_BPS` (5,000), `MIN_SLOW_SPAN` (1 day), `MAX_ATTEST_UNIT` ($2.50: no instance may let one
attester vouch for more), `MAX_BUCKET_MAX` ($10k), `MAX_REFILL_PER_DAY` ($25k), `MAX_FEE_BPS` (10), and a close hash
must exist. The window and attest-floor limits of V2 are gone with the design they served. Predicted and deployed
addresses agree (tested).

#### 2.13.4 D4: the price of a dollar in attesters

A forger just above alpha spends about `required x 125 KAS` of forgone block rewards per proof (one level-30
superblock is ~2^61 hashes, ~6.6 s of the whole network, ~125 KAS of emission at the 11-04 schedule; computed from the
schedule, not measured). With the amount term, `required >= amount / ATTEST_UNIT`, so a forged release loses money
whenever `125 KAS x price(KAS) > ATTEST_UNIT`. Chosen for #1: **ATTEST_UNIT = $2.00** (2,000,000 base units):
2x margin at KAS = $0.032, break-even at $0.016. The honest cost, exits at alpha 0.5, F 450, 9.1 attesters a minute,
before ~15 min of proving:

| exit | $1 per attester | $2 (chosen) | $2.50 (factory maximum) |
|---|---|---|---|
| up to $900 | 50 min (F) | 50 min | 50 min |
| $1,000 | 1 h 50 | 55 min | 50 min |
| $2,500 | 4 h 35 | 2 h 17 | 1 h 50 |
| $5,000 | 9 h 10 | 4 h 35 | 3 h 40 |
| $10,000 (the bucket) | 18 h 20 | 9 h 10 | 7 h 20 |

The amount term is per proof (the batch's total), so the robot keeps large burns in batches of their own. The
constant is immutable; the question it answers is the KAS price below which forging becomes profitable, and $2 puts
that at half of today's. D4 is decided with this; D1 (alpha, F) stands from 2.11.8; D2 (round shape) and D3
(after a forgery) have no object left under 2.11 beyond the caps, which S2 (sprint 4) confirms.

#### 2.13.5 bridge-v6 (F5)

`bridge.sil`: `require(nonce == last_nonce + 1)` where v5 had `nonce > last_nonce`. Tested on the real Sepia.k proof
that minted deposit 2 on its own (`out-auto-sepia-2026-11-02T14-33-05-736Z`): at cursor 1 the advance passes
(15.59M script units, the v5 order of cost); at cursor 0 the same journal is refused at input 0 (`VerifyError`).
The 23 engine tests and 7 Tipsy tests of v5 pass unchanged on v6. The inbound service already submits `cursor + 1`
onward with skipped deposits carried as status 1, which is what the check requires; sprint 6 states it in the
service's own words. The instance's constants (the Gloas-masked inbound image id and its chain commitment) are
constructor arguments, set at genesis.

#### 2.13.6 Tests, all green on the box

`forge test`: KaspaRelayV5Test 29, RelayFactoryV3Test 3; the untouched V4/V3/V2 suites 6, 26, 23. `bridge-v6`:
23 + 7 + the F5 case. The fork test (`KaspaRelayV5ForkTest`, the real EIP-2935 contract and a real header) runs with
the 11-04 environment variables and the V5 name; it now also prints `requiredAttest` gas with the 8-slot memory.
Three test-side mistakes were fixed on the box the same hour (two `expectRevert` armed on a view call in the
argument list, one `room` assertion at cap0); the contracts did not change after the pack.

#### 2.13.7 What sprint 3 leaves to the next ones

- Sprint 4 (S2, the attack pass) on this code: 2.11.7's five items, plus the fee and close paths.
- Sprint 5: Docker builds of both guests (`161f4b6c…`'s successor with the mask; the outbound v4), Groth16 proofs,
  clean-box reproduction, the image ids into `RelayFactoryV3`'s constructor.
- Sprint 6: `relay-prove.mjs` and the robot read `KZO5` (offsets above), submit `(seal, journal, headerRlp)` to V5,
  check `requiredAttest` before renting a GPU, keep big burns in their own batches, the daily maintenance burn, the
  12 h prove rule and 18 h alarm; the inbound service on `bridge-v6`; the page shows the exit-size table as the
  expected wait.
- Sprint 7: `u8.sh` (from `u7.sh`): `factory` with the limits above, `predict`, genesis with `--max-mint`, the close
  hash from a preimage written in two places, the fee address, `GENESIS_BITS` from `burnwitness --pick-k`.

### 2.14 After the outside review: KZO6 (S2b, S3b, 2026-11-08)

Branch `guest-v4`, commit `86bb869`, applied as `s4/s4-apply.py` and `s4/s4b-apply.py` over 2.12 and 2.13. The
review (`docs/REVIEW-2026-11-08.md`, two models, ten questions) left the design of 2.11 standing and found five
things to fix before the pin, F15 to F19; this is their record. The measurements of 2.11.6 to 2.11.8 are untouched.

#### 2.14.1 The guest: the reading is over the attesters, the prover is named

- **F15.** `r_bits` was the median compact target over everything the walks expanded. A forger can premine level-30
  superblocks at leisure, stamp any `daa_score` above a future B and any `bits` up to 64x the difficulty, and list
  them as level-30 parents of his T beside the honest ladder: the guest checks parsing and proof of work, not
  consensus, so they are expanded and counted. They cannot attest (nothing on their first-parent path reaches the
  commitment chain, which embeds the beacon), but they move a median over the expanded set once they outnumber the
  honest ones. Cost of a 1.5x reference for a week: about 456 premined superblocks, ~57k KAS of forgone emission;
  1.9x at six hours for ~394k KAS. No theft and no lowering, a repeatable stall lever. **Now `median_bits` runs over
  the attesting superblocks.** An attester was mined after the beacon, so it cannot be premined; the forger's share of
  attesters over the window is `h / (0.981 + h)`, and the median moves only past one half: hashrate above 98%. His
  own-ladder proof can carry any reading but has to meet `alpha x k x r x tau` with his own post-beacon blocks, so
  `k <= 2h`, no inflation below half the hashrate, and a low reading is absorbed by `max(history, own)`. With this,
  nothing the relay reads depends on a non-attesting header; `count` stays in the journal as information.
- **A witness without attesters is refused** ("no attesting superblock to read the difficulty from"). Before, such
  a witness produced a journal with `attesting 0` that the contract refused; the two adversarial cases that relied
  on that (`forged_b`, `no_attestation`) now expect the guest's refusal, and `forged_b` no longer writes a journal.
- **F16.** The witness carries the prover's Ethereum address and the journal copies it; a zero address is refused.
  The relay pays the proof's tips to that address, not to `msg.sender`, so a proof copied from the public mempool
  settles for the prover who made it and earns the copier nothing. `relay --prover 0x…` is required on the host;
  the address is not witness data (burnwitness is unchanged).
- **Journal `KZO6`**, 310 + 68 n bytes: as 2.13.1 up to the anchor hash, then prover (20) at 289, n_burns at 309,
  burns at 310. Input frame `KZO6`: the prover (20 bytes) follows `token_cov_id`. Witness file formats 3 and 4 still
  load.

#### 2.14.2 The contracts

- **KaspaRelayV5** reads `KZO6` (`MAGIC 0x4b5a4f36`, `HEADER_LEN 310`), requires a non-zero prover, and records
  `submitter: prover` from the journal; `Owed` names the prover; `Settled` keeps `msg.sender`. Everything else of
  2.13.1 stands.
- **UsdcVaultV4.release** (F18): when the recipient's transfer went through and the tip's did not (a blacklisted
  prover), the tip now accrues to `feeOwed` instead of staying in the vault counted nowhere. Invariant, tested:
  `balance == outstanding + feeOwed` after every release, and `== outstanding` after a sweep.
- **RelayFactoryV3** (F17): `checkRelay` requires `minInstallment != 0`; `create` requires
  `minInstallment <= bucketMax`, since an installment floor above the bucket would defer every burn larger than the
  bucket for good (`p < remaining && p < MIN_INSTALLMENT` with `p <= avail <= bucketMax`). USDC.k #1 uses $1.
- **F19** is a deploy parameter, not code: `Limits.maxAttestUnit` is $2.00 in the tests and goes into `u8.sh` as
  2,000,000, so no instance may run a thinner margin than #1 (break-even KAS $0.016; $2.50 would have been $0.02).

#### 2.14.3 Tests, all green on the box

- primitives: 23 (the median test now plants 7 and 40 premined, non-attesting hard superblocks and asserts the
  reading does not move, then attesting ones: 1 of 5 and 4 of 8 leave it, 5 of 9 move it; the journal round trip
  and the synthetic run check the prover at 289 and `n_burns` at 309; a zero prover is refused).
- adversarial, on the real format-4 witness of burn `83167eff…` (B `bb82e3d1…`, T `c55d73ce…`): 31 native, and
  the same 31 with `RELAY_ZKVM=1` in 246 s, every accepted case's zkVM journal byte-equal to the native one.
- forge: KaspaRelayV5Test 32 (three new: the tip goes to the journal's prover and a front-runner earns nothing; a
  zero prover is refused; a refused tip accrues to the fees and nothing is stranded), RelayFactoryV3Test 4 (one new:
  the installment floor against the bucket, both directions, and the deployed constants), the untouched V4/V3 suites.
- the real witness natively: 284 counted, 274 attesting (96.5%), journal 378 bytes, prover in it; `r_bits` over the
  274 (2.12's reading was over the 284; the two agree to the honest spread, as 2.14.1 predicts for an honest ladder).

#### 2.14.4 What this changes downstream

- Sprint 5 pins this commit's guest, not 2.12's: the image id of `guest-v4` at `86bb869`.
- Sprint 6: `relay-prove.mjs` passes `--prover <robot address>`; `relay-robot.mjs` and the page read the `KZO6`
  offsets (2.14.1), decode `Owed`'s submitter as the prover; `u8.sh` sets `maxAttestUnit 2_000_000` and
  `minInstallment 1_000_000`.
- README: the tip is paid to the prover the proof names, pro rata of each installment, best-effort (a refused tip goes
  to the fee address); the D4 statement with its KAS-price assumption ($0.016); the deposit's Kaspa address is
  final; the reference after a silence longer than SLOW_SPAN is the newest reading, which the maintenance burn
  keeps from mattering.
- 2.11.3 and 2.13.1 read "over the expanded superblocks" and "290 + 68 n"; this section supersedes both.

### 2.15 The pin (sprint 5, 2026-11-12)

Both guests built reproducibly, one real Groth16 proof of the outbound guest, the mainnet chain commitment computed
with the masked function. These are the constructor inputs of USDC.k #1 (2.15.5). Every number below has a command
output behind it on the node box (`~/pin/`), the clean box `vmi3019233` (`~/pin/`), or the proof bundle
`outbound/kaspa-prover/out-s2b-pin/`.

#### 2.15.1 Method

The recipe of U3, U4 and O5: `git archive --format=tar <commit> <crate dir>` into an empty directory, then
`docker buildx build -f docker/Dockerfile.cuda --target ids --output type=local,dest=.`; on the node box with its warm
cache mounts, on the clean box with a freshly created `docker-container` builder (empty cache mounts) and `--no-cache`.
The archive stream's sha256 is recorded so the two machines are known to have built the same bytes. The tracked
`IMAGE_IDS.txt` of `outbound/kaspa-prover` was the v2 file (`59cdd3c`) and sits in the Docker context, so a failed
ids build would have left a wrong file in place; ids are read from the log's `#12` lines and the file must agree.
The file is replaced in this record commit (it is not in the guest and does not move the id).

| guest | commit, branch | archive | files | image id (node box ids stage) | clean box `vmi3019233` |
|---|---|---|---|---|---|
| inbound `eth-bridge-guest` (mainnet spec), the Gloas epoch masked (GLOAS-GUEST 7) | `0fa57ca`, `inbound-mask` | `git archive 0fa57ca eth-prover`, tar sha256 `8845efc2eb257b407612d88d5282bde34c9bbad43deb3d90f4224d3db5027166` | 80 | **`45400f5f582380ce9919fbc5bf94f83d19e2b9aa9f5b2043030cb69b37587fd6`** (minimal spec `2904cc0d84fa96b73356b8b9b3b72095fd149937f381e7a1cc8fc866d0c1e22a`, unused) | **equal** (`45400f5f…7fd6`; fresh builder `pin-eth`, `--no-cache`, both clean-box builds run in parallel, about 3.5 h) |
| outbound `kaspa-relay-guest` (`KZO6`, 2.14) | `86bb869`, `guest-v4` (worktree HEAD `06658b6`; `git diff 86bb869 HEAD -- outbound/kaspa-prover` empty) | `git archive 86bb869 outbound/kaspa-prover`, tar sha256 `5ae0e51f56ee5e3884342c1b14a57b41e8977725876f8ea92733e9f3322bffff` | 113 | **`1b86827695b06ef38f4e31a36b995b52011fad678e9fc856e637163dc804dbb1`** (header guest `c61fd96588598d7f9b2a16aae765932ea3648177f42ddb167370f18f7d9a97f2`, unchanged since the v2 pin: the same toolchain reproducing an untouched guest) | **equal** (`1b868276…dbb1`; fresh builder `pin-kaspa`, `--no-cache`, in parallel with the eth-prover build) |

Native (host-built) ids seen this week and never pinned: inbound `88e8d020…`, outbound `e9b1550a…`.

GPU images, pushed 2026-11-12 from the same archives (the build stage is shared with the ids stage), to be used by
digest: `kasperolabs/eth-prover@sha256:42e598d102cddf9fb1603d46475940a33cfe3d76c183e77fc4ee0bf4c1fc8882` (tag
`cuda-v4`) and `kasperolabs/kaspa-prover@sha256:d034995ff605ecceb535eb86b43a1101f298c54eb92a7ff77b8983ba4e159f92`
(tag `cuda-v4`). The pod's `image_id.hex` in 2.15.4 is the proof that the pushed kaspa-prover image carries the
pinned guest.

Pin gates of GLOAS-GUEST 6, as they stand: the clean-box reproduction is the gate this record closes; the mainnet
Gloas epoch no longer matters (7, and 2.15.3); "client releases announced and the light-client spec unchanged since
Sepolia" cannot be met before a mainnet date exists and is no longer a gate (decision 2026-11-08: a fork is a prover
setting). The residual is stated for the README: a change to the Gloas light-client format before mainnet activation
would end deposits on #1 at the fork (exits continue), the same clause as any fork.

#### 2.15.2 The epoch-shift test on the Docker-built inbound guest

The runtime image's `eth-prover` needs `libcuda.so.1` and cannot run on a box without a driver. The `ids-run` stage
compiles a CPU-only host from the same source in the same container; a Dockerfile kept outside the context
(`~/pin/Dockerfile.eth-cpu`, two `sed` edits of `Dockerfile.cuda`, grep-checked) exports it, with the archive as the
unchanged context (every layer a cache hit). That binary's `ids` prints `45400f5f…` and `2904cc0d…`: it carries the
Docker-built guest. `examples/shift_epoch` (host-built) rewrites the Gloas epoch inside an existing `inputs.cbor`;
each variant is executed in dev mode by the CPU Docker binary and its decoded journal compared with the true run's.

| input | shifts giving the identical journal (exit 0) | refused (exit 1, guest panic at `src/lib.rs:79`) | commitment |
|---|---|---|---|
| `out-sepia-genesis` (slot 11,490,656 to 11,490,848, 55,945,846 user cycles) | 0, +1, -1, +10, -10, +1000, -1000, -353024 (epoch 0; 25 cycles fewer, the shorter encoding) | +10000, +100000 | `0xd6636d14d7e3fca287c87f43270a0c2ca626ccf7085ae8b60f6ae214139cfeb0` |
| `out-sepia-dep1` (one deposit, Gloas witness, 58,989,187 user cycles) | 0, -353024 | +10000, +100000 | the same |

Identical to GLOAS-GUEST 7's table for the host-built guest. The 24-rotation crossing input of GLOAS-GUEST 4 was not
kept on disk (7); the fork-crossing line of the record stays as measured on 11-02 for the unmasked guest, the mask
touching only the commitment hash.

#### 2.15.3 The mainnet chain commitment

`eth-prover fetch --network mainnet` with the CPU Docker binary, from the Wobbly.k service's own checkpoint and
endpoints, vault `0x721c6A3C273b965c85418B9A0C91c379F0981bC5`, token `0x6C2b23D88982B8D1793799cb17E6520A7b8fa08D`,
`--nonce 14` (the current cursor; `--vault` needs at least one nonce). Checkpoint `0x8bfdefef…5ff2bf` (slot
15,599,808, period 1904) to finalized `0xdc46f5bb…16f108` (slot 15,638,496, signed in period 1909), 5 sync committee
updates (periods 1904 to 1908), participation 483/512, exec point block 26,398,817, state root `0xc59fe29f…7d96fc`;
deposit 14 (1,000,000,000 units, depositor `…229105`, mint) proven again as the payload. Dev-mode execute:
315,540,677 user cycles, 321 segments, 7.9 s, journal 320 bytes.

**`chain_commitment = 0xffc6300b0673ffdeaa10b11d162bc7bc375514c89e29dd03dc6eeabd88b0c90b`**, the value every live
mainnet covenant already records (KBT, Wobbly.k): helios 0.12 carries mainnet's unknown Gloas epoch as `u64::MAX`,
which is the constant the mask writes, so on mainnet the mask changes nothing, and on Sepolia (a real epoch) it moved
the commitment from `…67d95c` to `…9cfeb0` (7). A USDC.k #1 covenant therefore records the same commitment as
Wobbly.k's with a different image id. Inputs and log in `~/pin/mainnet-fetch/` on the node box (not in the library).

#### 2.15.4 One real Groth16 proof of the outbound guest

Witness `out-s2/witness.json` (format 4): mainnet burn `83167eff649d669f605bf1584b0fe001424df5129865a98ddfbe4aaa5bf2fcd9`
(Sepia.k token `13af6019…ad58d`, 10,000 units, tip 0, recipient `…229105`, target `…dead`), B `bb82e3d1…c4e1ec`
(daa 587,235,457), T `c55d73ce…9972d1` (daa 587,254,029), 600 headers, 284 counted / 274 attesting at level 30
(96.5%), `r_bits 0x1a0213ff`. Input frame `KZO6` rebuilt with the robot's real address (`relay --native-only
--prover`), `out-s2b/input.bin` 4,623,016 bytes, sha256 `415c81a6956714d6365de147b43de24709635069ca3340f473dabb50509650c6`
(the `0x…0b0b` frame kept as `input-0b0b.bin`). Every native check row `ok` against the node (tx id, activity digest,
context hash, lane tip, lanes root, seq_commit C and B).

| step | measured |
|---|---|
| dev-mode execute (host, `RISC0_DEV_MODE=1 relay`) | **327,595,013 user cycles, 361,758,720 padded, 345 segments**, 1,145,437 user cycles per PoW header; journal 378 bytes, sha256 `e39df528…62958a`, equal to the native run |
| pod (`relay-prove.mjs --input … --image <digest>`) | `hkef8mzkkdv79v`, RTX 4090, US-NC-1, $0.89/h; IP after 89 s, SSH after 91 s |
| STARK | **519.1 s** (1.58 s per million user cycles); pod total 622 s |
| wrap (node box, r0vm 3.0.4 + Docker) | 71.1 s, receipt 795 bytes |
| total, cost | 694 s, **$0.154** |
| `image_id.hex` from the pod | `1b86827695b06ef38f4e31a36b995b52011fad678e9fc856e637163dc804dbb1` = the ids stage |
| journal | `KZO6`, 378 bytes, sha256 **`e39df528b23d883f401ba499301dd70f0b7816bed8234af4f97fba1bec62958a`**; prover `0x889a450BA0e4B740Cd901b3Ae88bC08D33552BeE` |
| `verify` (v4 host) | Groth16 receipt ok; control root `a54dc85a…8c1f56`, bn254 control id `c07a6514…6e4404`, verifier parameters `73c457ba…c6eedc` (risc0 3.0.4 defaults), selector `0x73c457ba`, claim digest `cb22c701…2111d0` |
| `receipt.hex` | 1,590 hex chars, sha256 `f911878df56c9f90cfac4667f4ee2faf4af0d7e0a82edc2fc1a11022d35beb35`; `eth-seal.hex` 520 chars |

Bundle: `outbound/kaspa-prover/out-s2b-pin/` (`record.json`, `prove.log`, `wrap.log`, `verify.log`, `timing.txt`,
`receipt.succinct.bin` 223,982 bytes). `relay-prove.mjs` with `--input` skips the dev-mode execute, so the cycles are
the by-hand run above; `verify` ran by hand too (the script's `done` followed `wrap-ok` by 8 ms). The GPU was the
script's default list (4090 first); the 3090-first order is sprint 6 work. The seal, journal and the burn's beacon
make this receipt the input of sprint 6's fork test: `KaspaRelayV5` with the real RISC Zero router on a mainnet fork
pinned within 8,191 blocks of the beacon the burn names.

#### 2.15.5 Constructor inputs for sprint 7

| where | constant | value |
|---|---|---|
| `RelayFactoryV3` Params, Ethereum mainnet | outbound image id | `0x1b86827695b06ef38f4e31a36b995b52011fad678e9fc856e637163dc804dbb1` |
| `bridge-v6` genesis, Kaspa mainnet | inbound image id | `0x45400f5f582380ce9919fbc5bf94f83d19e2b9aa9f5b2043030cb69b37587fd6` |
| `bridge-v6` genesis | chain commitment | `0xffc6300b0673ffdeaa10b11d162bc7bc375514c89e29dd03dc6eeabd88b0c90b` |
| services | GPU images | `kasperolabs/eth-prover@sha256:42e598d1…8882`, `kasperolabs/kaspa-prover@sha256:d034995f…9f92` |
| robot (`relay --prover`, the tips' recipient) | Ethereum address | `0x889a450BA0e4B740Cd901b3Ae88bC08D33552BeE` (key `eth-robot-key.txt`, repo root, 600, gitignored; made 2026-11-12, unfunded) |

Nothing in `eth-prover/` or `outbound/kaspa-prover/{primitives,methods}` changes again without a new id and a new
instance.

#### 2.15.6 Found on the way

- `set -e` pasted into an interactive shell exits the shell on the first failing command (two logouts on the clean
  box). Same rule as `exit`: never in a pasted block. Handoff section 7.
- A trailing `&` after an `&&` chain backgrounds the whole chain; `git diff` then stops on its pager. Background only
  the long command, in its own `( … & )`, and `--no-pager` for git in blocks.
- `cast wallet new --json` field names were not what was assumed; the robot key was made by a walker over the JSON
  that prints nothing but the address.
- `outbound/kaspa-prover/IMAGE_IDS.txt` tracked since `59cdd3c` held the v2 ids; replaced here, and so was `eth-prover/IMAGE_IDS.txt` (the `161f4b6c…` ids); both now hold the Docker ids of this
  record.
- The clean box dropped SSH twice under the cold CUDA build; the `nohup` builds were unaffected.
- The node box has no key to the clean box (keys only, no passwords); archives travel by hand.

### 2.16 Sprint 6: the services and the page on V5, and the loop closed on a fork (2026-11-12)

Branch `guest-v4`, worktree `~/kaspa-zk/kz-guest-v4`, on top of 2.15's pin. Three packs (`s6a`: the robot, `relay-prove.mjs`,
`src/runpod.js`; `s6b`: the inbound service; `s6c`: the page, the status job, `docs/TERMS.md`, the instance entries) and
two new files (`usdc/test/KaspaRelayV5RealSeal.t.sol`, `usdc/script/fork-v5.sh`). Every number below has a log line
behind it on the node box (`relay-robot-f.log.jsonl`, `relay-prove.log.jsonl`, `fork-v5.log`, the forge output,
`docs/s1b/stale-2026-11-12.txt`). The pinned ids did not move.

#### 2.16.1 The real seal through the real router (done criterion 1)

The s2b proof's burn `83167eff…` is a Sepia.k burn, so its beacon is a **Sepolia** block (12,090,822, 2026-11-08
13:17:48 UTC, hash `0xd9dc38cc…91ed`); mainnet's block 12,090,822 is from 2021. The fork is therefore Sepolia, pinned
at 12,091,022 (42 min after the beacon, inside the 8,191-block window), anvil at 127.0.0.1:8545, and the verifier is
Sepolia's real `RiscZeroVerifierRouter` `0x925d8331…9187` (the one the live Sepia.k relay verified real proofs through
on 11-02). Real proof, real router, real EIP-2935 read; the chain is the one the proof names.

Two facts of the proof force two test parameters, both deploy parameters, not code: the s2b ladder has 274 attesters
and #1's F is 450 (`submit` requires `attesting >= max(FLOOR, alpha x r x tau, amount / UNIT)`), so the test relay has
F 250; the burn is 10,000 units and #1's `MIN_BURN` is $10, so the test relay's `MIN_BURN` is 10,000. The journal's
target is `0x…dEaD` (`submit` requires `target == address(this)`), so the relay's code is etched at that address with
its memory slots copied and the vault told that address. Everything else is #1's: alpha 0.5, `ATTEST_UNIT` $2, 7 days,
fee 10 bps, cap0 $5,000, bucket $10k, the pinned image id, Sepia.k's token (the depositor funded with `deal`).

| step | measured (`forge test --match-contract KaspaRelayV5RealSealTest`, fork block 12,091,022, time 1794146436) |
|---|---|
| `beaconTime` through the real history contract and the header RLP | 1794143868; tau 2,580 s |
| `requiredAttest(2580, 0x1a0213ff, 10000)` | 250 at the test floor; the alpha term alone 194 (F 450 would have refused this proof) |
| a tampered seal (last byte flipped) | every relay gate passes, the router reverts with `0x439cc0cd` (`VerificationFailed()`) |
| a wrong header for the right anchor | `relay: header is not the beacon block` |
| the real `submit(seal, journal, rlp)` | **541,418 gas**; `Owed(txId, …229105, 10000, 0, prover 0x889a…2BeE)`, vault `Released(…, fee 10, tipPaid)`, `PaidInFull`; recipient +9,990 units, `feeOwed` 10, `outstanding` down 10,000, `settled(txId)` and `seen(sha256(journal))` true |
| the same journal again | `relay: journal already settled` |

There is no `finalize` in V5: `submit` verifies, records and pays in one transaction (2.13.1); the done criterion's
"finalize" is that same call. 2.13.1's estimate for the round with the real router was ~540k.

Anvil keeps the history contract current (a block anvil mined is readable by number through EIP-2935) and its clock
runs from the fork block's time plus wall time, so the robot on a fork behaves as on a live chain; the one setting is
`evm_setNextBlockTimestamp` once after a fork from head minus 32, and `--block-time 12` so the head moves.

#### 2.16.2 The fork instance (`usdc/script/fork-v5.sh`, the factory half of sprint 7's `u8.sh`)

Sepolia fork at the head (12,120,053 minus 32), `RelayFactoryV3` with 2.13.3's limits (`maxAttestUnit` 2,000,000,
`maxFeeBps` 10, `minFloor` 450), `create` with #1's numbers, Sepia.k's token `0x7da68ffb…686c`, covenant id
`13af6019…`, template `9703112e…`, `GENESIS_BITS 0x1a0214d1` (the sink header's compact bits through the SDK;
`burnwitness --pick-k` prints no bits line in this build), the real router. Factory `0x1eE0c106…50ec`, vault
`0xAF93541A…a21C`, relay `0x227A45a8…e57B`, predicted = deployed, `instance #1`; the deployer's 5,000 Sepia.k deposited.
`create` cost **31,967,347 gas** on this chain: Sepolia is post-Glamsterdam, where contract creation costs 6 to 7x
(handoff section 5); it is not mainnet's figure today, it is mainnet's figure the day it forks.

#### 2.16.3 The robot end to end (done criterion 2), with the real router, not the mock

`bin/relay-robot.mjs --name f --env usdc/fork.env --maintenance-hours 0.01` against the fork; Kaspa mainnet; the burn
from `sepia-key.json` through `bin/bridge-v5.mjs burn --beacon anvil`.

| step | measured |
|---|---|
| maintenance burn | `d2ef66c6…b05d`, 0.01 Sepia.k, tip 0, payload v3, beacon = anvil block 12,120,222 (17:13:48 UTC, 2.3 min old when seen), fee 0.232 KAS; made because the relay's reading was 0.49 h old against a 0.01 h test interval |
| scan, beacon check | `burn-seen` 60 s later (`payloadVersion 3`, `maintenance true`), `burn-beacon-ok` (hash at that number on the fork, time read) |
| floors | `waiting-for-floors`: needed 450 (F; the amount term 1), depth 32,685 DAA after B, 53 min to go, tau at landing 94 min |
| first witness, 18:12 UTC | 502 counted, 496 attesting, 504 headers, 4 s; `relay-prove --execute-only`: 615,020,028 user cycles, 649 segments (1.22M per header); `gate-ok` required 450 |
| first pod | 4090, US-IL-1: no public IP in 420 s, recycled (O4 rule), `cycle-failed`, 5 min backoff |
| second witness, 18:25 UTC | the clock had moved the requirement off the floor: needed 548, 584 counted, **578 attesting**, 586 headers; 705,729,719 cycles, 746 segments; `gate-ok` **required 515** at tau 114 min (0.5 x 9.0/min x 114) |
| second pod | 4090, US-NC-1, SSH after 120 s; STARK **1,151.4 s (1.632 s per million cycles)**; wrap 77.4 s; `verify-ok` image `1b868276…`, selector `0x73c457ba`, control root `a54dc85a…`; pod $0.318 |
| submit | `0x622cf6bd…9699`, fork block 12,120,693, **561,578 gas**, status 1, two events: `Settled` and `Skipped(below MIN_BURN)` (the 0.01 is below $10 by design); `lastTime` = the block's time; `seen(journal)` true |

No 3090 was free in RunPod's secure cloud for either pod; the list fell through to the 4090 as designed. The dead host
cost 7 minutes and 73 attesters of requirement (4.5 a minute while the ladder gains 9), which the re-witness covered
without a decision from anyone: that is 2.11's clock doing what it is for.

Four defects found by the run and fixed in the packs: `SIGS` declared with `let` below the main loop (the loop never
returns, so the first receipt decode hit the temporal dead zone; the `WaitError` class of patch 2 item 15; now `var`);
a failed maintenance burn locked the next attempt out for 2 h (now 10 min after a failure, 2 h after a success); the
driver path in the env file could not be absolute (`join` instead of `resolve`); `relay-prove.mjs` read `eth-seal.hex`
after `wrap`, but `verify` is what writes it (the robot checks after the whole run; only the log line was wrong).

#### 2.16.4 What the packs change (criteria 3 to 6)

- `src/runpod.js`: `GPUS` 3090 first; a 404 on a pod DELETE counts as deleted; `runpodBalance()`; the seconds-per-
  million table (4090 1.58 measured, 1.63 this run; the others set conservative) for the gate.
- `bin/relay-prove.mjs`: `--prover` required with `--witness`; the dev-mode execute runs on the frame
  (`RISC0_DEV_MODE=1 prove --input`, 8 s for 327M cycles), so it runs for `--input` too; `--execute-only` and
  `--input … --no-execute` split the run around the gate; `verify-ok` its own step; `--gpus`; the image by digest.
- `bin/relay-robot.mjs` (the V5 machine; state file v2, refuses the old): no checkpoint, candidate, finalize or
  defender. Scan reads v2 and v3 payloads and checks every v3 beacon against the relay's chain; the batch is led by
  the freshest good beacon and a rider must sit below it (the guest's anchor is the highest number, `pick_anchor`, so a
  bad or future beacon above the lead would sink the proof); the gate reads `requiredAttest(tau, r_bits, amount)` from
  the relay with tau = beacon age + the frame's proving time on the slowest listed GPU + margin, and rents nothing it
  would not settle; big burns alone (amount / UNIT > F); `submit(seal, journal, headerRlp)` after a free call with the
  revert reasons sorted (already settled, not enough attestation = deeper ladder, outside the window = rescue burn);
  `Owed`/`Paid`/`PaidInFull`/`Deferred`/`Skipped`/`Capped` and the vault's `Released`/`Refused` decoded; `claim` on owed
  burns when the bucket allows; the maintenance burn when `lastTime` is older than 24 h or as the rescue; 12 h prove
  rule, 18 h mail, RunPod balance every 6 h ($5 alarm), renting halted after 3 pod-delete failures until
  `--resume-pods`; `/ingest` after the maintenance burn.
- `bin/bridge-prover-v5.mjs`: v5 or v6 state; the driver `bin/bridge-v5.mjs` for both (`bridge-v6/` holds the four
  programs; how the tool selects `bridge-v6/bridge.sil` is sprint 7's question); the nonces asserted `cursor + 1`
  onward and contiguous before every cycle (F5 in the service's words); the GPU image by the covenant's image id from
  a pinned digest table, tags refused; the host binary's `ids` checked against the covenant's image id at start
  (`~/pin/eth-cpu/eth-prover-cpu` prints `45400f5f…`; the `kz-inbound-mask` host prints its native id and would be
  refused), so `ETH_PROVER_BIN=/root/pin/eth-cpu/eth-prover-cpu` is #1's setting; the masked Sepolia commitment
  `d6636d14…9cfeb0` known; `/ingest` after every advance.
- The page (`bridge-web`, instance flag `"v5": true`; Wobbly.k untouched): the status job reads the relay's constants
  and memory, the level-30 rate they imply, the vault's constants, a beacon (head minus 3) and the V5 robot's state;
  every burn the page builds carries the beacon (payload v3; refused when the status's beacon is older than 10 min),
  shown decoded in the intent with its age; a burn below the relay's `MIN_BURN` is refused with the reason; the quote
  is the expected wait for the amount (no tip floor); the exit-size table under Details; `/about` renders
  `docs/TERMS.md` with every figure read from the contracts (`/api/terms` gives the filled markdown for the README);
  the progress panel reads the V5 stages (owed = installments). Instances `usdck` (mainnet, `FILL` until deploy day)
  and `usdck-fork`; a second page on 8788 against the fork, checked: quote, about, status.

The exit-size table as the page now computes it from the fork relay (9.01 level-30 a minute at reading `0x1a0214d1`,
1.2M user cycles per attester from this run, 1.9 s per million, the robot's 15% depth margin, 7 min of pod overhead):

| exit up to | attesters | Kaspa work | proof | expected |
|---|---|---|---|---|
| $900 | 450 | 58 min | 24 min | about 1 h 25 |
| $1,000 | 500 | 65 min | 26 min | about 1 h 30 |
| $2,500 | 1,250 | 2 h 41 | 55 min | about 3 h 35 |
| $5,000 | 2,500 | 5 h 20 | 1 h 43 | about 7 h |
| $10,000 | 5,000 | 10 h 39 | 3 h 20 | about 14 h |

2.13.4's table counted the ladder and put the proof at "about 15 min"; the proof grows with the ladder (1.2M cycles
per attester), so the honest waits are the ones above. The terms text says "about an hour and a half" for small exits.
The measured run: 1 h 42 from the burn to the settlement, with a dead pod in it.

#### 2.16.5 The cadence reruns (criterion 7), `docs/s1b/stale-2026-11-12.txt`

Record 226.8 h (2026-11-03 to 11-12), 121,723 level-30 superblocks (8.95 a minute), **q 0.9812** (11-08: 124.8 h,
68,312, 9.12 a minute, q 0.9814). Cadence 24 h (one reading a day, what the relay really has with the maintenance
burn), alpha 0.5, F 450: forger odds per attempt at a third of the hashrate 1.7e-4 or below at beta 0.8 and 0 at beta
1.0 (V5 keeps the hardest reading of the week, the beta 1.0 column, and the proof's own reading above it); honest
settlement median 93 min with 36 min of proving (73 with 16), worst 158, nothing stuck, at every reference age from 0
to 3 days. Nothing reopens F or alpha. The 6 h, 3 h and plain reports follow in the same file.

#### 2.16.6 Open for sprint 7

- `u8.sh` from `fork-v5.sh` plus `u7.sh`'s token, verify and record steps; mainnet's `create` gas (pre-Glamsterdam,
  about 4 to 5M by 2.13's shape) and the 32M figure above for the day mainnet forks.
- How the driver's tool is built from `bridge-v6/*.sil` for USDC.k #1's covenant (the crate is `bridge-v5/`).
- The pm2 entries: `relay-robot` with `--env usdc/u8.env` (RELAY, TOKEN_COV_ID, ETH_NET=mainnet, BRIDGE_STATE,
  BEAT_KEY), `bridge-prover-v5` with `ETH_PROVER_BIN=/root/pin/eth-cpu/eth-prover-cpu`, the status job and the page
  with `INSTANCE=usdck`; the watchdog reading the V5 robot's files.
- A user-sized burn through the fork page (12 Sepia.k from a wallet, `Owed` and `PaidInFull` to a MetaMask address):
  the page's burn path with the beacon, end to end; about 90 min unattended.
- Optional: one real proof of a burn with a mainnet beacon through `relay-prove --prover` and the real-seal test on a
  mainnet fork, for the record's symmetry; nothing in the design depends on it.
- The README build from `/api/terms` (one text, two places) and the 2.14.4 items.

#### 2.16.7 The bridge view (`bridge-web` v0.5, pack `s6d`, 2026-11-12; appended to this file 2026-11-15)

The page's shape for real users, on top of the v0.4 logic (`app.js` unchanged; `index.html`, `style.css` and a new
`scene.js`): two shores, Kaspa left and Ethereum right, each with its wallet panel, a suspension deck between them
across the full width, and the form on the deck. A shore is greyscale until its wallet is connected (CSS filter on a
half-clipped background canvas; the barrier at that end of the deck lifts with it), so the page says what is missing
without a sentence. The traffic on the deck is the bridge's traffic as `/api/status` reports it: one car per burn the
robot has not settled (left to right, parked by stage: waiting 30%, proving 50%, submitted 76%, owed 86%, labelled
with its amount), one per deposit between the covenant's cursor and the vault's nonce (right to left, labelled with its
nonce, moved to the middle while the inbound prover is in a cycle), a car driving off when its transfer leaves the
status, the user's own transfer under a YOU pin, and a thin unlabelled trickle so the deck is never dead (off under
`prefers-reduced-motion`). The form is the plain bridge form: You send with balance, Max and quick amounts, the switch,
You receive, Fee / Arrives / To, email when it lands, the signing preview, the button; the recipient is still only ever
the connected wallet on the other side. Dark, system fonts (the CSP allows no font host), no dependencies, 22 KB of
script. Commit `57bae4b`. Driven end to end the same evening (2.16.8).

Two rough edges known on 11-12: on a 900 px window the deck sat just under the fold, and a parked car's label could
overlap a passing one. Both are gone in page v0.6 to v0.6.2 (`claude/UI-V06-PLAN.md`: the stage has a base height, the
transfers queue, labels stack, at most six cars each way with a "+N more" tag).

#### 2.16.8 The page driven end to end on the fork, both directions (2026-11-12, evening; appended to this file 2026-11-15)

Setup: MetaMask on the fork through the SSH tunnel (the fork's RPC added to MetaMask's Sepolia entry as
`http://localhost:8545`; the page at `http://localhost:8788`); the fork vault funded with 100 Sepia and 1 ETH for the
MetaMask address by the deployer key; anvil moved a week ahead (`evm_increaseTime 604800`) so the cap doubled to
$10,000 and the vault, full at cap0 after the deployer's 5,000, had room. Kasla signed the burn.

**Deposit, Ethereum to Kaspa.** Two attempts reverted out of gas with a limit of 25,837: MetaMask estimates gas and
simulates on its own infrastructure (Infura's Sepolia) whatever RPC the network entry carries, and there the fork's
vault is an address without code, so the estimate was the intrinsic cost and the simulation said "likely to fail".
The page's own `gas: 400000` on the request was overridden by the wallet (MetaMask replaces a site's limit with its
estimate); the manual gas limit in MetaMask's confirmation (advanced gas controls on) got it through: `0xeb432d…`,
10 Sepia.k, vault nonce 2, 320k gas class. None of this reaches mainnet, where the vault exists where MetaMask
simulates. The page then showed the deposit as minted: it compares the deposit's nonce with the covenant's cursor,
and the fork instance borrows the real Sepia.k covenant state (cursor 3 from October), so nonce 2 read as minted and
an old Sepia mint was linked. On #1 the vault and the covenant start together at zero and the comparison is honest.
No inbound prover watches the fork; the 10 stays in the fork vault.

**Burn, Kaspa to Ethereum.** `34cf7d44…6e90e0`, 13 Sepia.k, payload v3 with beacon 12,121,662, recipient the MetaMask
address, built and decoded by the page, signed in Kasla. The page's popup did not open; Kasla's own inbox carried the
signing request, the page's poller picked the signature up, the burn was broadcast. **Corrected 2026-11-15
(claude/UI-V06-PLAN.md item 3):** the popup did not open because `app.js` defined a top-level `function open()`, which
in a classic script replaces `window.open`; with both wallets connected it returned `true`, the page took `true` for a
window and polled forever. The http origin, blamed on the evening, had nothing to do with it; renamed to `bridgeOpen()`
in page v0.6, after which the Kasla popup opened on `http://localhost:8788`. The car with the YOU pin took the deck.
The robot:

| step | measured |
|---|---|
| `burn-seen`, `burn-beacon-ok` | at 22:07 UTC, 60 s after the broadcast; `ageMin -10074.6` (the beacon lives in the warped clock) |
| first fault | `tick-error`: tau negative from the wall clock, passed to `requiredAttest(uint256,…)`, `cast` refused the argument; every tick failed. Clamped at zero (`Math.max(0, …)`) and restarted; the proper fix is chain time (2.16.6) |
| `waiting-for-floors` | needed 450, required 450 (the clamp), 44.5 min to go |
| first cycle, 23:01 UTC | witness 527M user cycles, 557 segments, about 455 attesting; `gate-ok`; pod: no public IP in 420 s, `cycle-failed`, 5 min backoff (the second dead RunPod host of the day) |
| second cycle, 23:14 UTC | re-witness 457 headers, 455 attesting, 527,312,475 cycles; pod on a **3090** (first in the list, free this time): STARK **1,373.3 s, 2.604 s per million cycles**, wrap 70.9 s, `verify-ok` |
| `submit` | `0xff45f778…b25d5b`, fork block 12,122,158, status 1, **1,091,248 gas** (the vault's `Released` plus the difficulty memory's new day after the time jump, on post-Glamsterdam pricing; to be split by trace); recipient +12.987 Sepia.k, `feeOwed` 13,000 (the skipped maintenance burn accrues no fee) |
| burn to wallet | 1 h 34 min, with the dead host and the re-witness inside it |

The gate asked the relay for the floor because its tau was clamped to zero, while the contract counted the real
100 minutes: required about 450 against 455 attesting. Five attesters of margin, the warp's luck, not the design's;
with the clocks agreeing the gate adds its own margin. Measured today for the record: the 3090 at 2.60 s per million
against the 4090's 1.63 (same dollars per proof, 60 percent more waiting); two dead RunPod hosts in three rentals, each
costing 7 minutes under the O4 rule; MetaMask overriding a site's gas limit; Kasla's inbox as a signing path.

**The fast lane, a design note for sprint 8.** The lane switch exists in the page (`cfg.instant`, off). The lane
itself: the user names a liquidity provider as the recipient of their burn (or deposit); the provider, seeing the
irreversible burn (or the finalized deposit) that names it, pays the user from its stock now, minus its fee; the chain
repays the provider when the slow transfer lands. The provider carries no credit risk; the user trusts the provider for
one payout, and the page says so beside the free trustless lane. Pieces: an `instant` block in the instance entry
(provider name, Ethereum address and Kaspa x-only, fee bps plus a live gas component on exits, max per transfer,
enabled), a lane parameter on `/api/quote`, the provider's address as recipient in `buildBurn` and `deposit` with the
preview saying so in bold, and a third service, the teller, that watches for transfers naming it, pays from its stock,
keeps a ledger and refuses when short. The provider is pluggable: Kaspero Labs with an appointed operator, or a third
party with a referral share. No contract changes.

#### 2.16.9 The proof's cost per attester, and the variable-level rule for #2 (2026-11-12, evening)

The proof opens every counted attester (parse, PoW, level-L parents, the first-parent path to the commitment chain)
at about 1.2M user cycles each (615M for 502, 527M for 457 this week), and one 4090 proves 1.63 s per million. So the
proof grows one for one with the ladder: 24 min at the floor, 3 h 20 at $10,000 (5,000 attesters), about 8 h at $25,000
(12,500 attesters, 15 billion cycles). Sampling is not available: Kaspa headers carry no accumulator of past
superblocks, so a header the proof does not open is a header a forger can fake. For #1 the worst case is the cap,
$5,000, 1 h 43 of proving, and the exit table shows every user the wait before signing.

The rungs of the ladder are the lever. Level is a property of the hash alone (`calc_level_from_pow`); a level-L block
costs 2^(31+L) expected hashes whatever its `bits` claim; the count-based estimator held within a percent at every
level dagwalk measured, and the closed walk along `parents_by_level[L]` reached every level-L block in the window
(`missed` = 0 up to level 34), so there is no selection attack at the higher rungs. Counting at level 30+k shows the
same work with 2^k times fewer headers. The witness already builds several levels, the guest counts and attests each,
and the journal carries up to eight (level, count, attesting) triples; the V5 relay reads one, `CMP_LEVEL` (30 for
#1), and ignores the rest.

The rule for a V6 relay: the prover names the level L of the count it submits; the relay requires

    attesting_L >= max(F, (alpha x r x tau) / 2^(L-30), (amount / ATTEST_UNIT) / 2^(L-30))

with F a count at any level. The floor is the luck bound and must not scale: a handful of lucky high blocks can never
carry a proof, because a handful is below F at every level, and a small exit proven at level 34 would need 13 h of
ladder to reach 450 level-34 blocks (they arrive at 9/16 a minute), so the prover climbs only when the scaled amount
term still clears F. At today's rate the rungs start at about $1,800 (level 31), $3,600 (32), $7,200 (33), $14,400 (34).
The Kaspa work of an exit is unchanged at any level (the work is the security; $25,000 stays 23 h of ladder); only the
proof shrinks: $25,000 at level 34 is 781 attesters, under half an hour on one 4090 instead of 8 h. The exit table's
proof column flattens; its Kaspa column stays honest. `r` is still the level-30 rate from the relay's memory, scaled
by 2^(L-30) for the comparison; `r_bits` and the median rule are unchanged.

This is a relay change, not a guest change: the pinned guest `1b868276…` already emits what V6 reads, and the robot
picks the level per batch (the lowest at which the scaled requirement is at or above F). A new relay is a new instance
(#2). Ahead of it on cost per attester: parallel proving across GPUs (RISC Zero segments are independent until the
join; four 4090s divide the STARK time by about four; prover-host work, no image change, so it can land on #1), and a
Keccak-accelerated kHeavyHash in the guest (a new image id, so #2 or later). Order for sprint 8: multi-GPU on #1, the
variable-level rule and the bigger bucket in #2's relay, the accelerator when #2's guest is rebuilt anyway.

### 2.17 Sprint 7: USDC.k #1 (kzUSDC) on mainnet (2026-11-15 onward)

Branch `guest-v4`, worktree `~/kaspa-zk/kz-guest-v4`, on `5776cde` (page v0.6.2) and `f65ac5b` (this file's 2.16.7 to
2.16.9). Decisions of 11-14 and 11-15 built in: the covenant is `bridge-v7`, the fee 25 bps, the token kzUSDC "Kozmic
Bridged USDC", the contracts UNLICENSED. Packs: `s7a` (bridge-v7, the v6 negative test, the v7 driver), `s7b` (`u8.sh`,
`sink-bits.mjs`, the license line), `s7c` (the robot, the inbound service, the status job, the page server, the pm2
entries). Every number below is from a paste of the box on 11-15.

#### 2.17.1 bridge-v7: the KAS floor on minted cells, with the evidence on v6

The gap (read from `bridge.sil` on 11-14, after kUSDT's `MIN_MINTED_VALUE`): v6's `advance` validates each minted
cell's state but never its KAS value, and `keepValue` lets the successor lose up to `max_fee` whatever the mints
carry; the proof and the journal are public once broadcast and `advance` takes no signature. The copier's
transaction, built by `bridge-v6/tests/underfunded.rs` from the honest proof and journal: the cells at 1,000 sompi,
the successor at exactly `input - max_fee`, the rest in a plain output of the copier's, the miner paid the real fee.

| run on the box (v6 as it is, 2 KAS `max_fee` in the test) | result |
|---|---|
| the dev-test proof (nonce 1 minted) at cursor 0 | **v6 accepts**: 1 cell at 1,000 sompi, the copier keeps 196,999,000 sompi (1.97 KAS); bridge input 15,597,371 units (budget 1,559), authority 44,341 |
| the Sepia.k deposit-2 proof (`out-auto-sepia-2026-11-02T14-33-05-736Z`) at cursor 1 | **v6 accepts**: the same shape, bridge input 15,587,802 units (budget 1,558) |

So the gap is real on a real proof. `bridge-v7` is v6 plus: one constructor int `cell_value` (after `max_mint`);
`require(tx.outputs[cell].value >= cell_value)` on every minted cell; `keepValue(allowance)` with the successor keeping
`input - max_fee - allowance`, `cell_value` per mint in `advance` (accumulated, no multiplication) and one
`cell_value` in `init`, where output 1 (the authority) must also carry at least `cell_value`; `max_fee` is the fee
ceiling alone. Nothing else moves: no image id, no Solidity.

| test, v7 on the box | result |
|---|---|
| the copier's advance (cells at 1,000 sompi, the rest of `max_fee` to the copier) | rejected at input 0 (`VerifyError`) |
| a minted cell one sompi below `cell_value`, nothing drained | rejected at input 0 |
| the successor at `input - max_fee - cell_value` with the cell at 1,000 sompi | rejected at input 0 |
| a fee of `max_fee` with the cell at the floor; the v6 split (`max_fee - cell`) | both pass |
| a fee of `max_fee + 1` | rejected |
| a cell at 3 x `cell_value` with the honest fee / the same paid out of the `max_fee` allowance | passes / rejected |
| init with the authority one sompi below the floor; init losing `max_fee + cell_value + 1` | rejected, rejected |
| the v6 suite with `cell_value` in Params: 23 engine (F5 included, `F5_BUNDLE` the Sepia proof), 7 Tipsy | 26 + 7 passed |
| script units, one mint (`mint at max_mint`) | **15,598,342** (budget 1,559); v6 15,597,371: about 1,000 units for the floor |

Constructor and driver: `genesis --cell-value 0.3` (30,000,000 sompi, the cell KAS every mint already pays; the driver
refuses `--token-kas` or `--auth-kas` below it) and `--max-fee` now mandatory and tight. The measured Sepia.k advance
fee at fee-mult 1 is **17,236,900 sompi** for one mint (mass 172,369), 16,501,800 for a heartbeat; `--max-fee 0.5`
gives 2.9x of headroom for a fee-rate rise and bounds a copier's take at 0.33 KAS per advance. The tool for #1 is
`bridge-v7/target/release/bridge-covenant` (the crate `bridge-covenant-v7`, built in 52.6 s on the box), named by
`BRIDGE_COVENANT_V5_BIN`; the driver checks on every command that a state file with `params.cellValue` is served by
a tool whose `script` reports `covenantVersion 7` and the same floor (the v5 tool would ignore `--cell-value` and
compile v5 silently). The state file for #1 is `bridge-usdck-state.json`, its key `bridge-usdck-key.json`.

#### 2.17.2 The deployment script and the license line (s7b, 11-15)

`usdc/script/u8.sh`: `fork-v5.sh`'s factory / predict / create / deposit with `u7.sh`'s env file, gas guard,
Etherscan verification, record and `verify-eth`; mainnet only; USDC `0xA0b8…eB48` as the token and no token deployment;
fee 25 bps in the vault params and the factory's `maxFeeBps`; the fee address and the close hash read from
`~/fee-address.txt` and `~/close-hash.txt` on every run (checksum verified; the last 6 characters printed; `create`
recomputes `predictVault` before sending). The five deployed files (`RelayFactoryV3`, `UsdcVaultV4`, `KaspaRelayV5`,
`ISettlementV3`, `IRiscZeroVerifier`) carry `// SPDX-License-Identifier: UNLICENSED`; `check`, `factory` and
`create` refuse anything else. `forge test` after the change: 118 passed, 3 skipped (the fork tests without an RPC),
0 failed. `u8.sh check` on 11-15: files present (fee …af5e63, close …d2d9e3), USDC implementation `0x4350…2dd`
unchanged since 11-02, deployer 0.0676 ETH, robot 0, gas 0.205 gwei, the RISC Zero router at `0x8EaB…D319` with
code. `bin/sink-bits.mjs` prints `GENESIS_BITS` from the sink header. The close preimage's box copy was removed
(`shred -u`) after its sha256 was checked against `~/close-hash.txt` (matched); Oz holds the two copies.

#### 2.17.3 The robot, the service, the page server (s7c, 11-15)

- **Runpod 429.** Measured on the fork: robot f, `cycle-failed` three in a row, the last at 12:23:04Z, `relay-prove
  failed: Runpod GET /pods/<id>: 429 rate limit exceeded for the minute window`, backoff 20 min, the alarm mail sent;
  the next scan at 13:05:27Z with no newer failure. From the source: during a pod's IP wait `relay-prove.mjs` asked
  `GET /pods/<id>` every 5 s (58 to 301 s on live hosts, 420 s for a dead one), and each inbound service under pm2
  (`bridge-prover-v4`, `bridge-prover-sepia`, same key) asked `GET /pods` every 60 s; the robot itself only on exit
  and for the balance every 6 h. Now `rp()` treats 429 as wait-and-ask-again (`Retry-After`, else 15, 30, 60, 60 s)
  inside the call, so it never ends a cycle; the IP poll is every 10 s; the inbound sweep runs at start, after a
  failed cycle and then every 10 min.
- **Chain time.** `nowS()` in the robot is the relay chain's latest block timestamp, read once per tick, plus the
  seconds since (the wall clock only if the read fails, logged); beacon age, `leadable`, tau and the reading's age
  all follow it. The zero clamp in `requiredAttest` stays as a guard.
- **GPUs.** 4090 first (1.63 s per million measured), 3090 second (2.60), the table updated.
- **The s6b items, in the service for the first time** (2.16.4 described them; the file in the worktree was still
  the 11-08 one): `--image` must be a digest and must be the pinned pair for the covenant's image id; the host
  binary's `ids` must print the covenant's image id; a v7 state needs `BRIDGE_COVENANT_V5_BIN`; the nonces are
  asserted `cursor + 1` onward before the fetch; `/ingest` after every advance that minted.
- **Failures as a class.** `cycle-failed` carries `class` (`failureClass` in `src/runpod.js`); the status feed serves
  `lastFailure.class` and plain words in `error`, never the robot's text (a provider's name, a pod id); the page's
  hover shows the words with no page change.
- **Beacons from the future.** `freshBeacon` judges the beacon against `ethereum.headTime` (the chain's head, read by
  the status job in the same tick): more than 60 s ahead of the head or more than 10 min behind it is refused; the
  status file's own age says whether the job is behind. The wall clock is not compared with the beacon, so the fork
  (a week ahead) judges its beacons correctly.
- **The page server** takes INSTANCE, HOST, PORT, DATA_DIR, STATUS_FILE, KASPA_URL, KASPEROCONNECT_MERCHANT and TOOL
  from the process environment over `.env` (the pm2 entry says `INSTANCE=usdck`); secrets stay in `.env`.
- **The instance entry** `usdck`: name "Kozmic Bridged USDC", symbol kzUSDC, `instanceNumber` 1, state file
  `bridge-usdck-state.json`. **The pm2 entries** `ops/pm2-usdck.config.cjs`: `relay-robot-u`, `bridge-prover-usdck`,
  `bridge-status` (`--contact /var/lib/kozmic/web/contact.jsonl`), `bridge-web` (INSTANCE usdck, merchant
  `kpm_cheb8eey`); written, not started; the fork rig is stopped and the Wobbly.k `bridge-status` and `bridge-web`
  deleted before they start.
