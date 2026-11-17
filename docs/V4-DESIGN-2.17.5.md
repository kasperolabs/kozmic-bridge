### 2.17.5 The attestation-floor review, F 600, and instance 2 (kzUSDC) on mainnet (2026-11-16)

Written 2026-11-17 from the 11-16 session: the review request, the reviewer's answers and the checks run against them,
the instance 2 parameters as deployed, and the first day's record. Section numbers like 2.3 and 2.8 refer to the
design record, `docs/V4-DESIGN.md`. Nothing here changes the design; it changes three of instance 2's numbers and one
robot setting, and says why. Instance 1's own record (2.17.4) is still to be written.

This is a different review from `docs/REVIEW-2026-11-16.md`, which records the same day's review of this repository's
code and documents. This one was about one number, the floor F.

#### 2.17.5.1 What was asked

On 11-16 the floor F was proposed for lowering from 450 (instance 1, and the factory's `MIN_FLOOR`) to 225, to cut
small exits from about 1 h 12 to about 40 min. Before deciding, the question went to an outside reviewer as one
self-contained document: the relay rule as deployed, the threat model, odds tables for F from 150 to 600, Kaspa's
pool concentration, the proposal with its alternatives, seven questions, and the code that produced every table, so
the reviewer could rerun it. Writing it corrected the proposal before the reviewer saw it: the floor is what bounds a
minority miner's luck (a pool below alpha can never keep up with the requirement, but it can get ahead of it briefly
by variance, and F is the size of the lead it needs), so it does work at every exit size, not only at the smallest.

**The model** (2.3, 2.8): the forger owns each level-30 superblock with probability f, attesting share 1, proving
time 0; a time-stepped distribution of his count (dt 0.02 min, Poisson increments, lambda 9.1 a minute) with the mass
at or above `max(F, ceil(alpha x lambda x t))` removed as won at each step. Per year assumes a fresh attempt every
`T_F = F / (alpha x lambda)` minutes all year. The 5% correction multiplies f by 1.05 (the largest 3-hour hashrate
rise in the record, +5.2%). Checks: F 300, f 0.33, lambda 9.6 gives 1.3e-7 a year and F 600, f 0.40 gives 5.4e-4, the
record's 11-03 figures; the corrected F 450 row (5e-16, 1e-9, 8e-5 at f 0.30, 0.33, 0.36) is 2.8's row.

```python
def win_prob(F, f, a=0.5, lam=9.1, dt=0.02, extra=900):
    TF = F/(a*lam); kmax = int(F + a*lam*extra + 200); dist = np.zeros(kmax+1); dist[0] = 1.0
    mu = f*lam*dt; ker = [exp(-mu)*mu**j/factorial(j) for j in range(12)]; won = 0.0; t = 0.0
    for s in range(int((TF+extra)/dt)):
        t += dt; new = dist*ker[0]
        for j in range(1, 12): new[j:] += dist[:-j]*ker[j]
        dist = new; R = max(F, ceil(a*lam*t)); won += dist[R:].sum(); dist[R:] = 0
    return won, TF        # per attempt; per year: 1 - (1 - won) ** (525600 / TF)
```

**Kaspa's hashrate concentration** (miningboard.com, November 2026; network about 325 to 345 PH/s): two pools at about
31% and 30%, then 10.6%, 4% and 3.8%. So f 0.30 to 0.33 is one existing operator acting alone. Two of them together
exceed alpha, where no floor matters: that is the majority event.

| | F 450 (instance 1) | F 300 | F 225 (proposed) |
|---|---|---|---|
| floor reached after | 50 min | 33 min | 25 min |
| small exit end to end (proof 15 min) | 1 h 12 (measured) | about 50 min | about 40 min |
| one 31% pool, per year (f x 1.05) | 4e-16 to 1e-9 | 8e-10 to 2e-5 | 1e-6 to 2e-3 |
| a 36% miner, per year (f x 1.05) | 7e-5 | 3e-2 | 0.4 |

#### 2.17.5.2 What the reviewer said, and what was checked against it

- **Reject F 225.** Agreed. 300 is arguable; 450 is the defensible minimum under the stated threat model; 450 or 600
  for a bridge whose cap grows to $1M.
- **Private-branch difficulty manipulation** (the reviewer's largest concern). It does not apply: rusty-kaspa's
  `calc_level_from_pow` takes the level from the raw PoW hash, not relative to the block's target, so a level-30
  superblock costs about 2^61 hashes at any difficulty and an easy-target branch earns no extra superblocks per hash.
  Measured on the real record: level-30 count over work / 2^61 = 0.992. The relay's difficulty reading sets only the
  honest rate; f is a hashrate share. The same point answers section B of `docs/REVIEW-2026-11-16.md`.
- **Superblocks before the burn, replay, batching, header validity.** Settled in the design: every attester's
  first-parent path reaches the commitment chain that descends from the burn's block, so it was mined after every burn
  and beacon in the proof (2.1, 2.2; and section A of `docs/REVIEW-2026-11-16.md`); a journal settles once
  (`seen[sha256(journal)]`); each burn has one `owed` record; the amount term is over the whole batch. Header validity
  in the guest cannot be certified from a note: that is a code review of the guest and the relay against the model,
  the next review to commission.
- **Numerical convergence**, run 11-16: dt 0.02, 0.01, 0.005, kernel 12 to 20, horizon 900 to 1,500 min. F 450 at
  f 0.33: 7.95e-13, 7.99e-13, 8.02e-13 a year; F 225 at f 0.36: 2.85e-2, 2.86e-2, 2.87e-2. Stable to three digits.
- **Attempt model.** One continuous attempt is the per-attempt column (1.5e-16 at f 0.33, F 450); overlapping branches
  split f and are worse for the forger. The per-year figure is the union bound in practice.
- **Rate underestimation** (the reviewer's best point). If the relay believes the network slower by e than it is, the
  forger's effective share is f(1 + e). A 31% pool, per year:

| e | 5% | 10% | 20% | 30% |
|---|---|---|---|---|
| F 450 | 9e-14 | 1e-10 | 1e-5 | 5e-2 |
| F 600 | 4e-19 | 4e-15 | 2e-8 | 1e-3 |

  Redirecting existing hashrate into a private branch lowers the honest difficulty, and the relay keeps a 7-day
  maximum of its readings, so that direction is conservative. Only hashrate added to the network and hidden until the
  attack produces e, and the relay learns of growth at the next settled proof. So e is bounded by the network's growth
  between settlements: **the maintenance burn's cadence is a security parameter.** The record's 5% is an observation,
  not a bound; the cadence is what turns it into one.
- **ATTEST_UNIT $2 to $1** (economic margin `125 x price(KAS) / ATTEST_UNIT`: 2x today at $2, break-even at KAS
  $0.016; 4x at $1). Considered, then refused, 2.17.5.3.
- **Caps unchanged** ($10k a proof, $25k a day), and a review at each doubling of the cap before relying on it. The
  schedule doubles without a key; the review at each step is a README line.
- **State the majority boundary plainly**: "a forgery is a majority event", on the Token page in those words.

#### 2.17.5.3 Decisions for instance 2 (Oz, 11-16)

| parameter | instance 1 | instance 2 | why |
|---|---|---|---|
| F | 450 | **600** | about 350x on the 36% case and on every stress column of 2.17.5.2, for about 16 min more Kaspa work on every small exit (600 instead of 450 superblocks at about 9.1 a minute). 450 is safe; 600 is safe with margin against pools merging and hashrate moving over the years a bridge lives. Revisit with data in a later instance if the minutes cost users. |
| alpha | 0.5 | 0.5 | unchanged: "a forgery needs half the hashrate" as a number; honest exits survive a 2x hashrate drop |
| ATTEST_UNIT | $2 | **$2** | $1 refused: a $10k exit would need 10,000 attesters, about 18 h of chain plus about 7.6 h of proving at the 11-15 measured rate, about 26 h against the beacon's ~27 h EIP-2935 window. One provider outage and the exit restarts. At $2: about 9 h plus 3.8 h. The economic margin stays 2x at KAS $0.032; it is the assumption to watch. |
| maintenance burn | every 24 h | **every 8 h** | bounds e (above) to a third of a day's growth; about $0.55 a proof on a 4090, ~$1.65 a day |
| robot pod cap | 7,200 s | **21,600 s** | found while sizing ATTEST_UNIT: a $10k proof at $2 is about 6.9 G cycles, about 3.8 h at the measured rate, so instance 1 could never have proven its largest allowed exit. The watchdog's pod cap moved with it. |
| caps, fee, MIN_BURN, images | | unchanged | bucket $10k, refill $25k/day, MAX_DEPOSIT $10k, fee 25 bps, MIN_BURN $10, inbound 45400f5f…, outbound 1b868276… |
| factory | RelayFactoryV3 | the same, reused | F 600 is above its `MIN_FLOOR` 450 and $2 within its `MAX_ATTEST_UNIT`; the deploy script takes stricter per-instance values and checks the deployed relay against them |

The deploy runbook for instance 2 was written on 11-15, before this review, with F 450; this section supersedes it.

#### 2.17.5.4 Instance 2 record

Deployed 2026-11-16 around 12:00 UTC; the vault's cap epoch is 11:52:47 UTC (cap $5,000, doubling every 7 days,
$1,000,000 from 2027-01-11). Name kzUSDC, ticker KZUSDC, family id `cc9957fe…`. Addresses and parameters:
`usdc/deployments/2-0xF626DcC984d12445ABdDAADA989855E66d3cDB3A.json`. The relay calls RISC Zero's verifier router
`0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319`; the covenant pins USDC's implementation `0x43506849…02dd`.

| what | value |
|---|---|
| first exit at F 600 | 10 KZUSDC, **1 h 41 min** end to end (burn `25dac4a9…`, settlement `0x50512607…`); model 1 h 45 |
| first deposit | nonce 3, **1 h 06 min**, of which about 45 min were Runpod's REST v1 retirement (below) |
| first day, from the status job (11-17) | deposits: median 22.6 min over 5; exits: median 1 h 41 over 3, the slowest 1 h 57; the relay's rate reading 8.09 superblocks a minute |
| instance 1 | closed the same day (`closeDeposits` `0xe821f5c5…`, block 26,428,072; fees claimed `0x5cd90f97…`, 0.24875 USDC) |

**Incidents.** 11-15: Runpod's daily API quota (2,700 calls) spent by polls and sweeps; one exit took 3 h 38 (the
accounting was fixed). 11-16 17:33 to 18:17 UTC: Runpod retired REST v1 (`rest.runpod.io/v1`); every pod call failed,
the inbound cycle failed three times with the backoff doubling 10, 20, 40 min while a deposit waited (`src/runpod.js`
and the watchdog moved to `api.runpod.io/v2`). Open from both: a connection-level failure should retry in minutes, not
double; a provider's API retirement belongs in RISKS.md; a second GPU provider.

#### 2.17.5.5 Open

- The code review the reviewer named: the guest and the relay against this model, by someone reading the code.
- Measure the 8 h maintenance cadence over its first weeks: proofs per day, cost, and the largest growth between
  readings seen.
- The README line for the cap schedule: a review before relying on each doubling.
- The floor-review request and the reviewer's answers, in full, beside the other reviews in `docs/`.
