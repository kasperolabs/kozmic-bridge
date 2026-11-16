# USDC blacklist study (U0, 2026-10-16)

What Circle's blacklist looks like on chain, how fast it acts, and where the flag lives. Measured from Ethereum
mainnet on the node box; nothing here is taken from documentation or memory. Scripts: `u0/d_scan.py`,
`u0/d_refine.py`; raw cache `u0/d_scan_cache.json`; proofs `u0/proof-*.json`; logs `u0/probe*.log`, `u0/d_scan.log`.

## 1. Where the flag lives (U0a)

| item | value | evidence |
|---|---|---|
| USDC proxy | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | |
| proxy type | ZeppelinOS (pre EIP-1967); implementation at slot `keccak256("org.zeppelinos.proxy.implementation")` = `0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3` | the EIP-1967 slot reads zero; this one reads the implementation |
| implementation | **`0x43506849d7c04f9138d1a2050bbf3a0c054402dd`**, FiatTokenV2_2, solc 0.6.12, Etherscan exact match | `cast storage`, Etherscan |
| blacklist flag | **bit 255 of `balanceAndBlacklistStates[addr]`, mapping at slot 9**; balance = low 255 bits | the deployed bytecode: `isBlacklisted` loads slot 9 and shifts right 255; `blacklist` ORs `0x8000…`; `balanceOf` masks `0x7fff…` |
| old `blacklisted` mapping (slot 3) | empty since v2.2 | reads zero for blacklisted addresses |
| upgrades (`Upgraded` events) | 3 in six years: 2020-08-27 v2 `0xb7277a6e…`, 2021-04-26 v2.1 `0xa2327a93…`, **2024-01-08 v2.2 `0x43506849…`** | Etherscan logs |

Live check, mainnet, 2026-10-16:

| address | `isBlacklisted` | `balanceOf` | slot-9 word |
|---|---|---|---|
| `0x085488e7…853a` | true | 139,858.749668 | `0x8000…0020903b28e4` |
| `0x286ff942…3420` | true | 406,243.920148 | `0x8000…005e96064914` |
| `0x8c3e09ec…3412` | true | 7,375.896984 | `0x8000…0001b7a34198` |
| `0x00000000…8a90` (Uniswap v4 PoolManager, control) | false | 45,466,475.947411 | `0x0000…2959fd25e593` |

The low bits equal `balanceOf` exactly in every row. Proofs at finalized block **26,204,126** (one state root for all
three): `u0/proof-0x085488e7…json` (flag set, 7 nodes), `u0/proof-0x00000000…json` (flag clear, 8 nodes),
`u0/proof-impl.json` (implementation slot, 7 nodes). These are the fixtures for the inbound guest's adversarial cases.

**The January 2024 upgrade is the reason the guest pins the implementation address.** v2.2 moved the flag from the
slot-3 mapping into slot 9; a guest pinning only a slot would have read a stale mapping after the upgrade and treated
blacklisted depositors as clean. With the implementation pinned, an upgrade stalls minting instead. Three upgrades in
six years is the expected stall rate.

## 2. How fast Circle acts (U0b)

Source: every `Blacklisted` and `UnBlacklisted` event on USDC (Etherscan logs; the Alchemy free tier caps
`eth_getLogs` at 10 blocks, Flashbots' RPC silently returns incomplete logs, publicnode and drpc refuse). For each
blacklisting, the address's inbound USDC transfers before it.

| | count |
|---|---|
| `Blacklisted` events, block 10,274,701 (2020-06) to 26,177,928 | **903** (849 unique addresses) |
| `UnBlacklisted` events | **226**; 196 of the 903 freezes were later reversed |
| blacklisted addresses that had **never received USDC** | **586 (65%)** |
| blacklisted addresses that held funds | 317 |

Delay from inbound funds to the freeze, for the 317 funded addresses:

| measure | p10 | p25 | p50 | p75 | p90 |
|---|---|---|---|---|---|
| last inbound transfer -> freeze (h) | 13 | 76 | 583 | 4,876 | 17,821 |
| **largest inbound transfer -> freeze (h)** | 96 | 342 | **2,465 (103 days)** | 10,830 | |
| first inbound transfer -> freeze (h) | 190 | 715 | 4,012 | 15,086 | 25,349 |

Share of funded blacklistings a quarantine of D would have caught (largest inbound, which removes the dust bias of
"last inbound"):

| D | 6 h | 24 h | 72 h | 7 d | 30 d |
|---|---|---|---|---|---|
| caught | 1.3% | 5.0% | 8.8% | 14.5% | 35.6% |

Size: the largest inbound transfer before a freeze was p50 85k USDC, p75 311k, p90 1.05M (sum 221M over 317 cases).
Reversed freezes lasted p25 50 days, **p50 306 days**, p75 862 days.

## 3. What follows for the bridge

1. **No quarantine.** Circle's list is investigation-driven and lands months after the funds; a product-tolerable
   wait catches one funded case in twenty, a month catches a third. The latency buys nothing. Dropped.
2. **The blacklist check at mint time stays.** One storage proof, no wait: a deposit whose depositor is blacklisted
   at the finalized block is never minted. It covers the 65% pre-emptive listings (those addresses cannot deposit at
   all, `transferFrom` reverts) and anyone flagged between deposit and mint, and it makes the vault an enforcer of
   Circle's list, not a way around it. A skipped deposit's USDC stays in the vault, frozen there by Circle, backing
   nothing; minting it would create exactly the unbacked supply the design must avoid.
3. **No refund path.** One freeze in five is reversed, after a median of ten months. Not worth a mechanism.
4. **The late-freeze tail is the cap's job.** A freeze of the vault address would leave the Kaspa supply unbacked,
   as with every bridged USDC before it; the data says no quarantine prevents it. State it, cap it.
5. **Fast is a layer above.** Users who want USDC to KAS "now" get it from a liquidity provider holding inventory on
   both sides who rebalances through the rail; the rail stays slow and honest. First an OTC LP, later a hashlock
   swap (Ethereum contract + Kaspa covenant) so the fast path is as trustless as the rail.

## 4. Recount, 2026-11-02

After the Binance breach (reported 2026-10-29/30; Circle said to have frozen about $800M of USDC). Script
`u0/bl_recount.py` (sha256 `fad9b6c0af5bb9e30f66e857aa0763fbccbfb9eb6c9eeeec64dbad727d7297f3`), Etherscan logs on the
USDC proxy from block 26,177,929 (the block after section 2's range) to latest; last event at block 26,329,026.

| | count |
|---|---|
| `Blacklisted` events since section 2 | **32** (32 addresses) |
| of which 2026-10-28 to 10-31 (the breach window) | **22** |
| `UnBlacklisted` events since section 2 | 1 |
| `Blacklisted` events since 2020-06 | **935** |

By day: 10-19 2, 10-22 1, 10-27 2, 10-28 9, 10-29 4, 10-30 7, 10-31 2, 11-02 5. The fortnight before the breach ran
at about one event every three days.

Reading: the list is live and Circle's breach response landed on Ethereum mainnet, clustered in the breach window.
Nothing in section 3 changes. The bridge keeps no list: the inbound guest proves the depositor's bit in USDC's own
storage at the finalized block, so every flag is enforced the moment Circle sets it (and while it is set the address
cannot deposit at all, `transferFrom` reverts). Unique-address total since 2020-06 is at most 881; not deduplicated against section 2.
