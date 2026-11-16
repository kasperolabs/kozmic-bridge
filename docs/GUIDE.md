# How to use Kozmic Bridge

<!-- The bridge page renders this file at /guide (bridge-web/server.mjs). Every {{figure}} is read from the deployed
     contracts through the status job, never typed. {{exit_table}} and {{contact_form}} are blocks the page fills in.
     Second version (2026-11-15, pack s7x): short, numbers in tables, three steps each way. Wording is Oz's to change:
     plain real-world words and none of the bank or issuer words. Figures: {{symbol}} {{eth_symbol}} {{fee_pct}}
     {{cap_now}} {{room_now}} {{cap0}} {{ceiling}} {{doubling_days}} {{max_deposit}} {{min_deposit}} {{min_burn}}
     {{bucket}} {{refill}} {{deposit_time}} {{small_exit_time}} {{small_exit_usd}} {{kas_fee}} {{kas_park}} {{kas_needed}} -->

> **New, and not audited by a paid firm.** Move only what you can afford to lose. Nobody can reverse a transfer, including us. [What can go wrong](/about)

## What it does

Kozmic Bridge moves {{eth_symbol}} between Ethereum and Kaspa. {{eth_symbol}} in on Ethereum becomes the same amount of {{symbol}} in your Kaspa wallet, and back again.

Each transfer is checked by a mathematical proof. No person approves it, and no person can stop it.

## What you need

| | |
|---|---|
| On Ethereum | MetaMask, your {{eth_symbol}}, and a little ETH for the network fee |
| On Kaspa | Kasla, Kasware or Kaspire, and about {{kas_needed}} KAS if you will send back out |
| On the page | Both wallets connected. The bridge opens when both are in |

You never type an address. The money lands in the wallet connected on the other side.

## Ethereum to Kaspa

1. **Enter the amount** and press the Bridge button.
2. **Confirm in MetaMask.** The first time it asks twice: once to allow the amount, once to send it.
3. **Wait about {{deposit_time}}.** The full amount arrives in your Kaspa wallet.

## Kaspa to Ethereum

1. **Flip the direction** with the arrows, enter the amount, press the Bridge button.
2. **Check and sign.** The page shows the amount and the Ethereum account that will receive it. Sign in your Kaspa wallet. Kasla opens a small window for this.
3. **Wait.** About {{small_exit_time}} for up to {{small_exit_usd}}. Larger amounts take longer.

You can close the page while you wait, or ask for one email when it lands.

## Key numbers

| | |
|---|---|
| Fee, Ethereum to Kaspa | Nothing to the bridge. Ethereum's network fee only |
| Fee, Kaspa to Ethereum | {{fee_pct}} of the amount, taken when it is paid out |
| KAS used on the way out | About {{kas_fee}} KAS network fee, plus {{kas_park}} KAS that stays locked |
| Smallest transfer in | {{min_deposit}} |
| Largest transfer in | {{max_deposit}} |
| Smallest transfer out | {{min_burn}}. Less than this is not paid out and is lost |
| The bridge holds at most | {{cap_now}} today, with room for {{room_now}} more |
| How that limit grows | From {{cap0}}, doubling every {{doubling_days}} days, up to {{ceiling}} |
| Payouts on Ethereum | {{bucket}} at a time and {{refill}} a day, across everyone |

Every fee is shown before you sign. The limits are small on purpose while the bridge is new.

## How long a transfer out takes

A larger amount waits longer, because the bridge pays out only after Kaspa has done enough work on top of your transfer. That wait is what protects the money.

{{exit_table}}

On a busy day a payout can arrive in parts. Nothing is lost; it takes longer.

## Before you send

- **The receiving address is final.** It is the wallet connected when you sign.
- **One transfer out uses one coin.** If your {{symbol}} sits in several coins, the largest one is the most you can send at once.
- **The issuer of {{eth_symbol}} can block addresses.** A blocked address does not receive. The page checks yours before you sign.
- **A change to Ethereum or Kaspa can end this bridge.** Transfers in stop first. The date is announced on the bridge page. Move out before it.
- **{{symbol}} is its token id, not its name.** [The token page](/token) shows the id in full, with links to look it up.

## If something looks stuck

| What you see | What to do |
|---|---|
| "Ethereum confirms it" for 20 minutes | Wait. Ethereum takes 13 to 19 minutes, sometimes more |
| "The bridge proves it" for a long time | Wait. The proof machine is rented and a rental sometimes repeats. You can close the page |
| A transfer out is past its estimate | Wait. Large amounts and busy days take longer. The page shows what has been paid |
| The Kasla window did not open | Use the link under the Sign button, or your Kasla inbox |
| The button asks to switch MetaMask | Switch MetaMask to Ethereum mainnet |
| Your wallet does not show {{symbol}} | The transfer is on Kaspa either way. Use a wallet that shows Kaspa tokens, such as Kasla |

## Contact

Tell us what happened and where to answer. Never send anyone your recovery words or a private key. We will never ask for them.

{{contact_form}}
