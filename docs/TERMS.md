# About Kozmic Bridge, and what you should know before you use it

<!-- One text, two places: the bridge page renders this file at /about with every {{figure}} read from the deployed
     contracts (never typed), and the README's copy is generated from the same file by the same substitution at
     deploy time (sprint 7). Edit here only. Placeholders: {{symbol}} {{fee_pct}} {{cap0}} {{ceiling}} {{doubling_days}}
     {{bucket}} {{refill}} {{min_deposit}} {{min_burn}} {{vault_link}} {{relay_link}} {{token_link}} {{repo_link}}
     (the four _link figures are markdown links: the address or id as the text, its explorer page as the target) -->

## What this is

Kozmic Bridge moves USDC between Ethereum and Kaspa. You deposit USDC on Ethereum and receive the same amount of
{{symbol}} on Kaspa; you burn {{symbol}} on Kaspa and receive USDC on Ethereum, less a {{fee_pct}} fee. Every move is
checked by a mathematical proof, not by a person or a company. Nobody holds a key that can stop, redirect or reverse
an exit, including us.

## This is a new invention

The bridge, its proof programs and its contracts were built by Kaspero Labs and tested on both networks with real
funds. They have been reviewed, not audited by a paid firm. New systems have edge cases that appear only after real
use. Some may cost money. We cannot promise there are none.

## What protects you, and its limits

The bridge holds at most a fixed amount of USDC, starting at {{cap0}} and doubling every {{doubling_days}} days up to
{{ceiling}}. Exits are paid at most {{bucket}} per proof and {{refill}} per day. These limits cap what any failure can
cost in total; they do not protect any one holder from loss. The bridge's programs cannot be changed after deployment.
If a flaw is found, the fix is a new bridge, and the old one stays as it is until its holders have exited.

## What we can and cannot do

We can close the bridge to new deposits. We cannot pause exits, freeze an address, recover a mistaken transfer, or
return funds taken through a flaw. If something is stolen, we cannot pay you back. Circle, the issuer of USDC, can
freeze the Ethereum vault under its own terms; that is outside our control.

## Changes to Ethereum or Kaspa

A change to either network that the proof programs cannot follow ends this bridge instance. On an Ethereum change,
deposits stop first and exits remain possible for as long as proofs of Kaspa can still be made. On a Kaspa change that
alters block headers or the commitments the proofs read, exits may end as well. Exit before such a date is announced.

## Timing and minimums

An exit is paid after a proof of Kaspa's work has been made: a {{symbol}} burn smaller than about $900 settles in
about an hour and a half; larger exits wait longer, in proportion to the amount, because the proof must carry more of Kaspa's
work for them (the table on the bridge page shows the expected wait). Deposits below {{min_deposit}} are refused by the
vault. Burns below {{min_burn}} are not paid and the tokens are gone: do not burn less than that.

## Your part

The Kaspa address you give at deposit is final. Check it. Keep your {{symbol}} only in wallets you control. Use
amounts you can afford to lose while this is new. We publish the code, the proof programs and the live numbers
({{repo_link}}); read them if you want to know exactly what runs. The contracts are the vault {{vault_link}} and the relay
{{relay_link}} on Ethereum, and the token family {{token_link}} on Kaspa: the identity of {{symbol}} is that covenant id,
never its name or ticker.
