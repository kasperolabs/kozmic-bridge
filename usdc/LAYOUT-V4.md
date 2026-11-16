# UsdcVaultV4 storage layout (the live instance)

The inbound guest (`eth-prover`) hardcodes slots 0 and 1 and the two-word deposit record; they are unchanged
since `usdc/LAYOUT.md` (V1). Everything the guest reads is marked. Asserted by the Foundry tests with `vm.load`
and by `forge inspect UsdcVaultV4 storage-layout`.

```
slot 0                                      nonce (uint64, low 8 bytes); the first deposit is nonce 1                 [guest reads]
slot 1                                      deposits mapping base (always zero)                                        [guest reads]
k0 = keccak256(abi.encode(uint256(n), 1))   deposits[n] word 0: amount | kaspaVersion << 64 | depositor << 72            [guest reads]
k0 + 1                                      deposits[n] word 1: kaspaPayload (bytes32)                                 [guest reads]
slot 2                                      bucketFullAt (uint256): the timestamp at which the release bucket is full
                                            again; available() = BUCKET_MAX - (bucketFullAt - now) * REFILL_PER_DAY / 86400,
                                            clamped to [0, BUCKET_MAX]; a release of x pushes it forward by
                                            ceil(x * 86400 / REFILL_PER_DAY) seconds from max(bucketFullAt, now)
slot 3                                      bits 0..63 outstanding (uint64); bits 64..223 relay (address); bit 224 depositsClosed
slot 4                                      feeOwed (uint64): release fees accrued, swept to FEE_ADDRESS by claimFees
```

Immutables (no slot): TOKEN, FACTORY, DEPLOY_TIME, CAP0, CEILING, DOUBLING, MIN_DEPOSIT, BUCKET_MAX,
REFILL_PER_DAY, MAX_DEPOSIT, FEE_BPS, FEE_ADDRESS, CLOSE_HASH.

`outstanding` is the USDC the vault holds against circulating token: deposits add to it, releases subtract
the full installment (the fee is taken from the recipient's part and moved to `feeOwed`, so
`balance == outstanding + feeOwed`). Burns below the relay's `MIN_BURN` are never released, so
`outstanding` can exceed the circulating supply but never fall below it; that is why the relay's clamp of a
debt to `outstanding - owedTotal` cannot bite in an honest instance.

Burn debts live in the relay (`KaspaRelayV5.owed[txId]`: recipient, amount, tip, paid, submitter,
recorded); the vault only answers `release` calls from its one relay, `deposit` from anyone until
`closeDeposits`, and `claimFees` from anyone.
