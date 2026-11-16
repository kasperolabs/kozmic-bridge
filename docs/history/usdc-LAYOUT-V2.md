# UsdcVaultV2 storage layout (Tipsy.k, U7, 2026-10-17)

The inbound guest (eth-prover v2, image `c320da50…`, pinned) hardcodes slots 0 and 1 of `usdc/LAYOUT.md`. They are
byte-identical here, so the guest is unchanged. Asserted by `test/UsdcVaultV2.t.sol` (`testLayoutSlots0And1AreUsdcVaults`)
with vm.load, and by `forge inspect UsdcVaultV2 storage-layout`.

```
slot 0                                      nonce (uint64, low 8 bytes); first deposit is nonce 1           [guest reads]
slot 1                                      deposits mapping base (always zero)                            [guest reads]
k0 = keccak256(abi.encode(uint256(n), 1))   deposits[n] word 0: amount | kaspaVersion << 64 | depositor << 72  [guest reads]
k0 + 1                                      deposits[n] word 1: kaspaPayload (bytes32)                     [guest reads]
slot 2                                      bucketFullAt (uint256): the timestamp at which the release bucket is full
                                            again; `available() = BUCKET_MAX - (bucketFullAt - now) * REFILL_PER_DAY / 86400`
                                            (clamped to [0, BUCKET_MAX]); a release of x pushes it forward by
                                            ceil(x * 86400 / REFILL_PER_DAY) seconds from max(bucketFullAt, now).
                                            v1's unused `settled` mapping base was here; not read by the guest
slot 3                                      bits 0..63 outstanding (uint64); bits 64..223 relay (address): as v1
```

Immutables (no slot): TOKEN, FACTORY, DEPLOY_TIME, CAP0, CEILING, DOUBLING, MIN_DEPOSIT, BUCKET_MAX, REFILL_PER_DAY,
MAX_DEPOSIT.

`settled[txId]` moved to the relay (`KaspaRelayV3.owed[txId]`, two words per burn: `recipient | remaining` and
`tipRemaining | submitter | recorded`); the vault no longer records burns, it only answers `release` calls from its
one relay.
