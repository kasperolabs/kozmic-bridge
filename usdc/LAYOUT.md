# UsdcVault storage layout (frozen 2026-10-16, U2)

The inbound guest (eth-prover v2, U3) hardcodes this as its `vault_layout`, so the image id pins it. Changing
anything here means a new guest, a new image and a new instance.

```
slot 0                                      nonce (uint64, low 8 bytes); first deposit is nonce 1
slot 1                                      deposits mapping base (always zero)
k0 = keccak256(abi.encode(uint256(n), 1))   deposits[n] word 0:
                                              bits 0..63    amount (uint64, USDC base units, 6 decimals)
                                              bits 64..71   kaspaVersion (0 = P2PK, 8 = P2SH)
                                              bits 72..231  depositor (address)
                                              bits 232..255 zero
k0 + 1                                      deposits[n] word 1: kaspaPayload (bytes32)
slot 2                                      settled mapping base (burn tx id -> bool); not read by the guest
slot 3                                      bits 0..63 outstanding (uint64); bits 64..223 relay (address, set once by
                                            the factory in the deploy tx); packed by the compiler; not read by the guest
```

Immutables (no slot): TOKEN, FACTORY, DEPLOY_TIME, CAP0, CEILING, DOUBLING, MIN_DEPOSIT.

What the guest proves per deposit n > cursor, all at the light-client-finalized execution block:

1. The vault account against `exec_state_root`; words k0 and k0+1 against the account's storage root.
2. Decode word 0; refuse zero words, nonzero bits above 231, amount 0, version not in {0, 8}, zero payload,
   non-increasing nonces (as today).
3. The token account (`USDC`, committed in the journal) and two of its storage words:
   - the ZeppelinOS implementation slot `0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3`,
     committed in the journal (the covenant pins `0x43506849d7c04f9138d1a2050bbf3a0c054402dd`);
   - `keccak256(abi.encode(depositor, 9))`, the `balanceAndBlacklistStates[depositor]` word; bit 255 is the
     blacklist flag.
4. Status byte: 0x00 mint if the flag is clear, 0x01 skip if set. The covenant mints status-0 entries and
   advances the cursor past both.

Compared with Vault.sol (CP-3): word 0 gains the depositor in bits 72..231 (was zero); slots 0 and 1 unchanged;
slots 2 and 3 new. The deposit record stays two words, so still one `eth_getProof` per deposit.
