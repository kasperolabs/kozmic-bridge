# kpow: Kaspa header proof of work, checked in the EVM

Outbound study, experiment E10. Question: what does it cost an Ethereum contract to check one Kaspa
mainnet header by itself, with no zkVM and no GPU? That is, to check its hash (the parent link),
its kHeavyHash proof of work against its own `bits`, and its block level.

Everything here is local: `forge test` on a node box. No deployment, no gas spent, no keys.

## What is in here

```
vectors/   Rust, pinned to rusty-kaspa v2.1.0. Reads real headers from your node and writes every
           intermediate value (header preimage, block hash, pre_pow_hash, pow hash, the 64 matrix
           rows, final pow, level). Each value is computed step by step AND by rusty-kaspa itself
           (kaspa_pow::State, hashing::header::hash); it aborts if they ever differ.
sol/       Foundry project. src/KaspaPow.sol is the port; test/KaspaPow.t.sol checks every stage
           against the vectors and prints gas per stage per header.
gen/       KaspaPow.sol is generated: KaspaPow.sol.in plus an unrolled keccak-f[1600] round
           (gen_keccak.py). Edit the .in file and run `python3 gen/build.py`.
```

What the contract does per header:
1. **parse**: walks the serialized header (parents by level, then fixed fields) to find time, bits, nonce.
2. **block hash**: blake2b-256 keyed `"BlockHash"`, through the BLAKE2b F precompile (0x09).
3. **pre_pow_hash**: the same hash with time and nonce zeroed.
4. **pow hash**: cSHAKE256("ProofOfWorkHash") = one keccak-f[1600] from a fixed initial state. The EVM's
   KECCAK256 opcode can't be used (different domain and padding), so keccak-f is written in Yul.
5. **matrix**: xoshiro256++ seeded with pre_pow_hash, 64 rows of 64 nibbles.
6. **heavy hash**: matrix times the pow hash's nibbles, top 4 bits, XOR, then cSHAKE256("HeavyHash"), the second keccak-f.
7. **target and level**: pow <= target(bits); level = max(225 - bitlen(pow), 0).

The rank check (rusty-kaspa regenerates the matrix until it has full rank) is measured separately and is
off in `verify`. See "the rank question" below.

## Run it on the node box

Paths assume the repo at `~/kaspa-zk/kaspa-zk-tests` and your mainnet node's wRPC Borsh port at
`ws://127.0.0.1:17110` (the one the prover service uses).

```bash
cd ~/kaspa-zk/kaspa-zk-tests/outbound/kpow

# 1. Vectors from your node: 200 chain blocks back from the sink (first build ~5 min; Rust in Docker,
#    host network so the container reaches 127.0.0.1:17110)
docker run --rm --network host -v "$PWD":/w -w /w/vectors \
  -v kpow-cargo-registry:/usr/local/cargo/registry -v kpow-cargo-git:/usr/local/cargo/git \
  rust:1.97-bookworm \
  cargo run --release --locked -- fetch --url ws://127.0.0.1:17110 --count 200 --out /w/sol/vectors.json

# 2. Foundry: forge-std (copy the one the vault already uses, or install it), then the tests
cd sol
cp -r ../../../vault/lib/forge-std lib/ 2>/dev/null || forge install foundry-rs/forge-std --no-git
forge test -vv
```

`forge test -vv` prints, per header: size in bytes, level, gas per stage, gas of one `verify` call, the
calldata gas, and the transaction total (21000 + verify + calldata). Then averages.

Offline check, no node: `KPOW_VECTORS=vectors.synth.json forge test -vv` (8 random headers; the PoW
doesn't pass on them, but every stage must still match rusty-kaspa).

The fetch summary also prints a histogram of block levels over the walked chain blocks: an early look at
the superblock counts for the weekend plan. It walks the selected chain only, not every DAG block.
Use `--count 36000` for about an hour of chain blocks.

## Reading the numbers

- **verify** is execution gas for one header as an external call. **TX TOTAL** is what a one-header
  transaction would cost. Multiply by the gas price for ETH. A relay batch of k headers costs about k × verify
  plus calldata, plus one transaction base.
- **Calldata** uses 16 gas per nonzero byte and 4 per zero byte. The EIP-7623 floor (10/40) only applies when execution
  gas is small next to calldata, which is not the case here.
- The keccak-f is a memory-based Yul loop, about 100k gas per permutation, and there are two per header. A
  stack-resident keccak could roughly halve that. Not attempted; the number here is an honest first port,
  not a floor.

## The rank question

rusty-kaspa keeps generating matrices until one has rank 64, checked in floating point. `verify` assumes the
first matrix is the one used (`matrixSkip = 0`). That is safe, and it is cheap:
- A 64x64 matrix with entries uniform in 0..15 is singular with astronomically small probability. The leading
  term is two equal rows, about 64²/2 × 16⁻⁶⁴ ≈ 10⁻⁷⁴. Rigorous bounds are asymptotic, so treat this as a strong
  heuristic. Every vector run checks it empirically: the summary prints the most matrix attempts it saw.
- Even if it happened, the effect is liveness, not safety. The contract would compute the wrong PoW for that one
  header and reject it, or an attacker would have to grind PoW against the wrong matrix, which is the same
  keccak work. A singular matrix does not make PoW easier, because the last step is a keccak.
- `matrixSkip` exists so a submitter could name a later matrix. Proving that the earlier ones were singular is not
  implemented.

`fullRank` (exact Gaussian elimination mod 2⁶⁴−59) is in the contract and measured for reference: about 11.8M
gas per header, unoptimized. It is not needed.

## Measured so far (synthetic headers, 558 to 4,582 bytes, in the dev sandbox)

| stage | gas |
|---|---|
| parse | 4k to 23k (grows with parent levels) |
| blake2b block hash | 10k to 63k (grows with header size) |
| blake2b pre_pow_hash | 14k to 67k |
| pow hash (1 keccak-f) | ~102k |
| matrix generation | ~67k |
| heavy hash (matvec + 1 keccak-f) | ~167k |
| **verify, one header** | **~460k** (430k to 560k) |
| calldata | 8k to 70k |
| rank check (not used) | ~11.8M |

Real headers set the size-dependent rows. Those numbers come from step 1 above.
