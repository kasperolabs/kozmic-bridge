//! kaspa-header-guest: E1 of the outbound study. Verifies N Kaspa mainnet headers (blake2b block
//! hash and pre-PoW hash, kHeavyHash under each header's own `bits`, block level) and that each
//! header is a direct parent of the next, then commits the journal in
//! `kaspa_prover_primitives::Journal` layout. All logic lives in the primitives crate so the host
//! runs the identical code natively against rusty-kaspa's vectors.

use kaspa_prover_primitives::{input_wants_soft_keccak, run, KeccakF, SoftKeccak};
use risc0_zkvm::guest::env;

struct GuestKeccak;

impl KeccakF for GuestKeccak {
    #[inline(always)]
    fn f1600(state: &mut [u64; 25]) {
        env::risc0_keccak_update(state);
    }
}

fn main() {
    let input = env::read_frame();
    // One image, two keccak paths, chosen by the input so E1 can measure both: the zkVM's keccak
    // coprocessor (the real operating mode) and the plain software permutation.
    let journal = if input_wants_soft_keccak(&input) { run::<SoftKeccak>(&input) } else { run::<GuestKeccak>(&input) };
    env::commit_slice(&journal.encode());
}
