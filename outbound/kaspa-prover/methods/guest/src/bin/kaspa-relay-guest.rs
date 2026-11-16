//! kaspa-relay-guest: outbound stage O1. Verifies a superblock ladder from a checkpoint K to a tip B
//! (closed walks over `parents_by_level[L]`, every header PoW-checked), a burned-KAS transaction's
//! acceptance under B through the KIP-21 sequencing commitment, and commits the journal in
//! `kaspa_prover_primitives::relay::Journal` layout. All logic lives in the primitives crate so the
//! host runs the identical code natively against the node's values first.

use kaspa_prover_primitives::relay::{input_wants_soft_keccak, run};
use kaspa_prover_primitives::{KeccakF, SoftKeccak};
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
    let journal = if input_wants_soft_keccak(&input) { run::<SoftKeccak>(&input) } else { run::<GuestKeccak>(&input) };
    env::commit_slice(&journal.encode());
}
