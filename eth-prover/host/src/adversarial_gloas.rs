//! Gloas pack adversarial suite for the execution-header witness: each case changes the witness in a
//! REAL Gloas input (written by `eth-prover fetch` against Sepolia) and asserts the guest refuses, and
//! that the honest input commits exactly the state root and number the witness carries.
//!
//!   ETH_PROVER_WITNESS_GLOAS=$(realpath sep.cbor) [ETH_PROVER_WITNESS_FULU=$(realpath main.cbor)] \
//!     cargo test --release -p eth-bridge-host -- adversarial_gloas --nocapture
//!
//! Skipped (with a note) when the env var is unset. Use absolute paths: cargo runs tests in the
//! package directory.
#![cfg(test)]

use alloy_primitives::{keccak256, Bytes};
use eth_bridge_methods::ETH_BRIDGE_GUEST_ELF;
use eth_bridge_primitives::{exec_header, Journal, ProofInputs};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use risc0_zkvm::{default_executor, ExecutorEnv};

type Inputs = ProofInputs<MainnetConsensusSpec>;

fn load(var: &str) -> Option<Inputs> {
    let path = std::env::var(var).ok()?;
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    Some(serde_cbor::from_slice(&bytes).expect("decode ProofInputs"))
}

fn run(inputs: &Inputs) -> Result<Journal, String> {
    std::env::set_var("RISC0_DEV_MODE", "1");
    let bytes = serde_cbor::to_vec(inputs).unwrap();
    let env = ExecutorEnv::builder().write_frame(&bytes).build().unwrap();
    let info = default_executor().execute(env, ETH_BRIDGE_GUEST_ELF).map_err(|e| format!("{e:#}"))?;
    Journal::decode(&info.journal.bytes).ok_or_else(|| "journal does not decode".into())
}

fn refused(inputs: &Inputs, case: &str) {
    match run(inputs) {
        Err(e) => println!("  {case}: refused ({})", e.lines().last().unwrap_or("").trim()),
        Ok(j) => panic!("{case}: the guest ACCEPTED a mutated witness; exec block {} root {}", j.exec_block_number, j.exec_state_root),
    }
}

fn with<F: FnOnce(&mut Inputs)>(base: &Inputs, f: F) -> Inputs {
    let mut i: Inputs = serde_cbor::from_slice(&serde_cbor::to_vec(base).unwrap()).unwrap();
    f(&mut i);
    i
}

#[test]
fn adversarial_gloas() {
    let Some(base) = load("ETH_PROVER_WITNESS_GLOAS") else {
        println!("ETH_PROVER_WITNESS_GLOAS unset: Gloas adversarial suite skipped");
        return;
    };
    let rlp = base.exec_header_rlp.clone().expect("a Gloas witness carries exec_header_rlp");
    let (sr, n) = exec_header::state_root_and_number(&rlp).expect("witness decodes");

    // 0. honest: the journal commits exactly the witness's state root and number
    let j = run(&base).expect("honest Gloas witness accepted");
    assert_eq!((j.exec_state_root, j.exec_block_number), (sr, n));
    println!("  honest: exec block {n}, state root {sr}, header hash {}", keccak256(&rlp));

    // 1. the witness left out
    refused(&with(&base, |i| i.exec_header_rlp = None), "witness missing");

    // 2. one byte flipped at the start, inside the state root, and at the end
    for (k, at) in [("first byte", 0usize), ("middle byte", rlp.len() / 2), ("last byte", rlp.len() - 1)] {
        refused(&with(&base, |i| {
            let mut b = rlp.to_vec();
            b[at] ^= 1;
            i.exec_header_rlp = Some(Bytes::from(b));
        }), &format!("{k} flipped"));
    }

    // 3. trailing garbage after the header
    refused(&with(&base, |i| {
        let mut b = rlp.to_vec();
        b.push(0x80);
        i.exec_header_rlp = Some(Bytes::from(b));
    }), "trailing byte");

    // 4. an empty witness
    refused(&with(&base, |i| i.exec_header_rlp = Some(Bytes::new())), "empty witness");

    // 5. a pre-Gloas input given a witness it must not carry
    if let Some(fulu) = load("ETH_PROVER_WITNESS_FULU") {
        let j = run(&fulu).expect("honest Fulu input accepted");
        println!("  Fulu honest: exec block {}", j.exec_block_number);
        refused(&with(&fulu, |i| i.exec_header_rlp = Some(Bytes::from(rlp.to_vec()))), "witness on a Fulu header");
    } else {
        println!("  ETH_PROVER_WITNESS_FULU unset: the Fulu cases skipped");
    }
}
