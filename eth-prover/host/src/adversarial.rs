//! U3 adversarial suite for the inbound guest v2: each case changes one thing in a REAL witness (the cbor
//! that `eth-prover fetch` wrote against the mainnet dev-test vault) and asserts that the guest either refuses
//! (the executor returns an error: the proof cannot exist) or, where the mutated witness is an honest but
//! different one, that the journal only gets weaker.
//!
//!   ETH_PROVER_WITNESS=/tmp/u3-devtest.cbor cargo test -p eth-bridge-host -- adversarial --nocapture
//!
//! The witness must carry two deposits: nonce 1 from a clean depositor (status mint) and nonce 2 from a
//! blacklisted one (status skip). Skipped (with a note) when the env var is unset.
#![cfg(test)]

use alloy_primitives::{Address, U256};
use eth_bridge_methods::ETH_BRIDGE_GUEST_ELF;
use eth_bridge_primitives::{token_layout, vault_layout, Journal, ProofInputs, STATUS_MINT, STATUS_SKIP};
use helios_consensus_core::consensus_spec::MainnetConsensusSpec;
use risc0_zkvm::{default_executor, ExecutorEnv};

type Inputs = ProofInputs<MainnetConsensusSpec>;

fn witness() -> Option<Inputs> {
    let path = std::env::var("ETH_PROVER_WITNESS").ok()?;
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    Some(serde_cbor::from_slice(&bytes).expect("decode ProofInputs"))
}

/// Runs the guest in dev mode (executor only). Ok(journal) or Err(the guest's panic).
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
        Ok(j) => panic!("{case}: the guest ACCEPTED a mutated witness; journal {:?}", j.deposits),
    }
}

fn with<F: FnOnce(&mut Inputs)>(base: &Inputs, f: F) -> Inputs {
    let mut i: Inputs = serde_cbor::from_slice(&serde_cbor::to_vec(base).unwrap()).unwrap();
    f(&mut i);
    i
}

#[test]
fn adversarial() {
    let Some(base) = witness() else {
        println!("ETH_PROVER_WITNESS unset: adversarial suite skipped");
        return;
    };
    let vd = base.vault_deposits.as_ref().expect("witness has vault_deposits");
    assert_eq!(vd.deposits.len(), 2, "the suite expects nonces 1 (clean) and 2 (blacklisted)");

    // 0. the honest witness: two deposits, statuses mint and skip, token and implementation committed
    let j = run(&base).expect("honest witness accepted");
    assert_eq!(j.deposits.len(), 2);
    assert_eq!(j.deposits[0].status, STATUS_MINT);
    assert_eq!(j.deposits[1].status, STATUS_SKIP);
    assert_eq!(j.token, vd.token);
    assert_eq!(j.implementation, Address::from_slice(&vd.implementation_word.to_be_bytes::<32>()[12..]));
    assert!(token_layout::is_blacklisted(vd.deposits[1].blacklist_word));
    assert!(!token_layout::is_blacklisted(vd.deposits[0].blacklist_word));
    println!("  honest: 2 deposits, statuses [mint, skip], implementation {}", j.implementation);

    // 1. a blacklisted depositor presented as clean: his word claimed zero (absent) with his real proof
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[1];
        d.blacklist_word = U256::ZERO;
    }), "blacklisted claimed absent");

    // 2. the same, claiming his word with bit 255 cleared
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[1];
        d.blacklist_word &= U256::MAX >> 1usize;
    }), "blacklisted claimed clear");

    // 3. the clean depositor presented as blacklisted (bit set on his real word)
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[0];
        d.blacklist_word |= U256::from(1u8) << 255usize;
    }), "clean claimed blacklisted");

    // 4. the two depositors' blacklist proofs swapped (each key then proves the other's word)
    refused(&with(&base, |i| {
        let ds = &mut i.vault_deposits.as_mut().unwrap().deposits;
        let (a, b) = (ds[0].blacklist_proof.clone(), ds[1].blacklist_proof.clone());
        ds[0].blacklist_proof = b;
        ds[1].blacklist_proof = a;
    }), "blacklist proofs swapped");

    // 5. a truncated blacklist proof
    refused(&with(&base, |i| {
        i.vault_deposits.as_mut().unwrap().deposits[1].blacklist_proof.pop();
    }), "truncated blacklist proof");

    // 6. the implementation slot claimed as another address
    refused(&with(&base, |i| {
        let v = i.vault_deposits.as_mut().unwrap();
        v.implementation_word = U256::from_be_bytes(Address::repeat_byte(0x42).into_word().0);
    }), "wrong implementation");

    // 7. the token pointed at the vault (the account proof is for another address)
    refused(&with(&base, |i| {
        let v = i.vault_deposits.as_mut().unwrap();
        v.token = v.vault;
    }), "token is the vault");

    // 8. the vault pointed at the token
    refused(&with(&base, |i| {
        let v = i.vault_deposits.as_mut().unwrap();
        v.vault = v.token;
    }), "vault is the token");

    // 9. the depositor rewritten in word 0 (the vault proof no longer matches)
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[0];
        let (amount, version, _) = vault_layout::decode_word0(d.word0).unwrap();
        d.word0 = vault_layout::encode_word0(amount, version, Address::repeat_byte(0x99));
    }), "depositor rewritten");

    // 10. a v1 Vault.sol record (no depositor) with a matching-looking proof: refused by the decoder
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[0];
        let (amount, version, _) = vault_layout::decode_word0(d.word0).unwrap();
        d.word0 = vault_layout::encode_word0(amount, version, Address::ZERO);
    }), "v1 record without depositor");

    // 11. bits above 231 set in word 0
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[0];
        d.word0 |= U256::from(1u8) << 240usize;
    }), "word0 high bits");

    // 12. nonces out of order
    refused(&with(&base, |i| {
        i.vault_deposits.as_mut().unwrap().deposits.swap(0, 1);
    }), "nonces out of order");

    // 13. the same nonce twice
    refused(&with(&base, |i| {
        let ds = &mut i.vault_deposits.as_mut().unwrap().deposits;
        let d = ds[0].clone();
        ds.push(d);
    }), "duplicate nonce");

    // 14. vault_deposits present with no deposits
    refused(&with(&base, |i| {
        i.vault_deposits.as_mut().unwrap().deposits.clear();
    }), "no deposits listed");

    // 15. the amount rewritten in word 0 (proof mismatch)
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[1];
        let (amount, version, depositor) = vault_layout::decode_word0(d.word0).unwrap();
        d.word0 = vault_layout::encode_word0(amount + 1, version, depositor);
    }), "amount rewritten");

    // 16. the kaspa payload rewritten
    refused(&with(&base, |i| {
        let d = &mut i.vault_deposits.as_mut().unwrap().deposits[0];
        d.payload.0[31] ^= 1;
    }), "payload rewritten");

    // 17. honest but weaker: the blacklisted deposit left out; the journal has one deposit, status mint
    let j = run(&with(&base, |i| {
        i.vault_deposits.as_mut().unwrap().deposits.truncate(1);
    })).expect("one clean deposit is an honest witness");
    assert_eq!(j.deposits.len(), 1);
    assert_eq!(j.deposits[0].status, STATUS_MINT);
    println!("  blacklisted deposit omitted: accepted with 1 deposit (the cursor never passes nonce 2 this way)");

    // 18. heartbeat shape: no vault_deposits at all; token and implementation zero in the journal
    let j = run(&with(&base, |i| {
        i.vault_deposits = None;
    })).expect("heartbeat shape accepted");
    assert!(j.deposits.is_empty());
    assert_eq!(j.token, Address::ZERO);
    assert_eq!(j.implementation, Address::ZERO);
    println!("  heartbeat shape: accepted, token and implementation zero");
}
