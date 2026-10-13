//! Ethereum beacon-chain light client step, proven inside the RISC Zero zkVM.
//!
//! Private input: a light-client store at checkpoint_in, zero or more sync-committee
//! updates, one finality update, and optionally the vault's deposits to prove.
//! Public output (journal): checkpoint_in, checkpoint_out, the sync committee hashes
//! at both, the execution state root at checkpoint_out, the vault address and the
//! verified deposits (nonce, amount, kaspa_spk).
//!
//! Everything the journal says about checkpoint_out is backed by a BLS aggregate
//! signature of the sync committee that the store (i.e. the covenant state) names.
//! Everything it says about a deposit is backed by Merkle-Patricia proofs against the
//! execution state root of that finalized header, decoded with Vault.sol's storage
//! layout, which is compiled into this program (so the image id pins it).
//! Derived from risc0/r0vm-helios (MIT), ported to risc0 3.0.4 and helios 0.12.0.
//!
//! Two binaries wrap `run`: `eth-bridge-guest` (mainnet spec: 512-member committees,
//! the real thing) and `eth-bridge-guest-minimal` (minimal spec, 32-member committees,
//! only for running the consensus-spec test vectors offline).

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable;
use alloy_trie::{proof, Nibbles};
use eth_bridge_primitives::{
    compute_chain_commitment, vault_layout, Deposit, Journal, ProofInputs, VaultDeposits,
};
use helios_consensus_core::consensus_spec::ConsensusSpec;
use helios_consensus_core::{
    apply_finality_update, apply_update, verify_finality_update, verify_update,
};
use risc0_zkvm::guest::env;
use tree_hash::TreeHash;

pub fn run<S: ConsensusSpec + serde::Serialize + serde::de::DeserializeOwned>() {
    let encoded_inputs = env::read_frame();
    let ProofInputs::<S> {
        sync_committee_updates,
        finality_update,
        expected_current_slot,
        mut store,
        genesis_root,
        forks,
        vault_deposits,
    } = serde_cbor::from_slice(&encoded_inputs).expect("decode inputs");

    // The prover does not get to assert a next committee. If the period rolls over,
    // the committee must arrive as a signed Update (verified below).
    assert!(
        store.next_sync_committee.is_none(),
        "input store must not carry next_sync_committee"
    );
    assert!(
        store.best_valid_update.is_none(),
        "input store must not carry best_valid_update"
    );

    let prev_header: B256 = store.finalized_header.beacon().tree_hash_root();
    let prev_committee: B256 = store.current_sync_committee.tree_hash_root();

    // 1. Sync committee updates (period boundaries), each signed by the committee we trust.
    for (i, update) in sync_committee_updates.iter().enumerate() {
        verify_update::<S>(update, expected_current_slot, &store, genesis_root, &forks)
            .unwrap_or_else(|e| panic!("sync committee update {} invalid: {e}", i + 1));
        apply_update::<S>(&mut store, update);
    }

    // 2. Finality update, signed by the (possibly rotated) committee.
    verify_finality_update::<S>(
        &finality_update,
        expected_current_slot,
        &store,
        genesis_root,
        &forks,
    )
    .unwrap_or_else(|e| panic!("finality update invalid: {e}"));
    apply_finality_update::<S>(&mut store, &finality_update);

    // 3. The store must have actually advanced to the update's finalized header.
    //    apply_* silently skips updates below 2/3 participation; we refuse to
    //    publish a proof that says nothing new.
    let new_header: B256 = store.finalized_header.beacon().tree_hash_root();
    let update_finalized: B256 = finality_update
        .finalized_header()
        .beacon()
        .tree_hash_root();
    assert_eq!(
        new_header, update_finalized,
        "finality update not applied (participation < 2/3?)"
    );
    assert_ne!(new_header, prev_header, "no progress");

    let new_committee: B256 = store.current_sync_committee.tree_hash_root();
    let new_slot = store.finalized_header.beacon().slot;

    // 4. Execution state root at the new finalized header.
    let exec = store
        .finalized_header
        .execution()
        .expect("finalized header has no execution payload (pre-Capella or Gloas header)");
    let exec_state_root = *exec.state_root();
    let exec_block_number = *exec.block_number();

    // 5. Vault deposits against that state root.
    let (vault, deposits) = match vault_deposits {
        Some(vd) => verify_vault_deposits(exec_state_root, vd),
        None => (Address::ZERO, Vec::new()),
    };

    let journal = Journal {
        chain_commitment: compute_chain_commitment(genesis_root, &forks),
        prev_header,
        prev_committee,
        new_header,
        new_committee,
        new_slot,
        exec_state_root,
        exec_block_number,
        vault,
        deposits,
    };
    env::commit_slice(&journal.encode());
}

/// Verify one storage slot of an account: key = keccak(slot key), value = rlp(U256).
/// A zero value is an absent key in the trie, so callers must never claim zero.
fn verify_slot(storage_root: B256, key: B256, value: U256, mpt_proof: &[Bytes]) {
    assert!(!value.is_zero(), "zero storage value: slot {key} is unset");
    let key_hash = keccak256(key.as_slice());
    let key_nibbles = Nibbles::unpack(Bytes::copy_from_slice(key_hash.as_ref()));
    let mut rlp_value = Vec::new();
    value.encode(&mut rlp_value);
    proof::verify_proof(storage_root, key_nibbles, Some(rlp_value), mpt_proof)
        .unwrap_or_else(|e| panic!("storage proof invalid for slot {key}: {e}"));
}

fn verify_vault_deposits(execution_state_root: B256, vd: VaultDeposits) -> (Address, Vec<Deposit>) {
    assert!(!vd.deposits.is_empty(), "vault_deposits given but no deposits listed");

    // Account node in the global state trie: key = keccak(address), value = rlp(TrieAccount).
    let address_hash = keccak256(vd.vault.as_slice());
    let address_nibbles = Nibbles::unpack(Bytes::copy_from_slice(address_hash.as_ref()));
    let mut rlp_account = Vec::new();
    vd.account.encode(&mut rlp_account);
    proof::verify_proof(
        execution_state_root,
        address_nibbles,
        Some(rlp_account),
        &vd.account_proof,
    )
    .unwrap_or_else(|e| panic!("account proof invalid for {}: {e}", vd.vault));

    let storage_root = vd.account.storage_root;
    let mut out = Vec::with_capacity(vd.deposits.len());
    let mut last_nonce = 0u64;
    for d in vd.deposits {
        assert!(d.nonce > last_nonce, "deposit nonces must be strictly increasing and nonzero");
        last_nonce = d.nonce;

        // deposits[nonce] word 0: amount | kaspaVersion << 64. Both words are proven
        // against the vault's storage root at the finalized block.
        verify_slot(storage_root, vault_layout::word0_key(d.nonce), d.word0, &d.word0_proof);
        verify_slot(
            storage_root,
            vault_layout::word1_key(d.nonce),
            U256::from_be_bytes(d.payload.0),
            &d.payload_proof,
        );
        let (amount, version) = vault_layout::decode_word0(d.word0)
            .unwrap_or_else(|| panic!("deposit {} word 0 is not a Vault deposit: {}", d.nonce, d.word0));

        let mut kaspa_spk = [0u8; 33];
        kaspa_spk[0] = version;
        kaspa_spk[1..].copy_from_slice(d.payload.as_slice());
        out.push(Deposit { nonce: d.nonce, amount, kaspa_spk });
    }
    (vd.vault, out)
}
