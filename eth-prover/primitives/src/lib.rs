//! Types shared by the guest (inside the zkVM) and the host (prover).
//!
//! The journal layout is fixed-width so a Kaspa covenant can `substr` fields
//! at constant offsets. No ABI encoding: this journal is read by script, not by
//! Solidity.
//!
//! CP-2 (2026-10-12): raw storage slots are gone. The guest knows Vault.sol's storage
//! layout (`vault_layout`), proves the two words of `deposits[nonce]` and commits the
//! decoded deposit (nonce, amount, kaspa_spk) as first-class journal fields. The covenant
//! never sees Solidity packing. Because the layout is compiled into the guest, the image
//! id pins it: a different vault layout is a different program.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::TrieAccount;
use helios_consensus_core::consensus_spec::ConsensusSpec;
use helios_consensus_core::types::{FinalityUpdate, Forks, LightClientStore, Update};
use serde::{Deserialize, Serialize};

/// Storage layout of `vault/src/Vault.sol` (asserted by `vault/test/Vault.t.sol`):
///
/// ```text
/// slot 0                                   nonce (uint64, low 8 bytes)
/// slot 1                                   deposits mapping base
/// keccak256(abi.encode(uint256(n), 1))     deposits[n] word 0: amount (bits 0..63) | kaspaVersion (bits 64..71)
/// keccak256(abi.encode(uint256(n), 1)) + 1 deposits[n] word 1: kaspaPayload (bytes32)
/// ```
pub mod vault_layout {
    use super::*;

    pub const DEPOSITS_SLOT: u64 = 1;

    /// Storage key of `deposits[nonce]` word 0.
    pub fn word0_key(nonce: u64) -> B256 {
        let mut buf = [0u8; 64];
        buf[24..32].copy_from_slice(&nonce.to_be_bytes());
        buf[56..64].copy_from_slice(&DEPOSITS_SLOT.to_be_bytes());
        keccak256(buf)
    }

    /// Storage key of `deposits[nonce]` word 1 (the next slot).
    pub fn word1_key(nonce: u64) -> B256 {
        let k = U256::from_be_bytes(word0_key(nonce).0).wrapping_add(U256::from(1u8));
        B256::from(k.to_be_bytes::<32>())
    }

    /// Decode word 0 into (amount, kaspa version). `None` if the word has bits set above
    /// bit 71 (not a Deposit written by this Vault), if the amount is zero, or if the
    /// version is not one the bridge accepts (0 = P2PK Schnorr, 8 = P2SH).
    pub fn decode_word0(w: U256) -> Option<(u64, u8)> {
        let b = w.to_be_bytes::<32>();
        if b[..23].iter().any(|x| *x != 0) {
            return None;
        }
        let version = b[23];
        let amount = u64::from_be_bytes(b[24..32].try_into().unwrap());
        if amount == 0 || !(version == 0 || version == 8) {
            return None;
        }
        Some((amount, version))
    }

    /// Inverse of `decode_word0`, for the host's dry run and tests.
    pub fn encode_word0(amount: u64, version: u8) -> U256 {
        let mut b = [0u8; 32];
        b[23] = version;
        b[24..32].copy_from_slice(&amount.to_be_bytes());
        U256::from_be_bytes(b)
    }
}

/// `deposits[nonce]` as two storage proofs from `eth_getProof`, plus the claimed values.
/// The guest verifies both words against the vault's storage root and refuses anything
/// `vault_layout::decode_word0` rejects.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DepositProof {
    pub nonce: u64,
    /// claimed value of word 0 (amount | version << 64)
    pub word0: U256,
    pub word0_proof: Vec<Bytes>,
    /// claimed value of word 1 (kaspa payload)
    pub payload: B256,
    pub payload_proof: Vec<Bytes>,
}

/// The vault account proof in the global state trie, plus the deposits to prove under it.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultDeposits {
    pub vault: Address,
    pub account: TrieAccount,
    /// account proof nodes in the global state trie
    pub account_proof: Vec<Bytes>,
    /// nonces must be strictly increasing (the journal is canonical; the covenant keeps a cursor)
    pub deposits: Vec<DepositProof>,
}

/// Everything the guest needs. Serialized with CBOR into the executor env.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "S: ConsensusSpec + Serialize + serde::de::DeserializeOwned")]
pub struct ProofInputs<S: ConsensusSpec> {
    /// Sync-committee-period updates to apply before the finality update, in order.
    /// Usually empty, or one (at a period boundary).
    pub sync_committee_updates: Vec<Update<S>>,
    pub finality_update: FinalityUpdate<S>,
    /// The wall-clock slot the host believes it is. Bounds update slots from above.
    pub expected_current_slot: u64,
    /// Light-client store at `checkpoint_in`. The guest requires
    /// `next_sync_committee == None`; committee rotation must come in as a signed update.
    pub store: LightClientStore<S>,
    pub genesis_root: B256,
    pub forks: Forks,
    /// Vault deposits to prove at the execution block of the new finalized header. None = heartbeat step.
    pub vault_deposits: Option<VaultDeposits>,
}

/// Binds the proof to one chain: genesis validators root + fork schedule.
/// The covenant pins this constant, so a proof from another chain with the
/// same program cannot open it.
pub fn compute_chain_commitment(genesis_root: B256, forks: &Forks) -> B256 {
    let forks_bytes = serde_cbor::to_vec(forks).expect("forks serialize");
    keccak256([genesis_root.as_slice(), &forks_bytes].concat())
}

/// Journal layout (byte offsets). All integers big-endian. Frozen 2026-10-12 (CP-2).
/// Bytes 0..208 are unchanged from the CP-4/CP-5 layout, so `bridge/bridge.sil` reads them as before.
pub mod journal {
    pub const CHAIN_COMMITMENT: usize = 0; // 32
    pub const PREV_HEADER: usize = 32; // 32  checkpoint_in  (finalized beacon header root)
    pub const PREV_COMMITTEE: usize = 64; // 32  sync committee hash at checkpoint_in
    pub const NEW_HEADER: usize = 96; // 32  checkpoint_out
    pub const NEW_COMMITTEE: usize = 128; // 32  sync committee hash at checkpoint_out
    pub const NEW_SLOT: usize = 160; // 8   beacon slot of checkpoint_out
    pub const EXEC_STATE_ROOT: usize = 168; // 32  execution state root at checkpoint_out
    pub const EXEC_BLOCK_NUMBER: usize = 200; // 8
    pub const VAULT: usize = 208; // 20  vault contract address (zero when no deposits are proven)
    pub const DEPOSIT_COUNT: usize = 228; // 2   number of deposits n
    pub const DEPOSITS: usize = 230; // n * (8 nonce | 8 amount | 33 kaspa_spk)
    pub const DEPOSIT_NONCE: usize = 0; // 8   offsets inside one deposit entry
    pub const DEPOSIT_AMOUNT: usize = 8; // 8
    pub const DEPOSIT_KASPA_SPK: usize = 16; // 33  version byte + 32-byte payload
    pub const DEPOSIT_ENTRY_LEN: usize = 49;
    pub const FIXED_LEN: usize = 230;
}

/// One proven deposit, as the journal carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    pub nonce: u64,
    /// token base units
    pub amount: u64,
    /// Kaspa address version byte (0 = P2PK Schnorr, 8 = P2SH) followed by the 32-byte payload
    pub kaspa_spk: [u8; 33],
}

/// Parsed view of a journal, for the host and tests. The guest only writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    pub chain_commitment: B256,
    pub prev_header: B256,
    pub prev_committee: B256,
    pub new_header: B256,
    pub new_committee: B256,
    pub new_slot: u64,
    pub exec_state_root: B256,
    pub exec_block_number: u64,
    pub vault: Address,
    pub deposits: Vec<Deposit>,
}

impl Journal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(journal::FIXED_LEN + self.deposits.len() * journal::DEPOSIT_ENTRY_LEN);
        out.extend_from_slice(self.chain_commitment.as_slice());
        out.extend_from_slice(self.prev_header.as_slice());
        out.extend_from_slice(self.prev_committee.as_slice());
        out.extend_from_slice(self.new_header.as_slice());
        out.extend_from_slice(self.new_committee.as_slice());
        out.extend_from_slice(&self.new_slot.to_be_bytes());
        out.extend_from_slice(self.exec_state_root.as_slice());
        out.extend_from_slice(&self.exec_block_number.to_be_bytes());
        out.extend_from_slice(self.vault.as_slice());
        out.extend_from_slice(&(self.deposits.len() as u16).to_be_bytes());
        for d in &self.deposits {
            out.extend_from_slice(&d.nonce.to_be_bytes());
            out.extend_from_slice(&d.amount.to_be_bytes());
            out.extend_from_slice(&d.kaspa_spk);
        }
        debug_assert_eq!(out.len(), journal::FIXED_LEN + self.deposits.len() * journal::DEPOSIT_ENTRY_LEN);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        use journal::*;
        if b.len() < FIXED_LEN {
            return None;
        }
        let n = u16::from_be_bytes([b[DEPOSIT_COUNT], b[DEPOSIT_COUNT + 1]]) as usize;
        if b.len() != FIXED_LEN + n * DEPOSIT_ENTRY_LEN {
            return None;
        }
        let b256 = |o: usize| B256::from_slice(&b[o..o + 32]);
        let u64be = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
        let mut deposits = Vec::with_capacity(n);
        for i in 0..n {
            let o = DEPOSITS + i * DEPOSIT_ENTRY_LEN;
            deposits.push(Deposit {
                nonce: u64be(o + DEPOSIT_NONCE),
                amount: u64be(o + DEPOSIT_AMOUNT),
                kaspa_spk: b[o + DEPOSIT_KASPA_SPK..o + DEPOSIT_KASPA_SPK + 33].try_into().unwrap(),
            });
        }
        Some(Journal {
            chain_commitment: b256(CHAIN_COMMITMENT),
            prev_header: b256(PREV_HEADER),
            prev_committee: b256(PREV_COMMITTEE),
            new_header: b256(NEW_HEADER),
            new_committee: b256(NEW_COMMITTEE),
            new_slot: u64be(NEW_SLOT),
            exec_state_root: b256(EXEC_STATE_ROOT),
            exec_block_number: u64be(EXEC_BLOCK_NUMBER),
            vault: Address::from_slice(&b[VAULT..VAULT + 20]),
            deposits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word0_roundtrip_and_rejects() {
        let w = vault_layout::encode_word0(1_000_000, 0);
        assert_eq!(w, U256::from(1_000_000u64));
        assert_eq!(vault_layout::decode_word0(w), Some((1_000_000, 0)));
        let w8 = vault_layout::encode_word0(7, 8);
        assert_eq!(w8, U256::from(7u64) | (U256::from(8u64) << 64usize));
        assert_eq!(vault_layout::decode_word0(w8), Some((7, 8)));
        assert_eq!(vault_layout::decode_word0(U256::ZERO), None);
        assert_eq!(vault_layout::decode_word0(vault_layout::encode_word0(1, 1)), None);
        assert_eq!(vault_layout::decode_word0(w | (U256::from(1u64) << 72usize)), None);
    }

    #[test]
    fn deposit_keys_match_cast_index() {
        // `cast index uint256 1 1` and the anvil run in vault/README.md
        assert_eq!(
            format!("{}", vault_layout::word0_key(1)),
            "0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f"
        );
        assert_eq!(
            format!("{}", vault_layout::word1_key(1)),
            "0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b6887930"
        );
    }

    #[test]
    fn journal_roundtrip() {
        let j = Journal {
            chain_commitment: B256::repeat_byte(1),
            prev_header: B256::repeat_byte(2),
            prev_committee: B256::repeat_byte(3),
            new_header: B256::repeat_byte(4),
            new_committee: B256::repeat_byte(5),
            new_slot: 15_416_800,
            exec_state_root: B256::repeat_byte(6),
            exec_block_number: 26_178_080,
            vault: Address::repeat_byte(7),
            deposits: vec![Deposit { nonce: 1, amount: 1_000_000, kaspa_spk: [9u8; 33] }],
        };
        let bytes = j.encode();
        assert_eq!(bytes.len(), 230 + 49);
        assert_eq!(Journal::decode(&bytes), Some(j.clone()));
        let empty = Journal { deposits: vec![], vault: Address::ZERO, ..j };
        assert_eq!(empty.encode().len(), 230);
        assert_eq!(Journal::decode(&empty.encode()), Some(empty));
    }
}
