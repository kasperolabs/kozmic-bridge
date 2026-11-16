//! Types shared by the guest (inside the zkVM) and the host (prover).
//!
//! The journal layout is fixed-width so a Kaspa covenant can `substr` fields
//! at constant offsets. No ABI encoding: this journal is read by script, not by
//! Solidity.
//!
//! v2 (U3, 2026-10-16; `docs/INBOUND-JOURNAL-V2.md`, `usdc/LAYOUT.md`): the vault is
//! `usdc/src/UsdcVault.sol`, whose deposit record carries the depositor in word 0. The guest
//! additionally proves, against the same execution state root, the token's account, the
//! token proxy's implementation slot (committed so the covenant can pin it) and one word of
//! the token's `balanceAndBlacklistStates` mapping per deposit, whose bit 255 is Circle's
//! blacklist flag; each journal entry carries a status byte (0 mint, 1 skip). Bytes 0..228 of
//! the journal are the v1 layout unchanged.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::TrieAccount;
use helios_consensus_core::consensus_spec::ConsensusSpec;
use helios_consensus_core::types::{FinalityUpdate, Forks, LightClientStore, Update};
use serde::{Deserialize, Serialize};

/// Gloas pack: the execution block of a finalized light-client header, for both header forms.
pub mod exec_header;
pub use exec_header::exec_point;

/// Storage layout of `usdc/src/UsdcVault.sol` (asserted by `usdc/test/UsdcVault.t.sol`):
///
/// ```text
/// slot 0                                   nonce (uint64, low 8 bytes)
/// slot 1                                   deposits mapping base
/// keccak256(abi.encode(uint256(n), 1))     deposits[n] word 0: amount (bits 0..63) | kaspaVersion (bits 64..71)
///                                                              | depositor (bits 72..231); bits 232..255 zero
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

    /// Decode word 0 into (amount, kaspa version, depositor). `None` if bits 232..255 are set
    /// (not a record this vault writes), if the amount is zero, if the version is not one the
    /// bridge accepts (0 = P2PK Schnorr, 8 = P2SH), or if the depositor is zero (a v1 Vault.sol
    /// record; this guest is for UsdcVault only).
    pub fn decode_word0(w: U256) -> Option<(u64, u8, Address)> {
        let b = w.to_be_bytes::<32>();
        if b[..3].iter().any(|x| *x != 0) {
            return None;
        }
        let depositor = Address::from_slice(&b[3..23]);
        let version = b[23];
        let amount = u64::from_be_bytes(b[24..32].try_into().unwrap());
        if amount == 0 || !(version == 0 || version == 8) || depositor.is_zero() {
            return None;
        }
        Some((amount, version, depositor))
    }

    /// Inverse of `decode_word0`, for the host's dry run and tests.
    pub fn encode_word0(amount: u64, version: u8, depositor: Address) -> U256 {
        let mut b = [0u8; 32];
        b[3..23].copy_from_slice(depositor.as_slice());
        b[23] = version;
        b[24..32].copy_from_slice(&amount.to_be_bytes());
        U256::from_be_bytes(b)
    }
}

/// Storage layout of Circle's FiatTokenV2_2 (USDC implementation `0x43506849…02dd`, read from the deployed
/// bytecode, `docs/USDC-BLACKLIST-STUDY.md`) and of its ZeppelinOS proxy.
pub mod token_layout {
    use super::*;

    /// `keccak256("org.zeppelinos.proxy.implementation")`: the proxy's implementation address (low 20 bytes).
    pub const IMPLEMENTATION_SLOT: B256 = B256::new([
        0x70, 0x50, 0xc9, 0xe0, 0xf4, 0xca, 0x76, 0x9c, 0x69, 0xbd, 0x3a, 0x8e, 0xf7, 0x40, 0xbc, 0x37,
        0x93, 0x4f, 0x8e, 0x2c, 0x03, 0x6e, 0x5a, 0x72, 0x3f, 0xd8, 0xee, 0x04, 0x8e, 0xd3, 0xf8, 0xc3,
    ]);

    /// `balanceAndBlacklistStates` mapping slot in FiatTokenV2_2.
    pub const BALANCE_AND_BLACKLIST_SLOT: u64 = 9;

    /// Storage key of `balanceAndBlacklistStates[account]` = keccak256(abi.encode(account, 9)).
    pub fn blacklist_key(account: Address) -> B256 {
        let mut buf = [0u8; 64];
        buf[12..32].copy_from_slice(account.as_slice());
        buf[56..64].copy_from_slice(&BALANCE_AND_BLACKLIST_SLOT.to_be_bytes());
        keccak256(buf)
    }

    /// Bit 255 of the word: set means blacklisted; the low 255 bits are the balance.
    pub fn is_blacklisted(word: U256) -> bool {
        word.bit(255)
    }
}

/// `deposits[nonce]` as two storage proofs from `eth_getProof`, plus the claimed values, plus the
/// proof of the depositor's blacklist word in the token's storage (v2).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DepositProof {
    pub nonce: u64,
    /// claimed value of word 0 (amount | version << 64 | depositor << 72)
    pub word0: U256,
    pub word0_proof: Vec<Bytes>,
    /// claimed value of word 1 (kaspa payload)
    pub payload: B256,
    pub payload_proof: Vec<Bytes>,
    /// claimed value of `balanceAndBlacklistStates[depositor]` (zero = absent key = never held the token)
    #[serde(default)]
    pub blacklist_word: U256,
    /// its proof against the token's storage root (an exclusion proof when the word is zero)
    #[serde(default)]
    pub blacklist_proof: Vec<Bytes>,
}

/// The vault account proof in the global state trie, the deposits to prove under it, and (v2) the
/// token account with its implementation slot.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultDeposits {
    pub vault: Address,
    pub account: TrieAccount,
    /// account proof nodes in the global state trie
    pub account_proof: Vec<Bytes>,
    /// nonces must be strictly increasing (the journal is canonical; the covenant keeps a cursor)
    pub deposits: Vec<DepositProof>,
    /// the ERC-20 (USDC proxy) whose blacklist is read
    #[serde(default)]
    pub token: Address,
    #[serde(default)]
    pub token_account: TrieAccount,
    #[serde(default)]
    pub token_account_proof: Vec<Bytes>,
    /// claimed value of the implementation slot (low 20 bytes = the implementation address)
    #[serde(default)]
    pub implementation_word: U256,
    #[serde(default)]
    pub implementation_proof: Vec<Bytes>,
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
    /// Gloas pack: the execution block header (RLP) whose keccak is the finalized header's
    /// execution_block_hash. Required for a Gloas header, refused before Gloas (exec_header.rs).
    #[serde(default)]
    pub exec_header_rlp: Option<Bytes>,
}

/// Binds the proof to one chain: genesis validators root + fork schedule.
/// The covenant pins this constant, so a proof from another chain with the
/// same program cannot open it.
pub fn compute_chain_commitment(genesis_root: B256, forks: &Forks) -> B256 {
    let forks_bytes = serde_cbor::to_vec(forks).expect("forks serialize");
    keccak256([genesis_root.as_slice(), &forks_bytes].concat())
}

/// Journal layout (byte offsets). All integers big-endian. v2, frozen 2026-10-16 (U3).
/// Bytes 0..228 are the v1 layout unchanged, so the light-client part of `bridge.sil` reads them as before.
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
    pub const TOKEN: usize = 228; // 20  the ERC-20 whose blacklist was read (zero when no deposits)
    pub const IMPLEMENTATION: usize = 248; // 20  that token proxy's implementation at exec_state_root (zero when no deposits)
    pub const DEPOSIT_COUNT: usize = 268; // 2   number of deposits n
    pub const DEPOSITS: usize = 270; // n * (8 nonce | 8 amount | 33 kaspa_spk | 1 status)
    pub const DEPOSIT_NONCE: usize = 0; // 8   offsets inside one deposit entry
    pub const DEPOSIT_AMOUNT: usize = 8; // 8
    pub const DEPOSIT_KASPA_SPK: usize = 16; // 33  version byte + 32-byte payload
    pub const DEPOSIT_STATUS: usize = 49; // 1   0 = mint, 1 = skip (depositor blacklisted)
    pub const DEPOSIT_ENTRY_LEN: usize = 50;
    pub const FIXED_LEN: usize = 270;
}

pub const STATUS_MINT: u8 = 0;
pub const STATUS_SKIP: u8 = 1;

/// One proven deposit, as the journal carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    pub nonce: u64,
    /// token base units
    pub amount: u64,
    /// Kaspa address version byte (0 = P2PK Schnorr, 8 = P2SH) followed by the 32-byte payload
    pub kaspa_spk: [u8; 33],
    /// STATUS_MINT or STATUS_SKIP
    pub status: u8,
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
    pub token: Address,
    pub implementation: Address,
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
        out.extend_from_slice(self.token.as_slice());
        out.extend_from_slice(self.implementation.as_slice());
        out.extend_from_slice(&(self.deposits.len() as u16).to_be_bytes());
        for d in &self.deposits {
            out.extend_from_slice(&d.nonce.to_be_bytes());
            out.extend_from_slice(&d.amount.to_be_bytes());
            out.extend_from_slice(&d.kaspa_spk);
            out.push(d.status);
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
        let addr = |o: usize| Address::from_slice(&b[o..o + 20]);
        let mut deposits = Vec::with_capacity(n);
        for i in 0..n {
            let o = DEPOSITS + i * DEPOSIT_ENTRY_LEN;
            let status = b[o + DEPOSIT_STATUS];
            if status != STATUS_MINT && status != STATUS_SKIP {
                return None;
            }
            deposits.push(Deposit {
                nonce: u64be(o + DEPOSIT_NONCE),
                amount: u64be(o + DEPOSIT_AMOUNT),
                kaspa_spk: b[o + DEPOSIT_KASPA_SPK..o + DEPOSIT_KASPA_SPK + 33].try_into().unwrap(),
                status,
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
            vault: addr(VAULT),
            token: addr(TOKEN),
            implementation: addr(IMPLEMENTATION),
            deposits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPOSITOR: Address = Address::new([0xA1; 20]);

    #[test]
    fn word0_roundtrip_and_rejects() {
        let w = vault_layout::encode_word0(1_000_000, 0, DEPOSITOR);
        assert_eq!(vault_layout::decode_word0(w), Some((1_000_000, 0, DEPOSITOR)));
        let w8 = vault_layout::encode_word0(7, 8, DEPOSITOR);
        assert_eq!(vault_layout::decode_word0(w8), Some((7, 8, DEPOSITOR)));
        // the layout the Foundry test asserted: amount bits 0..63, version 64..71, depositor 72..231
        assert_eq!(w8 & U256::from(u64::MAX), U256::from(7u64));
        assert_eq!((w8 >> 64usize) & U256::from(0xffu64), U256::from(8u64));
        assert_eq!(Address::from_slice(&(w8 >> 72usize).to_be_bytes::<32>()[12..]), DEPOSITOR);
        assert_eq!(vault_layout::decode_word0(U256::ZERO), None);
        assert_eq!(vault_layout::decode_word0(vault_layout::encode_word0(1, 1, DEPOSITOR)), None);
        assert_eq!(vault_layout::decode_word0(w | (U256::from(1u64) << 232usize)), None);
        // a v1 Vault.sol record (no depositor) is refused by the v2 guest
        assert_eq!(vault_layout::decode_word0(vault_layout::encode_word0(5, 0, Address::ZERO)), None);
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
    fn token_layout_matches_mainnet_probe() {
        // U0 (2026-10-16): `cast storage USDC 0x7050c9e0…f8c3` -> 0x…43506849d7c04f9138d1a2050bbf3a0c054402dd
        assert_eq!(
            format!("{}", token_layout::IMPLEMENTATION_SLOT),
            "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
        );
        // `cast index address 0x085488e7310064bf7306e7b7a75dd0590354853a 9`, the blacklisted address of the probe
        let a: Address = "0x085488e7310064bf7306e7b7a75dd0590354853a".parse().unwrap();
        let expected_key = keccak256({
            let mut b = [0u8; 64];
            b[12..32].copy_from_slice(a.as_slice());
            b[63] = 9;
            b
        });
        assert_eq!(token_layout::blacklist_key(a), expected_key);
        // its slot-9 word on mainnet: 0x8000…0020903b28e4 (blacklisted, balance 139,858.749668)
        let w = U256::from_be_bytes({
            let mut b = [0u8; 32];
            b[0] = 0x80;
            b[27..32].copy_from_slice(&[0x20, 0x90, 0x3b, 0x28, 0xe4]);
            b
        });
        assert!(token_layout::is_blacklisted(w));
        assert_eq!(w & (U256::MAX >> 1usize), U256::from(139_858_749_668u64));
        // the PoolManager word: 0x…2959fd25e593, clear
        assert!(!token_layout::is_blacklisted(U256::from(0x2959fd25e593u64)));
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
            token: Address::repeat_byte(8),
            implementation: Address::repeat_byte(9),
            deposits: vec![
                Deposit { nonce: 1, amount: 1_000_000, kaspa_spk: [9u8; 33], status: STATUS_MINT },
                Deposit { nonce: 2, amount: 10, kaspa_spk: [8u8; 33], status: STATUS_SKIP },
            ],
        };
        let bytes = j.encode();
        assert_eq!(bytes.len(), 270 + 2 * 50);
        assert_eq!(&bytes[..228], &{
            // bytes 0..228 are the v1 layout: nothing before the vault moved
            let mut v = Vec::new();
            for x in [1u8, 2, 3, 4, 5] { v.extend_from_slice(&[x; 32]); }
            v.extend_from_slice(&15_416_800u64.to_be_bytes());
            v.extend_from_slice(&[6u8; 32]);
            v.extend_from_slice(&26_178_080u64.to_be_bytes());
            v.extend_from_slice(&[7u8; 20]);
            v
        }[..]);
        assert_eq!(Journal::decode(&bytes), Some(j.clone()));
        let empty = Journal { deposits: vec![], vault: Address::ZERO, token: Address::ZERO, implementation: Address::ZERO, ..j };
        assert_eq!(empty.encode().len(), 270);
        assert_eq!(Journal::decode(&empty.encode()), Some(empty));
        // a status byte outside {0, 1} does not decode
        let mut bad = bytes.clone();
        bad[270 + 49] = 2;
        assert_eq!(Journal::decode(&bad), None);
    }
}
