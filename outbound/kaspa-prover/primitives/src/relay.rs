//! Outbound relay guest v4 (S2 of the 11-08 plan, `KZO6` after the 11-08 review; `KZO5` was the pre-review
//! layout, docs/V4-DESIGN.md 2.11 and 2.14): the program in plain Rust so
//! the host runs the identical code natively and the guest runs it in the zkVM. v3 (`KZO4`, dev-mode only, commit
//! a86d896) and v2 (`KZO3`, image 110d48d6…, commit 59cdd3c) are the previous revisions; Wobbly.k and Sepia.k keep v2.
//!
//! What changes from v3, and nothing else:
//!   - no checkpoint. The ladders are walked from T down to B, the chain block every burn's commitment chain ends
//!     at: headers at or below B's daa score are leaves (PoW-verified, not expanded, not counted). K, its daa, bits
//!     and blue work are gone from the witness and the journal. What binds the count to B is the attestation: an
//!     attester's first-parent path reaches a block carrying a commitment that descends from B's, so it was mined
//!     after B; T descends from its attesters; and every burn was accepted at or before B. Nothing chains proof to
//!     proof, so the pruning horizon no longer bounds the relay, and a burn after a month of silence proves fine;
//!   - the journal carries the proof's own difficulty reading `r_bits`: the median compact target over the
//!     ATTESTING superblocks, by target. A median and not a maximum, because `bits` is free up to the hash and a
//!     superblock's level is absolute (`median_bits`); over the attesters and not over everything expanded, because
//!     a non-attesting superblock can be premined with any `daa` and `bits` and planted beside the honest ladder
//!     (REVIEW-2026-11-08 F15), while an attester commits to the beacon and so was mined after it. The relay takes
//!     max(its stored 7-day history, this reading) as the rate reference and stores the reading on settlement;
//!   - the witness names the prover's Ethereum address and the journal carries it; the relay pays the tip to that
//!     address, so a copied proof cannot take the tip (REVIEW-2026-11-08 F16);
//!   - the anchor is as v3: the burn beacon with the highest Ethereum block number. All attesters follow all burns
//!     (B accepted every burn, attesters follow B), and a burn cannot carry a future block hash, so every attester
//!     was mined after the freshest beacon; its tau is the tightest bound for every burn in the batch. A burn whose
//!     own beacon has aged out of EIP-2935 is therefore rescued by any later burn in the same proof.
//!
//! What a relay proof states, for the attested block B and a tip T:
//!   1. Every header in the witness passes PoW (E1 verifier) and is listed once.
//!   2. For every ladder level L: the closed walk from T along `parents_by_level[L]` over PoW-verified headers;
//!      every level-L parent of every expanded header is in the witness; headers whose claimed daa_score is at or
//!      below B's are leaves (verified, not expanded, not counted); the count of expanded headers (level >= L,
//!      daa_score > B's) is committed. T is at level >= L_max and after B.
//!   3. Each burn transaction (1 to 16 per proof, body given) has id `tx_id` (rusty-kaspa v2.1.0
//!      `hashing/tx.rs`, version 1), is in the native lane, and creates the KCC-20 reference cells the
//!      witness names (as v2). The transaction carries the payload v3 `"KZB1" | 0x03 | target(20) | tip(8, BE) |
//!      recipient(20) | beacon_number(8, BE) | beacon_hash(32)` (beacon zero = none) or the v2 payload (no
//!      beacon); `tip < amount`. All burns in one proof name the same target; no tx id repeats; at least one burn
//!      carries a beacon, and the one with the highest beacon number is the anchor (two beacons with that
//!      number must agree).
//!   4. Each burn's activity leaf is in the native lane's activity digest of its chain block C, chained through
//!      seq_commit to B's `accepted_id_merkle_root` (as v2).
//!   5. B's chain qualification by attestation, the three-step first-parent rule (as v2). The journal carries, per
//!      level, the superblock count and the attesting count.
//!   6. The token: covenant id and template hash (as v2).
//!   7. `r_bits`, the median compact target over the attesting superblocks.
//!   8. The prover's address, as given in the witness (non-zero).
//!
//! Hash functions, from rusty-kaspa v2.1.0 `crypto/hashes/src/hashers.rs`:
//!   blake2b-256 keyed: "TransactionID", "BlockHash"; blake2b-256 unkeyed: P2SH (`pay_to_script_hash_script`)
//!   blake3 keyed (key = domain string zero-padded to 32 bytes): "SeqCommitmentMerkleBranchHash",
//!   "PayloadDigest", "TransactionRest", "TransactionV1Id", "SeqCommitLaneKey", "SeqCommitLaneTip",
//!   "SeqCommitActivityLeaf", "SeqCommitMergesetContext", "SeqCommitActivityRoot",
//!   "SeqCommitActiveLeaf", "SeqCommitActiveNode", "SeqCommitActiveCollapsedNode".
//!   blake3 unkeyed: the Silverscript template hash.

extern crate alloc;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use crate::{parents_at_level, verify_header, Hash, KeccakF, Stage, U256};

pub const INPUT_MAGIC: &[u8; 4] = b"KZO6";
pub const JOURNAL_MAGIC: &[u8; 4] = b"KZO6";
pub const MAX_LEVELS: usize = 8;
pub const SMT_DEPTH: usize = 256;
pub const ZERO: Hash = [0u8; 32];
/// Lane of native (subnetwork 0) transactions.
pub const NATIVE_LANE: [u8; 20] = [0u8; 20];
pub const PAYLOAD_MAGIC: &[u8; 4] = b"KZB1";
/// Burn payload v3: "KZB1" | 3 | target(20) | tip(8, BE) | recipient(20) | beacon_number(8, BE) | beacon_hash(32)
pub const PAYLOAD_VERSION: u8 = 3;
pub const PAYLOAD_LEN: usize = 93;
/// Burn payload v2 (still read, as a burn without a beacon): "KZB1" | 2 | target(20) | tip(8, BE) | recipient(20)
pub const PAYLOAD_V2_VERSION: u8 = 2;
pub const PAYLOAD_V2_LEN: usize = 53;
pub const MAX_BURNS: usize = 16;
/// Upper bound on the attestation chain (chain blocks after B); ~1.36 chain blocks/s, so 100k is ~20 h.
pub const MAX_ATTEST_ROOTS: usize = 100_000;
/// First-parent hops a superblock may take to reach the commitment chain (O5: ~90% of the
/// non-direct level-30 attesters join within three).
pub const MAX_FP_STEPS: usize = 3;

// ---------------------------------------------------------------------------------------------
// The token family's reference cell (KCC-20 Last Call, argent-lang/kcc20-reference c8a0871)
// ---------------------------------------------------------------------------------------------

/// Redeem prefix of the reference cell.
pub const KCC20_PREFIX: &[u8] = &[0x6b];
/// Redeem suffix of the reference cell (3,885 bytes; bridge-v4/tests/fixtures/bridgemint-fixtures.json).
pub const KCC20_SUFFIX: &[u8] = include_bytes!("kcc20_suffix.bin");
/// Its template hash, BLAKE3(LE64(1) || 6b || LE64(3885) || suffix). The guest recomputes it.
pub const KCC20_TEMPLATE: Hash = [
    0x97, 0x03, 0x11, 0x2e, 0xe6, 0xe3, 0x55, 0x51, 0x07, 0xcd, 0x16, 0x88, 0x58, 0x99, 0x2b, 0x77, 0xd3, 0xb7, 0x4f, 0x65, 0x52, 0x05,
    0xb2, 0xb4, 0x63, 0xb1, 0xf9, 0xec, 0x2e, 0xc7, 0x3c, 0xf7,
];
/// The provably unspendable p2sh owner: BLAKE2b-256 of the one-byte script `6a` (OP_RETURN).
pub const BURN_OWNER: Hash = [
    0xd3, 0x79, 0xe5, 0x0f, 0x3e, 0x22, 0x03, 0xf9, 0xa9, 0x25, 0x84, 0x91, 0x63, 0x35, 0xbb, 0x7c, 0xd0, 0x14, 0xb2, 0x37, 0xce, 0xaa,
    0x8b, 0x36, 0xf1, 0xd3, 0xd8, 0x0d, 0x0c, 0xc8, 0x8b, 0x32,
];
/// KCC-20 owner scheme p2sh, borrow scheme disabled (KCC20.sil).
pub const OWNER_P2SH: u8 = 0x03;
pub const BORROW_DISABLED: u8 = 0x00;
/// Script public key version of a P2SH output.
pub const P2SH_SPK_VERSION: u16 = 0;
pub const CELL_WINDOW_LEN: usize = 145;

pub fn hx(h: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(h.len() * 2);
    for b in h {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 15) as usize] as char);
    }
    s
}

/// Silverscript template hash: BLAKE3(LE64(len p) || p || LE64(len s) || s), unkeyed.
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    *h.finalize().as_bytes()
}

/// KCC-1 state window of a reference cell (145 bytes). Equals `bridge-v4` `cell_window`.
pub fn cell_window(template: &Hash, amount: u64, owner: &Hash, owner_scheme: u8, borrow_scheme: u8, guard: &Hash, commitment: &Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(CELL_WINDOW_LEN);
    v.push(0x20);
    v.extend_from_slice(template);
    v.push(0x08);
    v.extend_from_slice(&amount.to_le_bytes());
    v.push(0x20);
    v.extend_from_slice(owner);
    v.extend_from_slice(&[0x01, owner_scheme, 0x01, borrow_scheme, 0x20]);
    v.extend_from_slice(guard);
    v.push(0x20);
    v.extend_from_slice(commitment);
    v
}

/// `aa 20 BLAKE2b-256(redeem) 87` (OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL).
pub fn p2sh_script(redeem: &[u8]) -> [u8; 35] {
    let d = blake2b_simd::Params::new().hash_length(32).hash(redeem);
    let mut s = [0u8; 35];
    s[0] = 0xaa;
    s[1] = 0x20;
    s[2..34].copy_from_slice(d.as_bytes());
    s[34] = 0x87;
    s
}

/// Script of a burn cell holding `amount`, for the reference cell given by (prefix, suffix, template).
pub fn burn_cell_script_with(prefix: &[u8], suffix: &[u8], template: &Hash, amount: u64) -> [u8; 35] {
    let mut r = Vec::with_capacity(prefix.len() + CELL_WINDOW_LEN + suffix.len());
    r.extend_from_slice(prefix);
    r.extend(cell_window(template, amount, &BURN_OWNER, OWNER_P2SH, BORROW_DISABLED, &ZERO, &ZERO));
    r.extend_from_slice(suffix);
    p2sh_script(&r)
}

pub fn burn_cell_script(amount: u64) -> [u8; 35] {
    burn_cell_script_with(KCC20_PREFIX, KCC20_SUFFIX, &KCC20_TEMPLATE, amount)
}

// ---------------------------------------------------------------------------------------------
// Keyed hashers
// ---------------------------------------------------------------------------------------------

fn b3(domain: &[u8]) -> blake3::Hasher {
    let mut key = [0u8; 32];
    key[..domain.len()].copy_from_slice(domain);
    blake3::Hasher::new_keyed(&key)
}

fn fin(h: &blake3::Hasher) -> Hash {
    *h.finalize().as_bytes()
}

/// H_seq: "SeqCommitmentMerkleBranchHash"(a || b).
pub fn h_seq(a: &Hash, b: &Hash) -> Hash {
    let mut h = b3(b"SeqCommitmentMerkleBranchHash");
    h.update(a);
    h.update(b);
    fin(&h)
}

pub fn lane_key(lane_id: &[u8; 20]) -> Hash {
    let mut h = b3(b"SeqCommitLaneKey");
    h.update(lane_id);
    fin(&h)
}

pub fn activity_leaf(tx_id: &Hash, version: u16, merge_idx: u32) -> Hash {
    let mut h = b3(b"SeqCommitActivityLeaf");
    h.update(tx_id);
    h.update(&version.to_le_bytes());
    h.update(&merge_idx.to_le_bytes());
    fin(&h)
}

pub fn lane_tip(parent_ref: &Hash, lane_key: &Hash, activity_digest: &Hash, context_hash: &Hash) -> Hash {
    let mut h = b3(b"SeqCommitLaneTip");
    h.update(parent_ref);
    h.update(lane_key);
    h.update(activity_digest);
    h.update(context_hash);
    fin(&h)
}

/// `H_mergeset_context(le_u64(selected parent timestamp) || le_u64(daa_score) || le_u64(blue_score))`
pub fn context_hash(timestamp: u64, daa_score: u64, blue_score: u64) -> Hash {
    let mut h = b3(b"SeqCommitMergesetContext");
    h.update(&timestamp.to_le_bytes());
    h.update(&daa_score.to_le_bytes());
    h.update(&blue_score.to_le_bytes());
    fin(&h)
}

pub fn activity_root(inactivity_shortcut: &Hash, lanes_root: &Hash) -> Hash {
    let mut h = b3(b"SeqCommitActivityRoot");
    h.update(inactivity_shortcut);
    h.update(lanes_root);
    fin(&h)
}

/// SMT leaf of an active lane: `H_active_leaf(lane_tip || le_u64(blue_score))`
pub fn active_leaf(lane_tip: &Hash, blue_score: u64) -> Hash {
    let mut h = b3(b"SeqCommitActiveLeaf");
    h.update(lane_tip);
    h.update(&blue_score.to_le_bytes());
    fin(&h)
}

pub fn active_node(left: &Hash, right: &Hash) -> Hash {
    let mut h = b3(b"SeqCommitActiveNode");
    h.update(left);
    h.update(right);
    fin(&h)
}

pub fn collapsed_node(key: &Hash, leaf: &Hash) -> Hash {
    let mut h = b3(b"SeqCommitActiveCollapsedNode");
    h.update(key);
    h.update(leaf);
    fin(&h)
}

pub fn payload_digest(payload: &[u8]) -> Hash {
    let mut h = b3(b"PayloadDigest");
    h.update(payload);
    fin(&h)
}

// ---------------------------------------------------------------------------------------------
// Merkle root with H_seq branches (`kaspa_merkle::calc_merkle_root_with_hasher`)
// ---------------------------------------------------------------------------------------------

/// Pads to a power of two; a missing right sibling hashes as ZERO, a missing left node stays
/// missing; one leaf is its own root; no leaves gives ZERO.
pub fn merkle_root_seq(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => return ZERO,
        1 => return leaves[0],
        _ => {}
    }
    let pot = leaves.len().next_power_of_two();
    let mut level: Vec<Option<Hash>> = leaves.iter().map(|h| Some(*h)).collect();
    level.resize(pot, None);
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(match pair[0] {
                None => None,
                Some(l) => Some(h_seq(&l, &pair[1].unwrap_or(ZERO))),
            });
        }
        level = next;
    }
    level[0].expect("merkle root")
}

// ---------------------------------------------------------------------------------------------
// Sparse Merkle tree proof (`crypto/smt/src/proof.rs`, hasher SeqCommitActiveNode)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminal {
    Full,
    Collapsed { depth: u8 },
    CollapsedOther { depth: u8, key: Hash, leaf: Hash },
}

impl Terminal {
    fn depth(&self) -> usize {
        match self {
            Terminal::Full => SMT_DEPTH,
            Terminal::Collapsed { depth } | Terminal::CollapsedOther { depth, .. } => *depth as usize,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtProof {
    pub bitmap: [u8; 32],
    pub siblings: Vec<Hash>,
    pub terminal: Terminal,
}

#[inline]
fn empty_at(bitmap: &[u8; 32], d: usize) -> bool {
    bitmap[d / 8] & (1 << (d % 8)) != 0
}

#[inline]
fn bit_at(key: &Hash, d: usize) -> bool {
    key[d / 8] & (0x80 >> (d % 8)) != 0
}

/// `EMPTY_HASHES[i]`: `[0]` = ZERO, `[i]` = node(empty[i-1], empty[i-1]).
pub fn empty_hashes() -> Vec<Hash> {
    let mut v = Vec::with_capacity(SMT_DEPTH + 1);
    v.push(ZERO);
    for i in 1..=SMT_DEPTH {
        let p = v[i - 1];
        v.push(active_node(&p, &p));
    }
    v
}

impl SmtProof {
    /// Wire format: `bitmap[32] || tag[1] || payload || siblings[N x 32]`.
    pub fn parse(d: &[u8]) -> SmtProof {
        assert!(d.len() >= 33, "SMT proof too short");
        let mut bitmap = [0u8; 32];
        bitmap.copy_from_slice(&d[..32]);
        let (terminal, rest) = match d[32] {
            0 => (Terminal::Full, &d[33..]),
            1 => {
                assert!(d.len() >= 34, "SMT proof too short");
                (Terminal::Collapsed { depth: d[33] }, &d[34..])
            }
            2 => {
                assert!(d.len() >= 98, "SMT proof too short");
                (
                    Terminal::CollapsedOther { depth: d[33], key: d[34..66].try_into().unwrap(), leaf: d[66..98].try_into().unwrap() },
                    &d[98..],
                )
            }
            t => panic!("SMT proof: unknown terminal tag {t}"),
        };
        assert!(rest.len() % 32 == 0, "SMT proof: sibling bytes not a multiple of 32");
        let siblings: Vec<Hash> = rest.chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
        let expected = (0..terminal.depth()).filter(|&dd| !empty_at(&bitmap, dd)).count();
        assert_eq!(siblings.len(), expected, "SMT proof: sibling count does not match the bitmap");
        SmtProof { bitmap, siblings, terminal }
    }

    /// Root implied by this proof for `key` holding `leaf` (None = non-inclusion).
    pub fn root(&self, key: &Hash, leaf: Option<Hash>) -> Hash {
        let empty = empty_hashes();
        let mut cur = match (&self.terminal, leaf) {
            (Terminal::CollapsedOther { key: k, leaf: l, .. }, None) if k != key => collapsed_node(k, l),
            (Terminal::CollapsedOther { .. }, None) => ZERO,
            (_, Some(lh)) => collapsed_node(key, &lh),
            (_, None) => ZERO,
        };
        let mut si = self.siblings.len();
        let limit = self.terminal.depth();
        for d in (0..limit).rev() {
            let sib = if empty_at(&self.bitmap, d) {
                empty[SMT_DEPTH - 1 - d]
            } else {
                si -= 1;
                self.siblings[si]
            };
            let (l, r) = if bit_at(key, d) { (sib, cur) } else { (cur, sib) };
            cur = active_node(&l, &r);
        }
        cur
    }
}

// ---------------------------------------------------------------------------------------------
// Transaction id (`consensus/core/src/hashing/tx.rs`)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    pub prev_tx_id: Hash,
    pub prev_index: u32,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub spk_version: u16,
    pub script: Vec<u8>,
    /// v1 only: (authorizing_input, covenant_id)
    pub covenant: Option<(u16, Hash)>,
}

/// The fields of a transaction that its id commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxBody {
    pub version: u16,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u64,
    pub subnetwork: [u8; 20],
    pub gas: u64,
    pub payload: Vec<u8>,
}

fn id_preimage(tx: &TxBody, exclude_payload: bool) -> Vec<u8> {
    let mut o = Vec::with_capacity(128 + tx.payload.len() + 64 * (tx.inputs.len() + tx.outputs.len()));
    o.extend_from_slice(&tx.version.to_le_bytes());
    o.extend_from_slice(&(tx.inputs.len() as u64).to_le_bytes());
    for i in &tx.inputs {
        o.extend_from_slice(&i.prev_tx_id);
        o.extend_from_slice(&i.prev_index.to_le_bytes());
        o.extend_from_slice(&0u64.to_le_bytes()); // empty signature script (var bytes)
        o.extend_from_slice(&i.sequence.to_le_bytes());
    }
    o.extend_from_slice(&(tx.outputs.len() as u64).to_le_bytes());
    for out in &tx.outputs {
        o.extend_from_slice(&out.value.to_le_bytes());
        o.extend_from_slice(&out.spk_version.to_le_bytes());
        o.extend_from_slice(&(out.script.len() as u64).to_le_bytes());
        o.extend_from_slice(&out.script);
        if tx.version >= 1 {
            o.push(out.covenant.is_some() as u8);
            if let Some((ai, cid)) = &out.covenant {
                o.extend_from_slice(&ai.to_le_bytes());
                o.extend_from_slice(cid);
            }
        }
    }
    o.extend_from_slice(&tx.lock_time.to_le_bytes());
    o.extend_from_slice(&tx.subnetwork);
    o.extend_from_slice(&tx.gas.to_le_bytes());
    if exclude_payload {
        o.extend_from_slice(&0u64.to_le_bytes());
    } else {
        o.extend_from_slice(&(tx.payload.len() as u64).to_le_bytes());
        o.extend_from_slice(&tx.payload);
    }
    o
}

pub fn tx_id(tx: &TxBody) -> Hash {
    if tx.version == 0 {
        let mut st = blake2b_simd::Params::new().hash_length(32).key(b"TransactionID").to_state();
        st.update(&id_preimage(tx, false));
        let mut out = [0u8; 32];
        out.copy_from_slice(st.finalize().as_bytes());
        out
    } else {
        let pd = payload_digest(&tx.payload);
        let rest = {
            let mut h = b3(b"TransactionRest");
            h.update(&id_preimage(tx, true));
            fin(&h)
        };
        let mut h = b3(b"TransactionV1Id");
        h.update(&pd);
        h.update(&rest);
        fin(&h)
    }
}

// ---------------------------------------------------------------------------------------------
// Witness (guest input). Same layout as v2 under the new magic: the anchor is chosen by the program.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurnCell {
    pub index: u32,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub tx: TxBody,
    pub cells: Vec<BurnCell>,
    pub leaves: Vec<(Hash, u16, u32)>,
    pub leaf_index: u32,
    pub sp_timestamp: u64,
    pub c_daa_score: u64,
    pub c_blue_score: u64,
    pub parent_ref: Hash,
    pub lane_blue_score: u64,
    pub inactivity_shortcut: Hash,
    pub payload_and_ctx_digest: Hash,
    pub parent_seq_commit: Hash,
    pub smt_proof: Vec<u8>,
    pub chain_state_roots: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub soft_keccak: bool,
    pub levels: Vec<u8>,
    pub t: Hash,
    pub b: Hash,
    pub token_cov_id: Hash,
    /// the Ethereum address the relay pays the tip to (F16); copied to the journal
    pub prover: [u8; 20],
    pub headers: Vec<Vec<u8>>,
    pub y_headers: Vec<Vec<u8>>,
    pub attest_roots: Vec<Hash>,
    pub burns: Vec<Burn>,
}

struct Wr(Vec<u8>);
impl Wr {
    fn u8(&mut self, v: u8) {
        self.0.push(v)
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn hash(&mut self, h: &Hash) {
        self.0.extend_from_slice(h)
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b)
    }
}

struct Rd<'a> {
    b: &'a [u8],
    off: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = self.b.get(self.off..self.off + n).expect("witness truncated");
        self.off += n;
        s
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take(2).try_into().unwrap())
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn hash(&mut self) -> Hash {
        self.take(32).try_into().unwrap()
    }
    fn bytes(&mut self) -> Vec<u8> {
        let n = self.u32() as usize;
        self.take(n).to_vec()
    }
}

impl TxBody {
    fn write(&self, w: &mut Wr) {
        w.u16(self.version);
        w.u32(self.inputs.len() as u32);
        for i in &self.inputs {
            w.hash(&i.prev_tx_id);
            w.u32(i.prev_index);
            w.u64(i.sequence);
        }
        w.u32(self.outputs.len() as u32);
        for o in &self.outputs {
            w.u64(o.value);
            w.u16(o.spk_version);
            w.bytes(&o.script);
            match &o.covenant {
                None => w.u8(0),
                Some((ai, cid)) => {
                    w.u8(1);
                    w.u16(*ai);
                    w.hash(cid);
                }
            }
        }
        w.u64(self.lock_time);
        w.0.extend_from_slice(&self.subnetwork);
        w.u64(self.gas);
        w.bytes(&self.payload);
    }
    fn read(r: &mut Rd) -> TxBody {
        let version = r.u16();
        let n_in = r.u32() as usize;
        assert!(n_in <= 10_000, "too many inputs");
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            inputs.push(TxInput { prev_tx_id: r.hash(), prev_index: r.u32(), sequence: r.u64() });
        }
        let n_out = r.u32() as usize;
        assert!(n_out <= 10_000, "too many outputs");
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let value = r.u64();
            let spk_version = r.u16();
            let script = r.bytes();
            let covenant = match r.u8() {
                0 => None,
                1 => {
                    let ai = r.u16();
                    Some((ai, r.hash()))
                }
                _ => panic!("bad covenant flag"),
            };
            outputs.push(TxOutput { value, spk_version, script, covenant });
        }
        let lock_time = r.u64();
        let subnetwork: [u8; 20] = r.take(20).try_into().unwrap();
        let gas = r.u64();
        let payload = r.bytes();
        TxBody { version, inputs, outputs, lock_time, subnetwork, gas, payload }
    }
}

impl Witness {
    /// Frame: "KZO6" | soft_keccak u8 | n_levels u8 | levels | T | B | token_cov_id | prover(20) |
    /// headers (u32 n, n x bytes) | y_headers (same) | attest_roots (u32 n, n x 32) | n_burns u8 |
    /// per burn: tx | cells | leaves | leaf_index | sp_timestamp | c_daa | c_blue | parent_ref | lane_blue |
    /// inactivity_shortcut | payload_and_ctx_digest | parent_seq_commit | smt_proof bytes | chain_state_roots.
    /// Little-endian. As v2 after the magic, without K (v4: the ladder is anchored at B, V4-DESIGN 2.11), with the
    /// prover's address after the token (F16).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Wr(Vec::with_capacity(
            160 + self.headers.iter().map(|h| h.len() + 4).sum::<usize>() + self.y_headers.iter().map(|h| h.len() + 4).sum::<usize>() + 32 * self.attest_roots.len(),
        ));
        w.0.extend_from_slice(INPUT_MAGIC);
        w.u8(self.soft_keccak as u8);
        w.u8(self.levels.len() as u8);
        for l in &self.levels {
            w.u8(*l);
        }
        w.hash(&self.t);
        w.hash(&self.b);
        w.hash(&self.token_cov_id);
        w.0.extend_from_slice(&self.prover);
        w.u32(self.headers.len() as u32);
        for h in &self.headers {
            w.bytes(h);
        }
        w.u32(self.y_headers.len() as u32);
        for h in &self.y_headers {
            w.bytes(h);
        }
        w.u32(self.attest_roots.len() as u32);
        for s in &self.attest_roots {
            w.hash(s);
        }
        w.u8(self.burns.len() as u8);
        for b in &self.burns {
            b.tx.write(&mut w);
            w.u32(b.cells.len() as u32);
            for c in &b.cells {
                w.u32(c.index);
                w.u64(c.amount);
            }
            w.u32(b.leaves.len() as u32);
            for (id, v, i) in &b.leaves {
                w.hash(id);
                w.u16(*v);
                w.u32(*i);
            }
            w.u32(b.leaf_index);
            w.u64(b.sp_timestamp);
            w.u64(b.c_daa_score);
            w.u64(b.c_blue_score);
            w.hash(&b.parent_ref);
            w.u64(b.lane_blue_score);
            w.hash(&b.inactivity_shortcut);
            w.hash(&b.payload_and_ctx_digest);
            w.hash(&b.parent_seq_commit);
            w.bytes(&b.smt_proof);
            w.u32(b.chain_state_roots.len() as u32);
            for s in &b.chain_state_roots {
                w.hash(s);
            }
        }
        w.0
    }

    pub fn decode(input: &[u8]) -> Witness {
        let mut r = Rd { b: input, off: 0 };
        assert!(r.take(4) == INPUT_MAGIC, "bad input magic");
        let soft_keccak = r.u8() == 1;
        let n_levels = r.u8() as usize;
        let mut levels = Vec::with_capacity(n_levels);
        for _ in 0..n_levels {
            levels.push(r.u8());
        }
        let t = r.hash();
        let b = r.hash();
        let token_cov_id = r.hash();
        let prover: [u8; 20] = r.take(20).try_into().unwrap();
        let n = r.u32() as usize;
        let mut headers = Vec::with_capacity(n);
        for _ in 0..n {
            headers.push(r.bytes());
        }
        let ny = r.u32() as usize;
        let mut y_headers = Vec::with_capacity(ny);
        for _ in 0..ny {
            y_headers.push(r.bytes());
        }
        let nr = r.u32() as usize;
        assert!(nr <= MAX_ATTEST_ROOTS, "attestation chain too long");
        let mut attest_roots = Vec::with_capacity(nr);
        for _ in 0..nr {
            attest_roots.push(r.hash());
        }
        let nb = r.u8() as usize;
        assert!((1..=MAX_BURNS).contains(&nb), "1 to {MAX_BURNS} burns per proof");
        let mut burns = Vec::with_capacity(nb);
        for _ in 0..nb {
            let tx = TxBody::read(&mut r);
            let nc = r.u32() as usize;
            assert!(nc <= tx.outputs.len(), "more burn cells named than the transaction has outputs");
            let mut cells = Vec::with_capacity(nc);
            for _ in 0..nc {
                let index = r.u32();
                cells.push(BurnCell { index, amount: r.u64() });
            }
            let nl = r.u32() as usize;
            let mut leaves = Vec::with_capacity(nl);
            for _ in 0..nl {
                let id = r.hash();
                let v = r.u16();
                leaves.push((id, v, r.u32()));
            }
            let leaf_index = r.u32();
            let sp_timestamp = r.u64();
            let c_daa_score = r.u64();
            let c_blue_score = r.u64();
            let parent_ref = r.hash();
            let lane_blue_score = r.u64();
            let inactivity_shortcut = r.hash();
            let payload_and_ctx_digest = r.hash();
            let parent_seq_commit = r.hash();
            let smt_proof = r.bytes();
            let ncr = r.u32() as usize;
            let mut chain_state_roots = Vec::with_capacity(ncr);
            for _ in 0..ncr {
                chain_state_roots.push(r.hash());
            }
            burns.push(Burn {
                tx,
                cells,
                leaves,
                leaf_index,
                sp_timestamp,
                c_daa_score,
                c_blue_score,
                parent_ref,
                lane_blue_score,
                inactivity_shortcut,
                payload_and_ctx_digest,
                parent_seq_commit,
                smt_proof,
                chain_state_roots,
            });
        }
        assert_eq!(r.off, input.len(), "trailing witness bytes");
        Witness { soft_keccak, levels, t, b, token_cov_id, prover, headers, y_headers, attest_roots, burns }
    }
}

pub fn input_wants_soft_keccak(input: &[u8]) -> bool {
    assert!(input.len() >= 5 && &input[..4] == INPUT_MAGIC, "bad input magic");
    input[4] == 1
}

// ---------------------------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------------------------

/// Journal (KZO6), 310 + 68 n bytes, big-endian. v4: no checkpoint; the ladder is anchored at B (V4-DESIGN 2.11);
/// after the 11-08 review the reading is over the attesters and the prover is named (2.14).
///   0    4   "KZO6"
///   4   32   T (tip: the ladders are walked from it; nothing in the relay depends on it)
///  36    8   T.daa_score
///  44   32   B (the block every burn's commitment chain ends at; the ladders end there; attested by the
///             superblocks after it)
///  76    8   B.daa_score
///  84    4   r_bits: the proof's own difficulty reading, the median compact target over the attesting
///             superblocks across the proved levels; the relay takes max(stored history, this)
///  88    4   headers verified (PoW) + first-parent headers (hash only)
///  92    1   n_levels
///  93   72   8 x (level u8, count u32, attesting u32)
/// 165   20   target: the Ethereum relay contract every burn in this proof is bound to
/// 185   32   token_cov_id
/// 217   32   template_hash
/// 249    8   anchor: Ethereum block number of the freshest burn beacon
/// 257   32   anchor: its Ethereum block hash (the relay checks it against EIP-2935 history)
/// 289   20   prover: the Ethereum address the relay pays the tips to (non-zero)
/// 309    1   n_burns (1..=16)
/// 310   68n  per burn: tx id (32) | amount (8, token base units) | tip (8) | recipient (20)
pub const JOURNAL_HEADER_LEN: usize = 310;
pub const JOURNAL_BURN_LEN: usize = 68;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub number: u64,
    pub hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalBurn {
    pub tx_id: Hash,
    pub amount: u64,
    pub tip: u64,
    pub recipient: [u8; 20],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LevelCount {
    pub level: u8,
    pub count: u32,
    pub attesting: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub t: Hash,
    pub t_daa: u64,
    pub b: Hash,
    pub b_daa: u64,
    /// the proof's own difficulty reading: the median compact target over the attesting superblocks (2.11.3, 2.14)
    pub r_bits: u32,
    pub n_headers: u32,
    pub levels: Vec<LevelCount>,
    pub target: [u8; 20],
    pub token_cov_id: Hash,
    pub template_hash: Hash,
    pub anchor: Beacon,
    /// the address the relay pays the tips to (F16)
    pub prover: [u8; 20],
    pub burns: Vec<JournalBurn>,
}

impl Journal {
    pub fn len(&self) -> usize {
        JOURNAL_HEADER_LEN + JOURNAL_BURN_LEN * self.burns.len()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(self.len());
        o.extend_from_slice(JOURNAL_MAGIC);
        o.extend_from_slice(&self.t);
        o.extend_from_slice(&self.t_daa.to_be_bytes());
        o.extend_from_slice(&self.b);
        o.extend_from_slice(&self.b_daa.to_be_bytes());
        o.extend_from_slice(&self.r_bits.to_be_bytes());
        o.extend_from_slice(&self.n_headers.to_be_bytes());
        o.push(self.levels.len() as u8);
        for i in 0..MAX_LEVELS {
            let lc = self.levels.get(i).copied().unwrap_or(LevelCount { level: 0, count: 0, attesting: 0 });
            o.push(lc.level);
            o.extend_from_slice(&lc.count.to_be_bytes());
            o.extend_from_slice(&lc.attesting.to_be_bytes());
        }
        o.extend_from_slice(&self.target);
        o.extend_from_slice(&self.token_cov_id);
        o.extend_from_slice(&self.template_hash);
        o.extend_from_slice(&self.anchor.number.to_be_bytes());
        o.extend_from_slice(&self.anchor.hash);
        o.extend_from_slice(&self.prover);
        o.push(self.burns.len() as u8);
        for bn in &self.burns {
            o.extend_from_slice(&bn.tx_id);
            o.extend_from_slice(&bn.amount.to_be_bytes());
            o.extend_from_slice(&bn.tip.to_be_bytes());
            o.extend_from_slice(&bn.recipient);
        }
        debug_assert_eq!(o.len(), self.len());
        o
    }
    pub fn decode(b: &[u8]) -> Option<Journal> {
        if b.len() < JOURNAL_HEADER_LEN || &b[..4] != JOURNAL_MAGIC {
            return None;
        }
        let n = b[92] as usize;
        if n > MAX_LEVELS {
            return None;
        }
        let mut levels = Vec::with_capacity(n);
        for i in 0..n {
            let at = 93 + 9 * i;
            levels.push(LevelCount {
                level: b[at],
                count: u32::from_be_bytes(b[at + 1..at + 5].try_into().unwrap()),
                attesting: u32::from_be_bytes(b[at + 5..at + 9].try_into().unwrap()),
            });
        }
        let nb = b[309] as usize;
        if nb == 0 || nb > MAX_BURNS || b.len() != JOURNAL_HEADER_LEN + JOURNAL_BURN_LEN * nb {
            return None;
        }
        let mut burns = Vec::with_capacity(nb);
        for i in 0..nb {
            let at = JOURNAL_HEADER_LEN + JOURNAL_BURN_LEN * i;
            burns.push(JournalBurn {
                tx_id: b[at..at + 32].try_into().unwrap(),
                amount: u64::from_be_bytes(b[at + 32..at + 40].try_into().unwrap()),
                tip: u64::from_be_bytes(b[at + 40..at + 48].try_into().unwrap()),
                recipient: b[at + 48..at + 68].try_into().unwrap(),
            });
        }
        Some(Journal {
            t: b[4..36].try_into().unwrap(),
            t_daa: u64::from_be_bytes(b[36..44].try_into().unwrap()),
            b: b[44..76].try_into().unwrap(),
            b_daa: u64::from_be_bytes(b[76..84].try_into().unwrap()),
            r_bits: u32::from_be_bytes(b[84..88].try_into().unwrap()),
            n_headers: u32::from_be_bytes(b[88..92].try_into().unwrap()),
            levels,
            target: b[165..185].try_into().unwrap(),
            token_cov_id: b[185..217].try_into().unwrap(),
            template_hash: b[217..249].try_into().unwrap(),
            anchor: Beacon { number: u64::from_be_bytes(b[249..257].try_into().unwrap()), hash: b[257..289].try_into().unwrap() },
            prover: b[289..309].try_into().unwrap(),
            burns,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The burn reader and transaction inclusion (E4)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inclusion {
    pub tx_id: Hash,
    pub amount: u64,
    pub tip: u64,
    pub target: [u8; 20],
    pub recipient: [u8; 20],
    /// the burn's Ethereum beacon, None for a v2 payload or a v3 payload with a zero beacon
    pub beacon: Option<Beacon>,
    pub burn_cells: u32,
    pub activity_digest: Hash,
    pub context_hash: Hash,
    pub lane_tip: Hash,
    pub lanes_root: Hash,
    pub state_root_c: Hash,
    pub seq_commit_c: Hash,
    pub seq_commit_final: Hash,
}

/// Decode a burn payload, v3 or v2: (target, tip, recipient). The beacon is `payload_beacon`.
pub fn parse_payload(p: &[u8]) -> ([u8; 20], u64, [u8; 20]) {
    let ok = p.len() >= 5
        && &p[..4] == PAYLOAD_MAGIC
        && ((p[4] == PAYLOAD_VERSION && p.len() == PAYLOAD_LEN) || (p[4] == PAYLOAD_V2_VERSION && p.len() == PAYLOAD_V2_LEN));
    assert!(ok, "payload is not a KZB1 v3 or v2 burn payload");
    let mut target = [0u8; 20];
    target.copy_from_slice(&p[5..25]);
    let tip = u64::from_be_bytes(p[25..33].try_into().unwrap());
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&p[33..53]);
    (target, tip, recipient)
}

/// The Ethereum beacon of a burn payload: Some for a v3 payload with a non-zero beacon, None for a v2 payload or a
/// zero beacon. A v3 beacon with a zero block number and a non-zero hash, or the reverse, is malformed.
pub fn payload_beacon(p: &[u8]) -> Option<Beacon> {
    parse_payload(p);
    if p[4] != PAYLOAD_VERSION {
        return None;
    }
    let number = u64::from_be_bytes(p[53..61].try_into().unwrap());
    let hash: Hash = p[61..93].try_into().unwrap();
    assert_eq!(number == 0, hash == ZERO, "payload beacon is half empty (block number {number}, hash {})", hx(&hash));
    if number == 0 { None } else { Some(Beacon { number, hash }) }
}

/// The anchor of a proof: the beacon with the highest block number. Panics when no burn carries a beacon, or when
/// two beacons name the same block with different hashes.
pub fn pick_anchor(beacons: &[Option<Beacon>]) -> Beacon {
    let top = beacons.iter().flatten().map(|b| b.number).max().expect("no burn in this proof carries an Ethereum beacon (payload v3)");
    let mut at_top = beacons.iter().flatten().filter(|b| b.number == top);
    let anchor = *at_top.next().unwrap();
    for b in at_top {
        assert_eq!(b.hash, anchor.hash, "two burns name Ethereum block {top} with different hashes");
    }
    anchor
}

/// The token burn in `tx`: every named cell is a burn cell of the token, distinct, at least one;
/// every covenant output of the tx is in the token's family. Returns the amount.
pub fn read_burn_cells(tx: &TxBody, cells: &[BurnCell], token_cov_id: &Hash, script_of: &dyn Fn(u64) -> [u8; 35]) -> u64 {
    assert_eq!(tx.version, 1, "burn transaction is version {}, a token transfer is version 1", tx.version);
    assert!(!cells.is_empty(), "the burn names no cells");
    for (i, out) in tx.outputs.iter().enumerate() {
        if let Some((_, cid)) = &out.covenant {
            assert_eq!(cid, token_cov_id, "output {i} carries covenant {}, not the token's", hx(cid));
        }
    }
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut amount = 0u64;
    for c in cells {
        assert!(seen.insert(c.index), "burn cell index {} named twice", c.index);
        let out = tx.outputs.get(c.index as usize).unwrap_or_else(|| panic!("burn cell index {} out of range", c.index));
        assert!(c.amount > 0, "burn cell {} has amount 0", c.index);
        assert_eq!(out.spk_version, P2SH_SPK_VERSION, "burn cell {} has spk version {}", c.index, out.spk_version);
        match &out.covenant {
            Some((_, cid)) if cid == token_cov_id => {}
            _ => panic!("burn cell {} is not under the token's covenant id", c.index),
        }
        assert!(
            out.script.as_slice() == &script_of(c.amount)[..],
            "output {} is not a burn cell of amount {} (script {})",
            c.index,
            c.amount,
            hx(&out.script)
        );
        amount = amount.checked_add(c.amount).expect("burn amount overflow");
    }
    amount
}

pub fn inclusion_with(b: &Burn, token_cov_id: &Hash, script_of: &dyn Fn(u64) -> [u8; 35]) -> Inclusion {
    let tx_id = tx_id(&b.tx);
    assert_eq!(b.tx.subnetwork, NATIVE_LANE, "burn transaction is not in the native lane");
    let (lid, lver, _) = b.leaves.get(b.leaf_index as usize).copied().expect("leaf index out of range");
    assert_eq!(lid, tx_id, "activity leaf tx id {} differs from the body's id {}", hx(&lid), hx(&tx_id));
    assert_eq!(lver, b.tx.version, "activity leaf version differs from the body's version");
    let amount = read_burn_cells(&b.tx, &b.cells, token_cov_id, script_of);
    let (target, tip, recipient) = parse_payload(&b.tx.payload);
    assert!(tip < amount, "tip {tip} must be below the burned amount {amount}");
    let beacon = payload_beacon(&b.tx.payload);

    let leaves: Vec<Hash> = b.leaves.iter().map(|(id, v, i)| activity_leaf(id, *v, *i)).collect();
    let activity_digest = merkle_root_seq(&leaves);
    let ctx = context_hash(b.sp_timestamp, b.c_daa_score, b.c_blue_score);
    let lk = lane_key(&NATIVE_LANE);
    let tip_hash = lane_tip(&b.parent_ref, &lk, &activity_digest, &ctx);
    assert_eq!(b.lane_blue_score, b.c_blue_score, "lane entry blue score differs from C's blue score");
    let leaf = active_leaf(&tip_hash, b.lane_blue_score);
    let lanes_root = SmtProof::parse(&b.smt_proof).root(&lk, Some(leaf));
    let ar = activity_root(&b.inactivity_shortcut, &lanes_root);
    let state_root_c = h_seq(&ar, &b.payload_and_ctx_digest);
    let seq_commit_c = h_seq(&b.parent_seq_commit, &state_root_c);
    let mut sc = seq_commit_c;
    for s in &b.chain_state_roots {
        sc = h_seq(&sc, s);
    }
    Inclusion {
        tx_id,
        amount,
        tip,
        target,
        recipient,
        beacon,
        burn_cells: b.cells.len() as u32,
        activity_digest,
        context_hash: ctx,
        lane_tip: tip_hash,
        lanes_root,
        state_root_c,
        seq_commit_c,
        seq_commit_final: sc,
    }
}

pub fn inclusion(b: &Burn, token_cov_id: &Hash) -> Inclusion {
    inclusion_with(b, token_cov_id, &burn_cell_script)
}

// ---------------------------------------------------------------------------------------------
// Attestation (three-step first-parent rule), unchanged from v2
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpNode {
    pub aimr: Hash,
    pub first_parent: Option<Hash>,
}

pub fn attest_steps(fp: &Hash, nodes: &BTreeMap<Hash, FpNode>, chain: &BTreeMap<Hash, u32>) -> Option<usize> {
    let mut y = *fp;
    for step in 1..=MAX_FP_STEPS {
        let n = nodes.get(&y)?;
        if chain.contains_key(&n.aimr) {
            return Some(step);
        }
        y = n.first_parent?;
    }
    None
}

// ---------------------------------------------------------------------------------------------
// The proof's own difficulty reading (V4-DESIGN 2.11.3)
// ---------------------------------------------------------------------------------------------

/// The compact target of the median ATTESTING superblock: (target, bits) pairs sorted by target (hardest first,
/// ties by bits), the element at index n/2. A median, not a maximum: `bits` is a free field of a header as long as
/// the hash is under its target, and a superblock's level is absolute (set by the hash alone), so a miner can
/// stamp any difficulty up to 2^(31+level) hashes per block on his own superblocks at no extra cost. The relay
/// takes max(stored history, this reading) and stores it on settlement; a maximum would let one planted
/// superblock in an otherwise honest proof raise everyone's bar for a week. Over the attesters and not over
/// everything expanded (REVIEW-2026-11-08 F15): a non-attesting superblock may be premined at leisure with any
/// `daa` and `bits` and listed beside the honest ladder, so the expanded set is a count, not a hashrate; an
/// attester commits to the beacon through its first-parent path and was mined after it. The median moves only when
/// more than half of the attesting superblocks are the forger's: more than the honest network's production since
/// the beacon, so a hashrate above 98% (honest attesters are 98.1% of honest superblocks).
pub fn median_bits(mut targets: Vec<(U256, u32)>) -> u32 {
    assert!(!targets.is_empty(), "no attesting superblock to read the difficulty from");
    targets.sort();
    targets[targets.len() / 2].1
}

// ---------------------------------------------------------------------------------------------
// The program
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Info {
    idx: usize,
    level: u32,
    daa: u64,
    aimr: Hash,
    bits: u32,
    target: U256,
}

fn aimr_of(hb: &[u8], ts_off: usize) -> Hash {
    let r = ts_off - 64;
    hb[r..r + 32].try_into().unwrap()
}

fn first_parent_of(hb: &[u8]) -> Option<Hash> {
    parents_at_level(hb, 0).and_then(|mut p| p.next()).map(|p| p.try_into().unwrap())
}

pub fn run<K: KeccakF>(input: &[u8]) -> Journal {
    run_with::<K>(input, KCC20_PREFIX, KCC20_SUFFIX)
}

pub fn run_with<K: KeccakF>(input: &[u8], cell_prefix: &[u8], cell_suffix: &[u8]) -> Journal {
    // 0. the token template from the embedded code, before anything else
    let template = template_hash(cell_prefix, cell_suffix);
    assert_eq!(template, KCC20_TEMPLATE, "reference cell template is {}, expected {}", hx(&template), hx(&KCC20_TEMPLATE));
    let script_of = |amount: u64| burn_cell_script_with(cell_prefix, cell_suffix, &template, amount);

    let w = Witness::decode(input);
    assert!(!w.levels.is_empty() && w.levels.len() <= MAX_LEVELS, "1 to {MAX_LEVELS} ladder levels");
    assert!(w.levels.windows(2).all(|p| p[0] < p[1]), "ladder levels must be strictly ascending");
    let lmax = *w.levels.last().unwrap() as u32;

    // 1. every header once, PoW checked
    let mut map: BTreeMap<Hash, Info> = BTreeMap::new();
    let mut nodes: BTreeMap<Hash, FpNode> = BTreeMap::new();
    for (i, hb) in w.headers.iter().enumerate() {
        let v = verify_header::<K>(hb, Stage::Full).unwrap_or_else(|e| panic!("header {i} does not parse: {e:?}"));
        assert!(v.passed, "header {i} ({}) fails proof of work", hx(&v.hash));
        let aimr = aimr_of(hb, v.parsed.ts_off);
        assert!(
            map.insert(v.hash, Info { idx: i, level: v.level, daa: v.parsed.daa_score, aimr, bits: v.parsed.bits, target: v.target }).is_none(),
            "header {i} ({}) is listed twice",
            hx(&v.hash)
        );
        nodes.insert(v.hash, FpNode { aimr, first_parent: first_parent_of(hb) });
    }
    let tin = *map.get(&w.t).unwrap_or_else(|| panic!("tip T {} is not among the headers", hx(&w.t)));
    let bin = *map.get(&w.b).unwrap_or_else(|| panic!("attested block B {} is not among the headers", hx(&w.b)));
    assert!(tin.level >= lmax, "T is at level {} but the top ladder level is {lmax}", tin.level);
    assert!(tin.daa > bin.daa, "T (daa {}) does not come after B (daa {})", tin.daa, bin.daa);

    // 1b. headers on first-parent paths: hash only
    for (i, hb) in w.y_headers.iter().enumerate() {
        let v = verify_header::<K>(hb, Stage::Hash).unwrap_or_else(|e| panic!("first-parent header {i} does not parse: {e:?}"));
        assert!(!map.contains_key(&v.hash), "first-parent header {i} ({}) is already a PoW-verified header", hx(&v.hash));
        assert!(
            nodes.insert(v.hash, FpNode { aimr: aimr_of(hb, v.parsed.ts_off), first_parent: first_parent_of(hb) }).is_none(),
            "first-parent header {i} ({}) is listed twice",
            hx(&v.hash)
        );
    }

    // 1c. the attestation chain: c_0 = B.aimr, c_i = H_seq(c_{i-1}, root_i)
    let mut chain: BTreeMap<Hash, u32> = BTreeMap::new();
    let mut c = bin.aimr;
    chain.insert(c, 0);
    for (i, s) in w.attest_roots.iter().enumerate() {
        c = h_seq(&c, s);
        assert!(chain.insert(c, (i + 1) as u32).is_none(), "attestation chain repeats a commitment at step {}", i + 1);
    }

    // 2. every burn, its acceptance chained to B; one target, no repeated tx id; the anchor. Before the ladders:
    //    a wrong B is refused here, with its own message, before any walk runs on it (2b, 2026-11-08).
    assert!((1..=MAX_BURNS).contains(&w.burns.len()), "1 to {MAX_BURNS} burns per proof");
    let mut target: Option<[u8; 20]> = None;
    let mut ids: BTreeSet<Hash> = BTreeSet::new();
    let mut burns = Vec::with_capacity(w.burns.len());
    let mut beacons = Vec::with_capacity(w.burns.len());
    for (i, bn) in w.burns.iter().enumerate() {
        let inc = inclusion_with(bn, &w.token_cov_id, &script_of);
        assert_eq!(
            inc.seq_commit_final,
            bin.aimr,
            "burn {i}: sequencing commitment chain ends at {} but B's accepted_id_merkle_root is {}",
            hx(&inc.seq_commit_final),
            hx(&bin.aimr)
        );
        match target {
            None => target = Some(inc.target),
            Some(t) => assert_eq!(t, inc.target, "burn {i} names a different target contract"),
        }
        assert!(ids.insert(inc.tx_id), "burn {i}: tx id {} appears twice", hx(&inc.tx_id));
        beacons.push(inc.beacon);
        burns.push(JournalBurn { tx_id: inc.tx_id, amount: inc.amount, tip: inc.tip, recipient: inc.recipient });
    }
    let anchor = pick_anchor(&beacons);

    // 3. closed walks per level from T down to B (v4: headers at or below B's daa are leaves, verified and not
    //    counted; K is gone); every counted superblock is checked for attestation. What binds the count to B is
    //    the attestation: an attester's first-parent path reaches a block carrying a commitment that descends
    //    from B's, so it was mined after B, and T, which descends from it, after that.
    let mut levels = Vec::with_capacity(w.levels.len());
    let mut attesters: BTreeSet<Hash> = BTreeSet::new();
    for &lv in &w.levels {
        let mut seen: BTreeSet<Hash> = BTreeSet::new();
        let mut q: VecDeque<Hash> = VecDeque::new();
        seen.insert(w.t);
        q.push_back(w.t);
        let mut count = 0u32;
        let mut attesting = 0u32;
        while let Some(h) = q.pop_front() {
            let info = map.get(&h).unwrap_or_else(|| panic!("level {lv}: header {} is not in the witness", hx(&h)));
            if info.daa <= bin.daa {
                continue;
            }
            assert!(info.level >= lv as u32, "level {lv}: block {} (level {}) was reached through level-{lv} parents", hx(&h), info.level);
            count += 1;
            let hb = &w.headers[info.idx];
            let y = first_parent_of(hb).expect("a header without direct parents");
            if attest_steps(&y, &nodes, &chain).is_some() {
                attesting += 1;
                attesters.insert(h);
            }
            let parents = parents_at_level(hb, lv as usize).unwrap_or_else(|| panic!("level {lv}: block {} lists no level-{lv} parents", hx(&h)));
            for p in parents {
                let ph: Hash = p.try_into().unwrap();
                if seen.insert(ph) {
                    q.push_back(ph);
                }
            }
        }
        levels.push(LevelCount { level: lv, count, attesting });
    }
    // No minimum here: the relay contract decides what is enough (V4-DESIGN 2.2).

    // 3b. the proof's own difficulty reading: the median target over the attesting superblocks (2.11.3; F15: not
    //     over everything expanded, which a forger can stuff with premined, stamped superblocks)
    let r_bits = median_bits(attesters.iter().map(|h| (map[h].target, map[h].bits)).collect());
    assert!(w.prover != [0u8; 20], "the witness names no prover (the address the relay pays the tip to)");

    Journal {
        t: w.t,
        t_daa: tin.daa,
        b: w.b,
        b_daa: bin.daa,
        r_bits,
        n_headers: (w.headers.len() + w.y_headers.len()) as u32,
        levels,
        target: target.unwrap(),
        token_cov_id: w.token_cov_id,
        template_hash: template,
        anchor,
        prover: w.prover,
        burns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{header_hashes, parse, SoftKeccak};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn h32(s: &str) -> Hash {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn hb(b: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }
    fn panics_with<F: FnOnce() -> R, R>(f: F, needle: &str) {
        let r = catch_unwind(AssertUnwindSafe(f));
        let e = match r {
            Ok(_) => panic!("expected a refusal containing {needle:?}, got acceptance"),
            Err(e) => e,
        };
        let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
        assert!(msg.contains(needle), "refused with {msg:?}, expected it to contain {needle:?}");
    }

    // ------------------------------------------------------------------ minimal JSON (fixtures)

    #[derive(Debug, Clone)]
    enum J {
        S(String),
        N(u64),
        A(Vec<J>),
        O(Vec<(String, J)>),
    }
    impl J {
        fn get(&self, k: &str) -> &J {
            match self {
                J::O(v) => &v.iter().find(|(kk, _)| kk == k).unwrap_or_else(|| panic!("fixture: no key {k}")).1,
                _ => panic!("fixture: not an object"),
            }
        }
        fn has(&self, k: &str) -> bool {
            matches!(self, J::O(v) if v.iter().any(|(kk, _)| kk == k))
        }
        fn s(&self) -> &str {
            match self {
                J::S(s) => s,
                _ => panic!("fixture: not a string"),
            }
        }
        fn hex(&self) -> Vec<u8> {
            hex::decode(self.s()).unwrap()
        }
        fn n(&self) -> u64 {
            match self {
                J::N(n) => *n,
                _ => panic!("fixture: not a number"),
            }
        }
        fn a(&self) -> &[J] {
            match self {
                J::A(v) => v,
                _ => panic!("fixture: not an array"),
            }
        }
    }
    fn json(s: &str) -> J {
        fn ws(b: &[u8], i: &mut usize) {
            while *i < b.len() && (b[*i] as char).is_ascii_whitespace() {
                *i += 1;
            }
        }
        fn val(b: &[u8], i: &mut usize) -> J {
            ws(b, i);
            match b[*i] {
                b'"' => {
                    *i += 1;
                    let st = *i;
                    while b[*i] != b'"' {
                        assert!(b[*i] != b'\\', "fixture: escapes not supported");
                        *i += 1;
                    }
                    let s = String::from_utf8(b[st..*i].to_vec()).unwrap();
                    *i += 1;
                    J::S(s)
                }
                b'{' => {
                    *i += 1;
                    let mut v = vec![];
                    loop {
                        ws(b, i);
                        if b[*i] == b'}' {
                            *i += 1;
                            break;
                        }
                        let k = match val(b, i) {
                            J::S(s) => s,
                            _ => panic!(),
                        };
                        ws(b, i);
                        assert_eq!(b[*i], b':');
                        *i += 1;
                        v.push((k, val(b, i)));
                        ws(b, i);
                        if b[*i] == b',' {
                            *i += 1;
                        }
                    }
                    J::O(v)
                }
                b'[' => {
                    *i += 1;
                    let mut v = vec![];
                    loop {
                        ws(b, i);
                        if b[*i] == b']' {
                            *i += 1;
                            break;
                        }
                        v.push(val(b, i));
                        ws(b, i);
                        if b[*i] == b',' {
                            *i += 1;
                        }
                    }
                    J::A(v)
                }
                _ => {
                    let st = *i;
                    while (b[*i] as char).is_ascii_digit() {
                        *i += 1;
                    }
                    J::N(core::str::from_utf8(&b[st..*i]).unwrap().parse().unwrap())
                }
            }
        }
        val(s.as_bytes(), &mut 0)
    }
    fn fixtures() -> J {
        let p = std::env::var("KCC20_FIXTURES")
            .unwrap_or_else(|_| format!("{}/../../../bridge-v4/tests/fixtures/bridgemint-fixtures.json", env!("CARGO_MANIFEST_DIR")));
        json(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}")))
    }

    // ------------------------------------------------------------------ the reference cell against the fixtures

    #[test]
    fn reference_cell_matches_fixtures() {
        let f = fixtures();
        let k = f.get("kcc20");
        assert_eq!(k.get("prefix").hex(), KCC20_PREFIX, "prefix");
        assert_eq!(k.get("suffix").hex(), KCC20_SUFFIX, "embedded suffix differs from the fixture");
        assert_eq!(KCC20_SUFFIX.len(), 3885);
        assert_eq!(k.get("state_window_len").n() as usize, CELL_WINDOW_LEN);
        assert_eq!(h32(k.get("template").s()), KCC20_TEMPLATE);
        assert_eq!(template_hash(KCC20_PREFIX, KCC20_SUFFIX), KCC20_TEMPLATE, "template hash formula");
        assert_eq!(h32(f.get("burn_owner_p2sh").s()), BURN_OWNER);
        let d = blake2b_simd::Params::new().hash_length(32).hash(&[0x6a]);
        assert_eq!(d.as_bytes(), &BURN_OWNER[..], "BURN_OWNER = BLAKE2b-256(6a)");

        let ex = f.get("mint_example");
        let mut burns = 0;
        for r in ex.get("recipients").a() {
            let amount = r.get("amount").n();
            let owner = h32(r.get("owner").s());
            let scheme = r.get("owner_scheme").n() as u8;
            let borrow = r.get("borrow_scheme").n() as u8;
            let guard = h32(r.get("borrow_guard").s());
            let ext = h32(r.get("extension_commitment").s());
            let win = cell_window(&KCC20_TEMPLATE, amount, &owner, scheme, borrow, &guard, &ext);
            assert_eq!(win, r.get("state_window").hex(), "window of the cell with amount {amount}");
            let mut redeem = KCC20_PREFIX.to_vec();
            redeem.extend(&win);
            redeem.extend_from_slice(KCC20_SUFFIX);
            if r.has("redeem") {
                assert_eq!(redeem, r.get("redeem").hex(), "redeem of the cell with amount {amount}");
            }
            assert_eq!(p2sh_script(&redeem).to_vec(), r.get("spk").hex(), "spk of the cell with amount {amount}");
            let is_burn = owner == BURN_OWNER && scheme == OWNER_P2SH && borrow == BORROW_DISABLED && guard == ZERO && ext == ZERO;
            assert_eq!(burn_cell_script(amount).to_vec() == r.get("spk").hex(), is_burn, "burn_cell_script on amount {amount}");
            if is_burn {
                burns += 1;
                assert_ne!(burn_cell_script(amount + 1).to_vec(), r.get("spk").hex(), "amount + 1 must not match");
                assert_ne!(burn_cell_script(amount - 1).to_vec(), r.get("spk").hex(), "amount - 1 must not match");
            }
        }
        assert_eq!(burns, 1, "the fixture mints exactly one burn cell");
    }

    // ------------------------------------------------------------------ payloads, beacons, the anchor (v3)

    const TOKEN: Hash = [0x71; 32];
    const TARGET: [u8; 20] = [0xcd; 20];
    const BEACON: Beacon = Beacon { number: 21_000_000, hash: [0xbe; 32] };

    fn payload_v2(tip: u64) -> Vec<u8> {
        let mut p = PAYLOAD_MAGIC.to_vec();
        p.push(PAYLOAD_V2_VERSION);
        p.extend_from_slice(&TARGET);
        p.extend_from_slice(&tip.to_be_bytes());
        p.extend_from_slice(&[0xab; 20]);
        p
    }
    fn payload_v3(tip: u64, beacon: Option<Beacon>) -> Vec<u8> {
        let mut p = PAYLOAD_MAGIC.to_vec();
        p.push(PAYLOAD_VERSION);
        p.extend_from_slice(&TARGET);
        p.extend_from_slice(&tip.to_be_bytes());
        p.extend_from_slice(&[0xab; 20]);
        let b = beacon.unwrap_or(Beacon { number: 0, hash: ZERO });
        p.extend_from_slice(&b.number.to_be_bytes());
        p.extend_from_slice(&b.hash);
        p
    }
    fn payload(tip: u64) -> Vec<u8> {
        payload_v3(tip, Some(BEACON))
    }

    #[test]
    fn payload_v3_and_v2() {
        assert_eq!(payload(1).len(), PAYLOAD_LEN);
        assert_eq!(parse_payload(&payload(1_000_000)), (TARGET, 1_000_000, [0xab; 20]));
        assert_eq!(payload_beacon(&payload(1)), Some(BEACON));
        assert_eq!(payload_beacon(&payload_v3(1, None)), None, "a zero beacon is no beacon");
        // v2 is read, without a beacon
        assert_eq!(parse_payload(&payload_v2(5)), (TARGET, 5, [0xab; 20]));
        assert_eq!(payload_beacon(&payload_v2(5)), None);
        // half-empty beacons are malformed
        let mut p = payload_v3(1, None);
        p[61] = 1;
        panics_with(|| payload_beacon(&p), "half empty");
        let mut p = payload_v3(1, None);
        p[60] = 1;
        panics_with(|| payload_beacon(&p), "half empty");
        // a version byte that does not match the length is refused
        let mut p = payload(1);
        p[4] = PAYLOAD_V2_VERSION;
        panics_with(|| parse_payload(&p), "not a KZB1 v3 or v2");
        let mut p = payload_v2(1);
        p[4] = PAYLOAD_VERSION;
        panics_with(|| parse_payload(&p), "not a KZB1 v3 or v2");
        let mut p = payload_v2(1);
        p[4] = 1;
        panics_with(|| parse_payload(&p), "not a KZB1 v3 or v2");
    }

    #[test]
    fn anchor_is_the_freshest_beacon() {
        let a = Beacon { number: 100, hash: [1; 32] };
        let b = Beacon { number: 250, hash: [2; 32] };
        let c = Beacon { number: 180, hash: [3; 32] };
        assert_eq!(pick_anchor(&[Some(a), None, Some(b), Some(c)]), b);
        assert_eq!(pick_anchor(&[None, Some(a)]), a);
        assert_eq!(pick_anchor(&[Some(b), Some(b)]), b, "the same beacon twice is fine");
        panics_with(|| pick_anchor(&[None, None]), "carries an Ethereum beacon");
        panics_with(|| pick_anchor(&[Some(b), Some(Beacon { number: 250, hash: [9; 32] })]), "different hashes");
        // a disagreement below the anchor is not the guest's concern (the relay never sees those beacons)
        assert_eq!(pick_anchor(&[Some(a), Some(Beacon { number: 100, hash: [9; 32] }), Some(b)]), b);
    }

    // ------------------------------------------------------------------ the burn reader

    fn cell_out(script: [u8; 35], cid: Hash) -> TxOutput {
        TxOutput { value: 20_000_000, spk_version: 0, script: script.to_vec(), covenant: Some((0, cid)) }
    }
    fn transfer_tx(tip: u64) -> TxBody {
        let mut change = KCC20_PREFIX.to_vec();
        change.extend(cell_window(&KCC20_TEMPLATE, 3, &[0x1b; 32], 0, 0, &ZERO, &ZERO));
        change.extend_from_slice(KCC20_SUFFIX);
        TxBody {
            version: 1,
            inputs: vec![TxInput { prev_tx_id: hb(4), prev_index: 2, sequence: 0 }],
            outputs: vec![
                cell_out(burn_cell_script(7), TOKEN),
                cell_out(p2sh_script(&change), TOKEN),
                TxOutput { value: 50_000_000, spk_version: 0, script: vec![0x20; 34], covenant: None },
            ],
            lock_time: 0,
            subnetwork: [0; 20],
            gas: 0,
            payload: payload(tip),
        }
    }
    fn read(tx: &TxBody, cells: &[BurnCell]) -> u64 {
        read_burn_cells(tx, cells, &TOKEN, &burn_cell_script)
    }
    fn bc(index: u32, amount: u64) -> BurnCell {
        BurnCell { index, amount }
    }

    #[test]
    fn burn_reader_accepts_the_burn_cell() {
        let tx = transfer_tx(1);
        assert_eq!(read(&tx, &[bc(0, 7)]), 7);
        let mut two = tx.clone();
        two.outputs[1] = cell_out(burn_cell_script(5), TOKEN);
        assert_eq!(read(&two, &[bc(0, 7), bc(1, 5)]), 12);
        assert_eq!(read(&two, &[bc(1, 5)]), 5);
    }

    #[test]
    fn burn_reader_refusals() {
        let tx = transfer_tx(1);
        panics_with(|| read(&tx, &[bc(0, 8)]), "is not a burn cell of amount 8");
        panics_with(|| read(&tx, &[bc(0, 6)]), "is not a burn cell of amount 6");
        panics_with(|| read(&tx, &[bc(1, 3)]), "is not a burn cell of amount 3");
        panics_with(|| read(&tx, &[bc(2, 7)]), "is not under the token's covenant id");
        panics_with(|| read(&tx, &[bc(0, 7), bc(0, 7)]), "named twice");
        panics_with(|| read(&tx, &[]), "names no cells");
        panics_with(|| read(&tx, &[bc(9, 7)]), "out of range");
        panics_with(|| read(&tx, &[bc(0, 0)]), "amount 0");
        let mut other = tx.clone();
        other.outputs[0].covenant = Some((0, [0x72; 32]));
        panics_with(|| read(&other, &[bc(0, 7)]), "not the token's");
        let mut v1spk = tx.clone();
        v1spk.outputs[0].spk_version = 1;
        panics_with(|| read(&v1spk, &[bc(0, 7)]), "spk version 1");
        let mut v0 = tx.clone();
        v0.version = 0;
        panics_with(|| read(&v0, &[bc(0, 7)]), "version 0");
        let mut mint = tx.clone();
        mint.outputs.insert(0, TxOutput { value: 1, spk_version: 0, script: vec![0xaa; 35], covenant: Some((0, [0xb7; 32])) });
        panics_with(|| read(&mint, &[bc(1, 7)]), "not the token's");
        let mut r = KCC20_PREFIX.to_vec();
        r.extend(cell_window(&KCC20_TEMPLATE, 7, &BURN_OWNER, OWNER_P2SH, 1, &ZERO, &ZERO));
        r.extend_from_slice(KCC20_SUFFIX);
        let mut borrow = tx.clone();
        borrow.outputs[0].script = p2sh_script(&r).to_vec();
        panics_with(|| read(&borrow, &[bc(0, 7)]), "is not a burn cell");
    }

    #[test]
    fn tampered_template_is_refused() {
        let mut s = KCC20_SUFFIX.to_vec();
        s[100] ^= 1;
        panics_with(|| run_with::<SoftKeccak>(&[], KCC20_PREFIX, &s), "reference cell template");
    }

    // ------------------------------------------------------------------ attestation steps

    #[test]
    fn attest_steps_bounds() {
        let c0 = hb(0xc0);
        let chain: BTreeMap<Hash, u32> = [(c0, 0u32)].into_iter().collect();
        let mk = |k: usize| -> BTreeMap<Hash, FpNode> {
            (1..=5u8)
                .map(|i| (hb(i), FpNode { aimr: if i as usize == k { c0 } else { hb(0x50 + i) }, first_parent: if i < 5 { Some(hb(i + 1)) } else { None } }))
                .collect()
        };
        for k in 1..=3 {
            assert_eq!(attest_steps(&hb(1), &mk(k), &chain), Some(k));
        }
        assert_eq!(attest_steps(&hb(1), &mk(4), &chain), None, "a 4-hop path does not attest");
        let mut gap = mk(3);
        gap.remove(&hb(2));
        assert_eq!(attest_steps(&hb(1), &gap, &chain), None);
        let cyc: BTreeMap<Hash, FpNode> =
            [(hb(1), FpNode { aimr: hb(0x51), first_parent: Some(hb(2)) }), (hb(2), FpNode { aimr: hb(0x52), first_parent: Some(hb(1)) })].into_iter().collect();
        assert_eq!(attest_steps(&hb(1), &cyc, &chain), None);
    }

    // ------------------------------------------------------------------ a synthetic end-to-end run

    /// A header preimage at the easiest target; nonce searched until it passes PoW at level >= `min_level`.
    /// Its blue work is the single byte `bw` (so K's journal fields are checkable).
    fn mk_header_bw(parents: &[Vec<Hash>], aimr: Hash, daa: u64, ts: u64, min_level: u32, bw: u8) -> (Vec<u8>, Hash) {
        for nonce in 0u64.. {
            let mut b = Vec::new();
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&(parents.len() as u64).to_le_bytes());
            for ps in parents {
                b.extend_from_slice(&(ps.len() as u64).to_le_bytes());
                for p in ps {
                    b.extend_from_slice(p);
                }
            }
            b.extend_from_slice(&[7u8; 32]);
            b.extend_from_slice(&aimr);
            b.extend_from_slice(&[9u8; 32]);
            b.extend_from_slice(&ts.to_le_bytes());
            b.extend_from_slice(&0x207fffffu32.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
            b.extend_from_slice(&daa.to_le_bytes());
            b.extend_from_slice(&daa.to_le_bytes());
            b.extend_from_slice(&1u64.to_le_bytes());
            b.push(bw);
            b.extend_from_slice(&[0xaa; 32]);
            if min_level == u32::MAX {
                let p = parse(&b).unwrap();
                return (b.clone(), header_hashes(&b, &p).0);
            }
            let v = verify_header::<SoftKeccak>(&b, Stage::Full).unwrap();
            if v.passed && v.level >= min_level {
                return (b, v.hash);
            }
        }
        unreachable!()
    }
    fn mk_header(parents: &[Vec<Hash>], aimr: Hash, daa: u64, ts: u64, min_level: u32) -> (Vec<u8>, Hash) {
        mk_header_bw(parents, aimr, daa, ts, min_level, 1)
    }

    const PROVER: [u8; 20] = [0x77; 20];

    struct Synth {
        w: Witness,
        expect_attesting: u32,
        expect_count: u32,
    }

    /// As v2's synthetic run (see the paths below). v4: the ladder ends at B (daa 20); the old K (daa 10) and s1
    /// (daa 12) stay in the witness as unused headers, which the guest tolerates.
    fn synth_with(tx: TxBody) -> Synth {
        let txid = tx_id(&tx);
        let mut smt = vec![0u8; 32];
        smt.extend_from_slice(&[1, 0]);
        let burn = Burn {
            tx,
            cells: vec![BurnCell { index: 0, amount: 7 }],
            leaves: vec![(hb(0x33), 0, 0), (txid, 1, 1)],
            leaf_index: 1,
            sp_timestamp: 1,
            c_daa_score: 20,
            c_blue_score: 20,
            parent_ref: hb(8),
            lane_blue_score: 20,
            inactivity_shortcut: hb(9),
            payload_and_ctx_digest: hb(10),
            parent_seq_commit: hb(11),
            smt_proof: smt,
            chain_state_roots: vec![hb(12)],
        };
        let b_aimr = inclusion(&burn, &TOKEN).seq_commit_final;
        let roots = [hb(0x61), hb(0x62), hb(0x63), hb(0x64)];
        let mut c = vec![b_aimr];
        for r in &roots {
            let n = h_seq(c.last().unwrap(), r);
            c.push(n);
        }
        let junk = |i: u8| hb(0xe0 + i);
        let anchor = hb(0x99);
        let mut headers = vec![];
        let mut y_headers = vec![];
        let mut ts = 100u64;
        let mut y = |aimr: Hash, fp: Hash| -> Hash {
            ts += 1;
            let (b, h) = mk_header(&[vec![fp]], aimr, 0, ts, u32::MAX);
            y_headers.push(b);
            h
        };
        let p2b = y(c[2], anchor);
        let p3c = y(c[3], anchor);
        let p3b = y(junk(2), p3c);
        let p4d = y(c[4], anchor);
        let p4c = y(junk(4), p4d);
        let p4b = y(junk(5), p4c);
        let mut pow = |parents: Vec<Hash>, aimr: Hash, daa: u64, t: u64, bw: u8| -> Hash {
            let (b, h) = mk_header_bw(&[parents], aimr, daa, t, 0, bw);
            headers.push(b);
            h
        };
        let p1 = pow(vec![anchor], c[1], 0, 201, 1);
        let p2 = pow(vec![p2b], junk(1), 0, 202, 1);
        let p3 = pow(vec![p3b], junk(3), 0, 203, 1);
        let p4 = pow(vec![p4b], junk(6), 0, 204, 1);
        let pg = pow(vec![hb(0x98)], junk(7), 0, 205, 1);
        let kh = pow(vec![anchor], junk(8), 10, 1, 0x2a);
        let s1 = pow(vec![kh], junk(9), 12, 2, 1);
        let bh = pow(vec![s1], b_aimr, 20, 3, 1);
        let s3 = pow(vec![bh], junk(10), 21, 4, 1);
        let s4 = pow(vec![p1, s3], junk(11), 22, 5, 1);
        let s5 = pow(vec![p2, s4], junk(12), 23, 6, 1);
        let s6 = pow(vec![p3, s5], junk(13), 24, 7, 1);
        let s7 = pow(vec![p4, s6], junk(14), 25, 8, 1);
        let th = pow(vec![pg, s7], junk(15), 26, 9, 1);
        Synth {
            w: Witness { soft_keccak: true, levels: vec![0], t: th, b: bh, token_cov_id: TOKEN, prover: PROVER, headers, y_headers, attest_roots: roots.to_vec(), burns: vec![burn] },
            expect_attesting: 4,
            expect_count: 6,
        }
    }
    fn synth() -> Synth {
        synth_with(transfer_tx(1))
    }

    #[test]
    fn synthetic_run_counts_three_step_attesters() {
        let s = synth();
        let input = s.w.encode();
        assert_eq!(Witness::decode(&input), s.w);
        let j = run::<SoftKeccak>(&input);
        assert_eq!(j.levels, vec![LevelCount { level: 0, count: s.expect_count, attesting: s.expect_attesting }]);
        assert_eq!(j.token_cov_id, TOKEN);
        assert_eq!(j.template_hash, KCC20_TEMPLATE);
        assert_eq!(j.target, TARGET);
        assert_eq!(j.burns.len(), 1);
        assert_eq!((j.burns[0].amount, j.burns[0].tip, j.burns[0].recipient), (7, 1, [0xab; 20]));
        assert_eq!(j.burns[0].tx_id, tx_id(&s.w.burns[0].tx));
        assert_eq!(j.n_headers as usize, s.w.headers.len() + s.w.y_headers.len());
        // v3: the anchor; v4 (KZO5): B and T, the median difficulty reading, no K
        assert_eq!(j.anchor, BEACON);
        assert_eq!((j.b_daa, j.t_daa), (20, 26));
        assert_eq!(j.r_bits, 0x207fffff);
        let e = j.encode();
        assert_eq!(e.len(), JOURNAL_HEADER_LEN + JOURNAL_BURN_LEN);
        assert_eq!(Journal::decode(&e).unwrap(), j);
        assert_eq!(&e[0..4], b"KZO6");
        assert_eq!(&e[36..44], &26u64.to_be_bytes());
        assert_eq!(&e[76..84], &20u64.to_be_bytes());
        assert_eq!(&e[84..88], &0x207fffffu32.to_be_bytes());
        assert_eq!(&e[185..217], &TOKEN);
        assert_eq!(&e[217..249], &KCC20_TEMPLATE);
        assert_eq!(&e[249..257], &BEACON.number.to_be_bytes());
        assert_eq!(&e[257..289], &BEACON.hash);
        assert_eq!(&e[289..309], &PROVER);
        assert_eq!(e[309], 1);
        assert_eq!(j.prover, PROVER);
        // F16: a witness without a prover is refused
        let mut w = s.w.clone();
        w.prover = [0; 20];
        panics_with(|| run::<SoftKeccak>(&w.encode()), "names no prover");
    }

    /// A header at a harder target than the synthetic DAG's 0x207fffff (nonce searched until the hash is under it).
    fn mk_header_bits(parents: &[Vec<Hash>], aimr: Hash, daa: u64, ts: u64, bits: u32) -> (Vec<u8>, Hash) {
        for nonce in 0u64.. {
            let mut b = Vec::new();
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&(parents.len() as u64).to_le_bytes());
            for ps in parents {
                b.extend_from_slice(&(ps.len() as u64).to_le_bytes());
                for p in ps {
                    b.extend_from_slice(p);
                }
            }
            b.extend_from_slice(&[7u8; 32]);
            b.extend_from_slice(&aimr);
            b.extend_from_slice(&[9u8; 32]);
            b.extend_from_slice(&ts.to_le_bytes());
            b.extend_from_slice(&bits.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
            b.extend_from_slice(&daa.to_le_bytes());
            b.extend_from_slice(&daa.to_le_bytes());
            b.extend_from_slice(&1u64.to_le_bytes());
            b.push(1);
            b.extend_from_slice(&[0xaa; 32]);
            let v = verify_header::<SoftKeccak>(&b, Stage::Full).unwrap();
            if v.passed {
                return (b, v.hash);
            }
        }
        unreachable!()
    }

    /// v4: the ladder is anchored at B. Without K the proof still verifies; T must come after B; a tip at or
    /// below B's daa is refused.
    #[test]
    fn synthetic_run_without_k_and_tip_must_follow_b() {
        let base = synth();
        let go = |w: &Witness| run::<SoftKeccak>(&w.encode());
        // drop the old K (daa 10) and s1 (daa 12): nothing refers to them any more
        let mut w = base.w.clone();
        w.headers.retain(|hb| {
            let d = verify_header::<SoftKeccak>(hb, Stage::Parse).unwrap().parsed.daa_score;
            d != 10 && d != 12
        });
        assert_eq!(w.headers.len(), base.w.headers.len() - 2);
        let j = go(&w);
        assert_eq!(j.levels[0], LevelCount { level: 0, count: base.expect_count, attesting: base.expect_attesting });
        assert_eq!(j.n_headers as usize, w.headers.len() + w.y_headers.len());
        // T = B: nothing after B
        let mut w = base.w.clone();
        w.t = w.b;
        panics_with(|| go(&w), "does not come after B");
        // B missing from the headers
        let mut w = base.w.clone();
        w.b = hb(0x5a);
        panics_with(|| go(&w), "is not among the headers");
    }

    /// The difficulty reading is the median over the ATTESTING superblocks (2.11.3, REVIEW-2026-11-08 F15).
    /// Premined, stamped superblocks beside the honest ladder are counted but cannot attest (nothing on their
    /// first-parent path reaches the chain): any number of them leaves the reading where it is. Planted
    /// superblocks that do attest (first parent B) move it only once they outnumber the honest attesters.
    #[test]
    fn difficulty_reading_is_the_median_of_the_attesting_superblocks() {
        let base = synth();
        let go = |w: &Witness| run::<SoftKeccak>(&w.encode());
        let hard: u32 = 0x1f7fffff; // target 2^8 below 0x207fffff: ~1 in 256 nonces pass
        // plant `n` hard superblocks between T and its level-0 parents: T' -> hard_1 -> ... -> hard_n -> old T;
        // with `attest` their first parent is B (aimr = c_0), so they attest in one step
        let plant = |n: usize, attest: bool| -> Witness {
            let mut w = base.w.clone();
            let mut tip = w.t;
            let mut ts = 1000u64;
            for i in 0..n {
                ts += 1;
                let parents = if attest { vec![w.b, tip] } else { vec![tip] };
                let (hb_, h) = mk_header_bits(&[parents], hb(0xa0 + i as u8), 30 + i as u64, ts, hard);
                w.headers.push(hb_);
                tip = h;
            }
            w.t = tip;
            w
        };
        // the stuffing attack (F15): 7 premined superblocks against 6 honest expanded ones; counted, not read
        let j = go(&plant(7, false));
        assert_eq!(j.levels[0], LevelCount { level: 0, count: base.expect_count + 7, attesting: base.expect_attesting });
        assert_eq!(j.r_bits, 0x207fffff, "premined superblocks that do not attest must not move the reading");
        let j = go(&plant(40, false));
        assert_eq!(j.levels[0].count, base.expect_count + 40);
        assert_eq!(j.r_bits, 0x207fffff, "however many");
        // attesting plants against 4 honest attesters: 1 of 5 and 4 of 8 leave it (index n/2 is honest), 5 of 9 move it
        let j = go(&plant(1, true));
        assert_eq!(j.levels[0], LevelCount { level: 0, count: base.expect_count + 1, attesting: base.expect_attesting + 1 });
        assert_eq!(j.r_bits, 0x207fffff, "one planted attester must not move the reading");
        let j = go(&plant(4, true));
        assert_eq!(j.levels[0].attesting, base.expect_attesting + 4);
        assert_eq!(j.r_bits, 0x207fffff, "4 of 8 must not move the reading");
        let j = go(&plant(5, true));
        assert_eq!(j.levels[0].attesting, base.expect_attesting + 5);
        assert_eq!(j.r_bits, hard, "5 of 9 attesters is a majority");
        // the pure function: sorted by target, hardest first, index n/2
        let t = |bits: u32| (U256::from_compact_target_bits(bits), bits);
        assert_eq!(median_bits(vec![t(0x207fffff)]), 0x207fffff);
        assert_eq!(median_bits(vec![t(0x207fffff), t(hard)]), 0x207fffff, "n = 2: index 1, the easier one");
        assert_eq!(median_bits(vec![t(hard), t(0x207fffff), t(0x207fffff)]), 0x207fffff);
        assert_eq!(median_bits(vec![t(hard), t(hard), t(0x207fffff)]), hard);
        let easy = 0x207ffffe; // a larger mantissa would be a larger target; this one is smaller: harder than 0x207fffff
        assert_eq!(median_bits(vec![t(0x207fffff), t(easy), t(0x207fffff)]), 0x207fffff);
        panics_with(|| median_bits(vec![]), "no attesting superblock");
    }

    /// Re-point the burn's activity leaf at its (changed) tx id, as a prover would.
    fn with_payload(base: &Witness, p: Vec<u8>) -> Witness {
        let mut w = base.clone();
        w.burns[0].tx.payload = p;
        let id = tx_id(&w.burns[0].tx);
        w.burns[0].leaves[1].0 = id;
        w
    }

    #[test]
    fn synthetic_run_refusals() {
        let base = synth();
        let go = |w: &Witness| run::<SoftKeccak>(&w.encode());
        let mut w = base.w.clone();
        w.burns[0].cells[0].amount = 8;
        panics_with(|| go(&w), "is not a burn cell of amount 8");
        let mut w = base.w.clone();
        w.burns[0].cells = vec![BurnCell { index: 1, amount: 3 }];
        panics_with(|| go(&w), "is not a burn cell of amount 3");
        let mut w = base.w.clone();
        w.token_cov_id = [0x72; 32];
        panics_with(|| go(&w), "not the token's");
        // F6: a tip equal to the amount, or above it, is refused (the tip check comes before inclusion)
        panics_with(|| go(&with_payload(&base.w, payload(7))), "must be below the burned amount");
        panics_with(|| go(&with_payload(&base.w, payload(8))), "must be below the burned amount");
        // the anchor: a proof whose only burn has no beacon is refused (v2 payload, or a zero v3 beacon); the
        // witness is rebuilt around the changed burn so everything else in it is valid
        let mut tx = transfer_tx(1);
        tx.payload = payload_v2(1);
        panics_with(|| go(&synth_with(tx.clone()).w), "carries an Ethereum beacon");
        tx.payload = payload_v3(1, None);
        panics_with(|| go(&synth_with(tx).w), "carries an Ethereum beacon");
        // hash-only headers and attestation roots, as v2
        let mut w = base.w.clone();
        let n = w.y_headers[0].len();
        w.y_headers[0][n - 1] ^= 1;
        assert_eq!(go(&w).levels[0].attesting, base.expect_attesting - 1);
        let mut w = base.w.clone();
        w.y_headers.remove(2);
        assert_eq!(go(&w).levels[0].attesting, base.expect_attesting - 1);
        let mut w = base.w.clone();
        w.attest_roots.truncate(2);
        assert_eq!(go(&w).levels[0].attesting, base.expect_attesting - 1);
        // a v2 input frame is refused
        let mut e = base.w.encode();
        e[3] = b'3';
        panics_with(|| run::<SoftKeccak>(&e), "bad input magic");
    }

    #[test]
    fn synthetic_run_with_tip_one_below_and_a_v2_payload_beside_an_anchor() {
        // tip = amount - 1 is the largest tip allowed
        let mut tx = transfer_tx(6);
        let s = synth_with(tx.clone());
        let j = run::<SoftKeccak>(&s.w.encode());
        assert_eq!((j.burns[0].amount, j.burns[0].tip), (7, 6));
        // the same tx with a zero tip and a fresher beacon: the journal's anchor follows the payload
        let fresh = Beacon { number: BEACON.number + 5, hash: [0xcf; 32] };
        tx.payload = payload_v3(0, Some(fresh));
        let s = synth_with(tx);
        assert_eq!(run::<SoftKeccak>(&s.w.encode()).anchor, fresh);
    }

    // ------------------------------------------------------------------ carried over from v2

    #[test]
    fn tx_id_vectors() {
        let empty = TxBody { version: 0, inputs: vec![], outputs: vec![], lock_time: 0, subnetwork: [0; 20], gas: 0, payload: vec![] };
        assert_eq!(hx(&tx_id(&empty)), "2c18d5e59ca8fc4c23d9560da3bf738a8f40935c11c162017fbf2c907b7e665c");
        let out = TxOutput { value: 1564, spk_version: 7, script: vec![1, 2, 3, 4, 5], covenant: None };
        let t3 = TxBody {
            version: 0,
            inputs: vec![TxInput { prev_tx_id: [0; 32], prev_index: 2, sequence: 7 }],
            outputs: vec![out.clone()],
            lock_time: 0,
            subnetwork: [0; 20],
            gas: 0,
            payload: vec![],
        };
        assert_eq!(hx(&tx_id(&t3)), "67289b12146d1b5ef384332137399791a5cfe89506ff31688b0d95ae821d0a0c");
        let mut registry = [0u8; 20];
        registry[0] = 2;
        let t8 = TxBody {
            version: 0,
            inputs: vec![TxInput { prev_tx_id: h32("59b3d6dc6cdc660c389c3fdb5704c48c598d279cdf1bab54182db586a4c95dd5"), prev_index: 2, sequence: 7 }],
            outputs: vec![out.clone()],
            lock_time: 54,
            subnetwork: registry,
            gas: 3,
            payload: vec![1, 2, 3],
        };
        assert_eq!(hx(&tx_id(&t8)), "4acda997dfb31c6518224c9ac00d0777fc7cbecdab461be3c0816b1cba19a056");
        let t10 = TxBody { version: 1, ..t8.clone() };
        assert_eq!(hx(&tx_id(&t10)), "a08a500b21be3e692c080b14e399fcfa2cfa01b25c08f2f8e7414d1c116e8d18");
        let v1_empty = TxBody {
            version: 1,
            inputs: vec![TxInput { prev_tx_id: [0; 32], prev_index: 0, sequence: 0 }],
            outputs: vec![],
            lock_time: 0,
            subnetwork: [0; 20],
            gas: 0,
            payload: vec![],
        };
        assert_eq!(hx(&tx_id(&v1_empty)), "5978e7aa1a9ba8fdf12dae6aa39aa198a91985e91192b291e207d4d6246349e6");
    }

    #[test]
    fn seq_commit_goldens() {
        assert_eq!(hx(&lane_key(&[0x42; 20])), "57c7e52c7602b366b3f662addc36129677d4844b840468ccaa9631106bea8897");
        let mut coinbase = [0u8; 20];
        coinbase[0] = 1;
        assert_eq!(hx(&lane_key(&coinbase)), "8aa78027db66a16cb69692ee0af5cb76738ef80ad14c9d13920d7fa3cc40b9e4");
        assert_eq!(hx(&activity_leaf(&hb(1), 0, 0)), "4ef43f316ecf616c6934b566ae41055e9712f1089b914f33186cdc9d55191121");
        let lk = lane_key(&[0x55; 20]);
        assert_eq!(hx(&lane_tip(&hb(1), &lk, &hb(2), &hb(3))), "38793576d545d2952df31b7c57193a492f9c5b8c09ddaeb2274e4e23edbc3f43");
        let pd = h_seq(&hb(2), &hb(3));
        assert_eq!(hx(&h_seq(&hb(1), &pd)), "20d135775a39be49fe34709a55b0c7eb3905f5c9be27d1dc1150b8af239e56d9");
        assert_eq!(hx(&h_seq(&hb(1), &hb(2))), "7e9e797699567ab5cbccc5a7e720c627099df83186e1d1e1cae88d8646c063df");
        assert_eq!(hx(&payload_digest(b"hello miner")), "c0f20a1777e175c50a6b97afbac57aae055ebab3dd7774e59aeb4c776c2a7d3a");
        assert_eq!(hx(&payload_digest(&[])), "9c0ca2acb45e92ffe6ceb4ae29188b35c82d9676cdd3ce067fd6ccc30a9c4a38");
    }

    #[test]
    fn merkle_shape() {
        assert_eq!(merkle_root_seq(&[]), ZERO);
        assert_eq!(merkle_root_seq(&[hb(1)]), hb(1));
        assert_eq!(merkle_root_seq(&[hb(1), hb(2)]), h_seq(&hb(1), &hb(2)));
        let three = merkle_root_seq(&[hb(1), hb(2), hb(3)]);
        assert_eq!(three, h_seq(&h_seq(&hb(1), &hb(2)), &h_seq(&hb(3), &ZERO)));
    }

    #[test]
    fn smt_roundtrip_shape() {
        let mut wire = vec![0u8; 32];
        wire.push(1);
        wire.push(0);
        let p = SmtProof::parse(&wire);
        let key = hb(9);
        assert_eq!(p.root(&key, Some(hb(5))), collapsed_node(&key, &hb(5)));
        let mut full = vec![0xffu8; 32];
        full.push(0);
        let p = SmtProof::parse(&full);
        let e = empty_hashes();
        assert_eq!(p.root(&key, None), e[SMT_DEPTH]);
    }

    #[test]
    fn journal_roundtrip() {
        let j = Journal {
            t: hb(5),
            t_daa: 90,
            b: hb(2),
            b_daa: 9,
            r_bits: 0x1a2b3c4d,
            n_headers: 7,
            levels: vec![LevelCount { level: 30, count: 544, attesting: 489 }],
            target: [0xcd; 20],
            token_cov_id: [0x71; 32],
            template_hash: KCC20_TEMPLATE,
            anchor: Beacon { number: 21_000_123, hash: [0xee; 32] },
            prover: [0x42; 20],
            burns: vec![
                JournalBurn { tx_id: hb(3), amount: 20_000_000, tip: 1_000_000, recipient: [0xab; 20] },
                JournalBurn { tx_id: hb(4), amount: 5, tip: 0, recipient: [0x01; 20] },
            ],
        };
        let e = j.encode();
        assert_eq!(e.len(), 310 + 2 * 68);
        assert_eq!(&e[289..309], &[0x42; 20]);
        assert_eq!(Journal::decode(&e).unwrap(), j);
        assert!(Journal::decode(&e[..e.len() - 1]).is_none());
        let mut old = e.clone();
        old[3] = b'5'; // a KZO5 journal (no prover, the reading over the expanded set) is refused
        assert!(Journal::decode(&old).is_none());
    }
}
