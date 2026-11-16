//! kaspa-prover primitives: the parts of rusty-kaspa v2.1.0 consensus a header verifier needs,
//! rewritten without the kaspa crates so the same code runs natively (cross-checked against
//! rusty-kaspa through `kpow`'s vectors) and inside the RISC Zero guest.
//!
//! Source of every rule, rusty-kaspa v2.1.0 (commit 01b532e8):
//!   consensus/core/src/hashing/header.rs   serialized header, blake2b-256 keyed "BlockHash"
//!   crypto/hashes/src/pow_hashers.rs       cSHAKE256 initial states (constants copied verbatim)
//!   consensus/pow/src/{lib,matrix,xoshiro}.rs  target, matrix, heavy hash, level
//!   math/src/lib.rs                        Uint256::from_compact_target_bits, bits()
//!   consensus/core/src/config/params.rs    mainnet max_block_level = 225
//!
//! `relay` (O1): the outbound relay program on top of the header verifier: superblock ladders,
//! the KIP-21 sequencing commitment (consensus/seq-commit, crypto/smt), transaction ids.
//!
//! The matrix rank check (rusty-kaspa regenerates the matrix until it has full rank, in f64) is
//! not reproduced: the first matrix is used, as in `kpow`. A singular first matrix would make the
//! verifier reject an honest header (liveness), never accept a false one (the last PoW step is
//! a keccak), and its probability is ~1e-74 per header. The host asserts `attempts == 1` on every
//! vector it checks.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

pub mod relay;

/// Mainnet `max_block_level` (params.rs). Level = max(225 - bitlen(pow), 0).
pub const MAX_BLOCK_LEVEL: u32 = 225;

pub type Hash = [u8; 32];

/// The keccak-f[1600] permutation. The guest plugs the zkVM's keccak accelerator in here; the
/// host and the software path use `tiny_keccak::keccakf`.
pub trait KeccakF {
    fn f1600(state: &mut [u64; 25]);
}

pub struct SoftKeccak;
impl KeccakF for SoftKeccak {
    #[inline(always)]
    fn f1600(state: &mut [u64; 25]) {
        tiny_keccak::keccakf(state)
    }
}

// cSHAKE256 sponge states after absorbing the domain prefix and with the message padding
// pre-applied, copied verbatim from rusty-kaspa crypto/hashes/src/pow_hashers.rs.
// PoW: message = pre_pow_hash(32) | timestamp(8 LE) | zeros(32) | nonce(8 LE) = 80 bytes.
#[rustfmt::skip]
pub const POW_INITIAL_STATE: [u64; 25] = [
    1242148031264380989, 3008272977830772284, 2188519011337848018, 1992179434288343456, 8876506674959887717,
    5399642050693751366, 1745875063082670864, 8605242046444978844, 17936695144567157056, 3343109343542796272,
    1123092876221303306, 4963925045340115282, 17037383077651887893, 16629644495023626889, 12833675776649114147,
    3784524041015224902, 1082795874807940378, 13952716920571277634, 13411128033953605860, 15060696040649351053,
    9928834659948351306, 5237849264682708699, 12825353012139217522, 6706187291358897596, 196324915476054915,
];
// HeavyHash: message = 32 bytes.
#[rustfmt::skip]
pub const HEAVY_INITIAL_STATE: [u64; 25] = [
    4239941492252378377, 8746723911537738262, 8796936657246353646, 1272090201925444760, 16654558671554924250,
    8270816933120786537, 13907396207649043898, 6782861118970774626, 9239690602118867528, 11582319943599406348,
    17596056728278508070, 15212962468105129023, 7812475424661425213, 3370482334374859748, 5690099369266491460,
    8596393687355028144, 570094237299545110, 9119540418498120711, 16901969272480492857, 13372017233735502424,
    14372891883993151831, 5171152063242093102, 10573107899694386186, 6096431547456407061, 1592359455985097269,
];

// ---------------------------------------------------------------------------------------------
// Header preimage (the exact byte string blake2b sees; `hash_override_nonce_time` in header.rs)
// ---------------------------------------------------------------------------------------------
//
//   version u16 LE | n_levels u64 LE | per level: count u64 LE, 32*count parent hashes |
//   hash_merkle_root 32 | accepted_id_merkle_root 32 | utxo_commitment 32 |
//   timestamp u64 LE | bits u32 LE | nonce u64 LE | daa_score u64 LE | blue_score u64 LE |
//   blue_work: len u64 LE + big-endian bytes with leading zeros stripped | pruning_point 32

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub version: u16,
    pub n_levels: u64,
    /// byte range of the level-0 (direct) parent hashes inside the preimage
    pub parents0: (usize, usize),
    pub n_parents_total: u64,
    /// offset of the timestamp field; bits is at +8, nonce at +12, daa_score at +20
    pub ts_off: usize,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub blue_score: u64,
    /// blue_work as a 24-byte big-endian integer (Uint192)
    pub blue_work: [u8; 24],
    pub pruning_point: Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    TooManyParents,
    BlueWorkLength,
    TrailingBytes,
}

fn rd_u64(b: &[u8], at: usize) -> Result<u64, ParseError> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).ok_or(ParseError::Truncated)
}

pub fn parse(b: &[u8]) -> Result<Parsed, ParseError> {
    let version = u16::from_le_bytes(b.get(0..2).ok_or(ParseError::Truncated)?.try_into().unwrap());
    let n_levels = rd_u64(b, 2)?;
    let mut off = 10usize;
    let mut parents0 = (off, off);
    let mut n_parents_total = 0u64;
    for lvl in 0..n_levels {
        let count = rd_u64(b, off)?;
        off += 8;
        if count > 1 << 16 {
            return Err(ParseError::TooManyParents);
        }
        let end = off + 32 * count as usize;
        if end > b.len() {
            return Err(ParseError::Truncated);
        }
        if lvl == 0 {
            parents0 = (off, end);
        }
        n_parents_total += count;
        off = end;
    }
    // hash_merkle_root, accepted_id_merkle_root, utxo_commitment
    off += 96;
    let ts_off = off;
    let timestamp = rd_u64(b, off)?;
    let bits = u32::from_le_bytes(b.get(off + 8..off + 12).ok_or(ParseError::Truncated)?.try_into().unwrap());
    let nonce = rd_u64(b, off + 12)?;
    let daa_score = rd_u64(b, off + 20)?;
    let blue_score = rd_u64(b, off + 28)?;
    let bw_len = rd_u64(b, off + 36)? as usize;
    if bw_len > 24 {
        return Err(ParseError::BlueWorkLength);
    }
    off += 44;
    let bw = b.get(off..off + bw_len).ok_or(ParseError::Truncated)?;
    let mut blue_work = [0u8; 24];
    blue_work[24 - bw_len..].copy_from_slice(bw);
    off += bw_len;
    let pruning_point: Hash = b.get(off..off + 32).ok_or(ParseError::Truncated)?.try_into().unwrap();
    off += 32;
    if off != b.len() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Parsed { version, n_levels, parents0, n_parents_total, ts_off, timestamp, bits, nonce, daa_score, blue_score, blue_work, pruning_point })
}

/// Direct parents (level 0) of a parsed header.
pub fn direct_parents<'a>(b: &'a [u8], p: &Parsed) -> impl Iterator<Item = &'a [u8]> + 'a {
    b[p.parents0.0..p.parents0.1].chunks_exact(32)
}

/// Parent hashes of a header at `level` in the header's expanded `parents_by_level` form
/// (`parents_at_level` in consensus), or None if the header lists fewer levels. Only valid on a
/// preimage that `parse` accepted.
pub fn parents_at_level(b: &[u8], level: usize) -> Option<core::slice::ChunksExact<'_, u8>> {
    let n_levels = rd_u64(b, 2).ok()? as usize;
    if level >= n_levels {
        return None;
    }
    let mut off = 10usize;
    for _ in 0..level {
        let c = rd_u64(b, off).ok()? as usize;
        off += 8 + 32 * c;
    }
    let c = rd_u64(b, off).ok()? as usize;
    off += 8;
    b.get(off..off + 32 * c).map(|s| s.chunks_exact(32))
}

// ---------------------------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------------------------

fn blake2b_block_hasher() -> blake2b_simd::State {
    blake2b_simd::Params::new().hash_length(32).key(b"BlockHash").to_state()
}

/// (block hash, pre_pow_hash). Both are blake2b-256 keyed "BlockHash" over the preimage; the
/// pre-PoW hash has timestamp and nonce zeroed. Everything before the timestamp is shared, so it is
/// absorbed once and the state is cloned (this halves the blake2b work compared with two passes).
pub fn header_hashes(b: &[u8], p: &Parsed) -> (Hash, Hash) {
    let mut st = blake2b_block_hasher();
    st.update(&b[..p.ts_off]);
    let mut st2 = st.clone();
    st.update(&b[p.ts_off..]);
    // zeroed timestamp (8) | bits (4) | zeroed nonce (8) | rest
    st2.update(&[0u8; 8]);
    st2.update(&b[p.ts_off + 8..p.ts_off + 12]);
    st2.update(&[0u8; 8]);
    st2.update(&b[p.ts_off + 20..]);
    let mut h = [0u8; 32];
    let mut pp = [0u8; 32];
    h.copy_from_slice(st.finalize().as_bytes());
    pp.copy_from_slice(st2.finalize().as_bytes());
    (h, pp)
}

#[inline(always)]
fn absorb_hash(state: &mut [u64; 25], h: &Hash) {
    for (i, chunk) in h.chunks_exact(8).enumerate() {
        state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

#[inline(always)]
fn squeeze_hash(state: &[u64; 25]) -> Hash {
    let mut out = [0u8; 32];
    for (i, w) in state[..4].iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// cSHAKE256("ProofOfWorkHash")(pre_pow_hash | timestamp | 0^32 | nonce), one permutation.
pub fn pow_hash<K: KeccakF>(pre_pow: &Hash, timestamp: u64, nonce: u64) -> Hash {
    let mut s = POW_INITIAL_STATE;
    absorb_hash(&mut s, pre_pow);
    s[4] ^= timestamp;
    s[9] ^= nonce;
    K::f1600(&mut s);
    squeeze_hash(&s)
}

/// cSHAKE256("HeavyHash")(32 bytes), one permutation.
pub fn kheavy_hash<K: KeccakF>(input: &Hash) -> Hash {
    let mut s = HEAVY_INITIAL_STATE;
    absorb_hash(&mut s, input);
    K::f1600(&mut s);
    squeeze_hash(&s)
}

// ---------------------------------------------------------------------------------------------
// Matrix (xoshiro256++ seeded with pre_pow_hash; first matrix, no rank check)
// ---------------------------------------------------------------------------------------------

pub struct Xoshiro {
    s: [u64; 4],
}
impl Xoshiro {
    pub fn new(h: &Hash) -> Self {
        let mut s = [0u64; 4];
        for (i, c) in h.chunks_exact(8).enumerate() {
            s[i] = u64::from_le_bytes(c.try_into().unwrap());
        }
        Self { s }
    }
    #[inline(always)]
    pub fn u64(&mut self) -> u64 {
        let s = &mut self.s;
        let res = s[0].wrapping_add(s[0].wrapping_add(s[3]).rotate_left(23));
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        res
    }
}

/// 64 x 64 nibbles, row-major, as rusty-kaspa's `Matrix::rand_matrix_no_rank_check`.
pub type Matrix = [[u8; 64]; 64];

pub fn gen_matrix(pre_pow: &Hash) -> Matrix {
    let mut g = Xoshiro::new(pre_pow);
    let mut m = [[0u8; 64]; 64];
    for row in m.iter_mut() {
        let mut val = 0u64;
        for (j, e) in row.iter_mut().enumerate() {
            let shift = j % 16;
            if shift == 0 {
                val = g.u64();
            }
            *e = ((val >> (4 * shift)) & 0x0F) as u8;
        }
    }
    m
}

/// `Matrix::heavy_hash`: matrix x nibbles(hash), keep the top 4 bits of each sum, XOR with the
/// hash, cSHAKE256("HeavyHash").
pub fn heavy_hash<K: KeccakF>(m: &Matrix, hash: &Hash) -> Hash {
    let mut v = [0u8; 64];
    for (i, b) in hash.iter().enumerate() {
        v[2 * i] = b >> 4;
        v[2 * i + 1] = b & 0x0F;
    }
    let mut product = [0u8; 32];
    for i in 0..32 {
        let mut s1 = 0u16;
        let mut s2 = 0u16;
        let r1 = &m[2 * i];
        let r2 = &m[2 * i + 1];
        for j in 0..64 {
            s1 += (r1[j] as u16) * (v[j] as u16);
            s2 += (r2[j] as u16) * (v[j] as u16);
        }
        product[i] = (((s1 >> 10) << 4) as u8) | ((s2 >> 10) as u8);
    }
    for (p, h) in product.iter_mut().zip(hash) {
        *p ^= h;
    }
    kheavy_hash::<K>(&product)
}

// ---------------------------------------------------------------------------------------------
// Target, PoW value, level (Uint256 as little-endian u64 limbs, like kaspa_math)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);

    pub fn from_le_bytes(b: &[u8; 32]) -> Self {
        let mut l = [0u64; 4];
        for (i, c) in b.chunks_exact(8).enumerate() {
            l[i] = u64::from_le_bytes(c.try_into().unwrap());
        }
        U256(l)
    }
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }
    /// `Uint256::bits()`: bit length.
    pub fn bits(&self) -> u32 {
        for (i, &w) in self.0.iter().enumerate().rev() {
            if w != 0 {
                return 64 * (i as u32 + 1) - w.leading_zeros();
            }
        }
        0
    }
    pub fn shl(&self, n: u32) -> Self {
        let mut out = [0u64; 4];
        let limb = (n / 64) as usize;
        let sh = n % 64;
        for i in 0..4 {
            if i + limb < 4 {
                out[i + limb] |= self.0[i] << sh;
                if sh != 0 && i + limb + 1 < 4 {
                    out[i + limb + 1] |= self.0[i] >> (64 - sh);
                }
            }
        }
        U256(out)
    }
    /// `Uint256::from_compact_target_bits`.
    pub fn from_compact_target_bits(bits: u32) -> Self {
        let (mant, expt) = {
            let unshifted = bits >> 24;
            if unshifted <= 3 {
                ((bits & 0xFFFFFF) >> (8 * (3 - unshifted)), 0)
            } else {
                (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
            }
        };
        if mant > 0x7FFFFF {
            U256::ZERO
        } else if expt >= 256 {
            U256::ZERO
        } else {
            U256([mant as u64, 0, 0, 0]).shl(expt)
        }
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for U256 {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&o.0[i]) {
                core::cmp::Ordering::Equal => continue,
                x => return x,
            }
        }
        core::cmp::Ordering::Equal
    }
}

/// `calc_level_from_pow`.
pub fn level_from_pow(pow: &U256, max_block_level: u32) -> u32 {
    let l = max_block_level as i64 - pow.bits() as i64;
    if l < 0 { 0 } else { l as u32 }
}

// ---------------------------------------------------------------------------------------------
// One header, staged (so the guest can be measured one stage at a time)
// ---------------------------------------------------------------------------------------------

/// How much of the verification to run. Cumulative; `Full` is the real thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    /// parse only (sizes, field offsets)
    Parse = 0,
    /// + the two blake2b hashes (block hash, pre_pow_hash); enough for parent links
    Hash = 1,
    /// + cSHAKE256 PoW hash (one keccak-f)
    PowHash = 2,
    /// + matrix generation, heavy hash (second keccak-f), target check, level
    Full = 3,
}

impl Stage {
    pub fn from_u8(v: u8) -> Option<Stage> {
        Some(match v {
            0 => Stage::Parse,
            1 => Stage::Hash,
            2 => Stage::PowHash,
            3 => Stage::Full,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub parsed: Parsed,
    pub hash: Hash,
    pub pre_pow: Hash,
    pub pow_hash: Hash,
    /// final PoW value (heavy hash output, as a number)
    pub pow: U256,
    pub target: U256,
    pub passed: bool,
    pub level: u32,
}

pub fn verify_header<K: KeccakF>(b: &[u8], stage: Stage) -> Result<Verified, ParseError> {
    let parsed = parse(b)?;
    let mut v = Verified {
        parsed,
        hash: [0; 32],
        pre_pow: [0; 32],
        pow_hash: [0; 32],
        pow: U256::ZERO,
        target: U256::ZERO,
        passed: false,
        level: 0,
    };
    if stage == Stage::Parse {
        return Ok(v);
    }
    let (h, pp) = header_hashes(b, &parsed);
    v.hash = h;
    v.pre_pow = pp;
    if stage == Stage::Hash {
        return Ok(v);
    }
    v.pow_hash = pow_hash::<K>(&pp, parsed.timestamp, parsed.nonce);
    if stage == Stage::PowHash {
        return Ok(v);
    }
    let m = gen_matrix(&pp);
    let heavy = heavy_hash::<K>(&m, &v.pow_hash);
    v.pow = U256::from_le_bytes(&heavy);
    v.target = U256::from_compact_target_bits(parsed.bits);
    v.passed = v.pow <= v.target;
    v.level = level_from_pow(&v.pow, MAX_BLOCK_LEVEL);
    Ok(v)
}

// ---------------------------------------------------------------------------------------------
// Guest input and journal
// ---------------------------------------------------------------------------------------------

/// Input frame: magic "KZE1" | stage u8 | link u8 (1 = require parent links) |
/// keccak u8 (0 = zkVM keccak accelerator, 1 = software permutation; same result, different cost) |
/// n u32 LE | n x (len u32 LE, preimage bytes), headers in chain order (oldest first).
pub const INPUT_MAGIC: &[u8; 4] = b"KZE1";
pub const INPUT_HEADER_LEN: usize = 11;

pub fn encode_input(stage: Stage, link: bool, soft_keccak: bool, headers: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + headers.iter().map(|h| h.len() + 4).sum::<usize>());
    out.extend_from_slice(INPUT_MAGIC);
    out.push(stage as u8);
    out.push(link as u8);
    out.push(soft_keccak as u8);
    out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for h in headers {
        out.extend_from_slice(&(h.len() as u32).to_le_bytes());
        out.extend_from_slice(h);
    }
    out
}

/// Journal, 592 bytes, big-endian:
///   0    4   n headers
///   4    1   stage
///   5    1   link checked (1) or not (0)
///   6    1   keccak path used (0 = accelerator, 1 = software); informational
///   7    1   reserved (0)
///   8   32   hash of the first (oldest) header
///  40   32   hash of the last (newest) header
///  72    4   min level
///  76    4   max level
///  80  512   level histogram: u16 count for levels 0..=255 (Full stage only; zeros otherwise)
pub const JOURNAL_LEN: usize = 592;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub n: u32,
    pub stage: Stage,
    pub link: bool,
    pub soft_keccak: bool,
    pub first: Hash,
    pub last: Hash,
    pub min_level: u32,
    pub max_level: u32,
    pub hist: [u16; 256],
}

impl Journal {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(JOURNAL_LEN);
        o.extend_from_slice(&self.n.to_be_bytes());
        o.push(self.stage as u8);
        o.push(self.link as u8);
        o.push(self.soft_keccak as u8);
        o.push(0);
        o.extend_from_slice(&self.first);
        o.extend_from_slice(&self.last);
        o.extend_from_slice(&self.min_level.to_be_bytes());
        o.extend_from_slice(&self.max_level.to_be_bytes());
        for c in self.hist.iter() {
            o.extend_from_slice(&c.to_be_bytes());
        }
        debug_assert_eq!(o.len(), JOURNAL_LEN);
        o
    }
    pub fn decode(b: &[u8]) -> Option<Journal> {
        if b.len() != JOURNAL_LEN {
            return None;
        }
        let mut hist = [0u16; 256];
        for (i, c) in b[80..].chunks_exact(2).enumerate() {
            hist[i] = u16::from_be_bytes([c[0], c[1]]);
        }
        Some(Journal {
            n: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            stage: Stage::from_u8(b[4])?,
            link: b[5] == 1,
            soft_keccak: b[6] == 1,
            first: b[8..40].try_into().unwrap(),
            last: b[40..72].try_into().unwrap(),
            min_level: u32::from_be_bytes(b[72..76].try_into().unwrap()),
            max_level: u32::from_be_bytes(b[76..80].try_into().unwrap()),
            hist,
        })
    }
}

/// The whole program, shared by the guest and by the host's native cross-check. Verifies every
/// header to `stage`, checks (when `link`) that header i's hash is a direct parent of header i+1,
/// and returns the journal. Panics on any failure, like the guest must.
pub fn input_wants_soft_keccak(input: &[u8]) -> bool {
    assert!(input.len() >= INPUT_HEADER_LEN && &input[..4] == INPUT_MAGIC, "bad input magic");
    input[6] == 1
}

pub fn run<K: KeccakF>(input: &[u8]) -> Journal {
    assert!(input.len() >= INPUT_HEADER_LEN && &input[..4] == INPUT_MAGIC, "bad input magic");
    let stage = Stage::from_u8(input[4]).expect("bad stage");
    let link = input[5] == 1;
    let soft_keccak = input[6] == 1;
    let n = u32::from_le_bytes(input[7..11].try_into().unwrap());
    let mut off = INPUT_HEADER_LEN;
    let mut j = Journal { n, stage, link, soft_keccak, first: [0; 32], last: [0; 32], min_level: u32::MAX, max_level: 0, hist: [0; 256] };
    let mut prev: Option<Hash> = None;
    for i in 0..n {
        let len = u32::from_le_bytes(input[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let hb = &input[off..off + len];
        off += len;
        let v = verify_header::<K>(hb, stage).expect("header does not parse");
        if stage >= Stage::Full {
            assert!(v.passed, "header {i} fails proof of work");
            j.hist[(v.level.min(255)) as usize] = j.hist[(v.level.min(255)) as usize].saturating_add(1);
            j.min_level = j.min_level.min(v.level);
            j.max_level = j.max_level.max(v.level);
        }
        if link && stage >= Stage::Hash {
            if let Some(p) = prev {
                assert!(direct_parents(hb, &v.parsed).any(|x| x == p), "header {i} does not have header {} as a direct parent", i - 1);
            }
            prev = Some(v.hash);
        }
        if i == 0 {
            j.first = v.hash;
        }
        j.last = v.hash;
    }
    assert_eq!(off, input.len(), "trailing input bytes");
    if j.min_level == u32::MAX {
        j.min_level = 0;
    }
    j
}

impl PartialOrd for Stage {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        (*self as u8).partial_cmp(&(*o as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{CShake, Hasher, Xof};

    fn cshake_state_after_prefix(custom: &[u8], msg_len: usize) -> [u64; 25] {
        // Absorb bytepad(encode_string("") || encode_string(custom), 136), permute, then XOR in the
        // cSHAKE padding for a message of msg_len bytes (0x04 at msg_len, 0x80 at 135).
        let mut block = [0u8; 136];
        let mut p = 0;
        block[p] = 1; p += 1; block[p] = 136; p += 1; // left_encode(136)
        block[p] = 1; p += 1; block[p] = 0; p += 1;   // encode_string("") = left_encode(0)
        block[p] = 1; p += 1; block[p] = (custom.len() * 8) as u8; p += 1; // left_encode(bits)
        block[p..p + custom.len()].copy_from_slice(custom);
        let mut s = [0u64; 25];
        for (i, c) in block.chunks_exact(8).enumerate() {
            s[i] ^= u64::from_le_bytes(c.try_into().unwrap());
        }
        tiny_keccak::keccakf(&mut s);
        s[msg_len / 8] ^= 0x04u64 << (8 * (msg_len % 8));
        s[16] ^= 0x8000000000000000u64;
        s
    }

    #[test]
    fn initial_states_match_cshake_definition() {
        assert_eq!(cshake_state_after_prefix(b"ProofOfWorkHash", 80), POW_INITIAL_STATE);
        assert_eq!(cshake_state_after_prefix(b"HeavyHash", 32), HEAVY_INITIAL_STATE);
    }

    #[test]
    fn pow_hash_matches_tiny_keccak_cshake() {
        // Same vector as rusty-kaspa's test_pow_hash.
        let pre = [42u8; 32];
        let ts = 5435345234u64;
        let nonce = 432432432u64;
        let ours = pow_hash::<SoftKeccak>(&pre, ts, nonce);
        let mut h = CShake::v256(b"", b"ProofOfWorkHash");
        h.update(&pre);
        h.update(&ts.to_le_bytes());
        h.update(&[0u8; 32]);
        h.update(&nonce.to_le_bytes());
        let mut want = [0u8; 32];
        h.squeeze(&mut want);
        assert_eq!(ours, want);
        let ours = kheavy_hash::<SoftKeccak>(&pre);
        let mut h = CShake::v256(b"", b"HeavyHash");
        h.update(&pre);
        h.squeeze(&mut want);
        assert_eq!(ours, want);
    }

    #[test]
    fn blake2b_keyed_matches_rusty_kaspa_vectors() {
        // crypto/hashes/src/hashers.rs test_vectors, BlockHash row (incremental: each hash is over
        // the concatenation of all inputs so far).
        let inputs: [&[u8]; 5] = [
            &[],
            &[1],
            &[5, 199, 126, 44, 71, 32, 82, 139, 122, 217, 43, 48, 52, 112, 40, 209, 180, 83, 139, 231, 72, 48, 136, 48, 168, 226, 133, 7, 60, 4, 160, 205],
            &[42; 64],
            &[0; 8],
        ];
        let want = [
            "a80b6aa20f20b15ebabe2b1949527f78a257594a732e774de637d85e6973a768",
            "5643023add641f9421187b8c9aa3c6c73227d5ec34131c61a08d35b43e7e4b65",
            "4dc3bf72045431e46f8839a7d390898f27c887fddd8637149bfb70f732f04334",
            "15d7648e69023dca65c949a61ea166192049f449c604523494813873b19918a7",
            "3ac41af8385ea5d902ce6d47f509b7accc9c631f1d57a719d777874467f6d877",
        ];
        let mut st = blake2b_block_hasher();
        for (inp, w) in inputs.iter().zip(want) {
            st.update(inp);
            assert_eq!(hex::encode(st.clone().finalize().as_bytes()), w);
        }
    }

    fn synth_header(parents: &[Hash], ts: u64, nonce: u64, bits: u32, blue_work_be: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&3u64.to_le_bytes()); // 3 levels
        for lvl in 0..3u64 {
            let ps: &[Hash] = if lvl == 0 { parents } else { &parents[..1.min(parents.len())] };
            b.extend_from_slice(&(ps.len() as u64).to_le_bytes());
            for p in ps { b.extend_from_slice(p); }
        }
        b.extend_from_slice(&[7u8; 32]); b.extend_from_slice(&[8u8; 32]); b.extend_from_slice(&[9u8; 32]);
        b.extend_from_slice(&ts.to_le_bytes());
        b.extend_from_slice(&bits.to_le_bytes());
        b.extend_from_slice(&nonce.to_le_bytes());
        b.extend_from_slice(&1234u64.to_le_bytes());
        b.extend_from_slice(&999u64.to_le_bytes());
        b.extend_from_slice(&(blue_work_be.len() as u64).to_le_bytes());
        b.extend_from_slice(blue_work_be);
        b.extend_from_slice(&[0xAAu8; 32]);
        b
    }

    #[test]
    fn parse_roundtrip_and_shared_prefix_hash() {
        let h = synth_header(&[[1u8; 32], [2u8; 32]], 1_700_000_000_000, 0xdeadbeef, 0x1d00ffff, &[1, 226, 64]);
        let p = parse(&h).unwrap();
        assert_eq!(p.n_levels, 3);
        assert_eq!(p.n_parents_total, 4);
        assert_eq!(p.timestamp, 1_700_000_000_000);
        assert_eq!(p.nonce, 0xdeadbeef);
        assert_eq!(p.bits, 0x1d00ffff);
        assert_eq!(p.daa_score, 1234);
        assert_eq!(p.blue_score, 999);
        assert_eq!(&p.blue_work[21..], &[1, 226, 64]); // 123456
        assert_eq!(p.pruning_point, [0xAA; 32]);
        assert_eq!(direct_parents(&h, &p).count(), 2);
        // parents_at_level agrees with the parse for every level and refuses missing ones
        assert_eq!(parents_at_level(&h, 0).unwrap().count(), 2);
        assert_eq!(parents_at_level(&h, 1).unwrap().count(), 1);
        assert_eq!(parents_at_level(&h, 2).unwrap().next().unwrap(), &[1u8; 32]);
        assert!(parents_at_level(&h, 3).is_none());
        // accepted_id_merkle_root sits 64 bytes before the timestamp
        assert_eq!(&h[p.ts_off - 64..p.ts_off - 32], &[8u8; 32]);
        // the shared-prefix trick equals two independent full passes
        let (hash, pre) = header_hashes(&h, &p);
        let full = |b: &[u8]| { let mut s = blake2b_block_hasher(); s.update(b); let mut o = [0u8; 32]; o.copy_from_slice(s.finalize().as_bytes()); o };
        assert_eq!(hash, full(&h));
        let h0 = synth_header(&[[1u8; 32], [2u8; 32]], 0, 0, 0x1d00ffff, &[1, 226, 64]);
        assert_eq!(pre, full(&h0));
        assert!(matches!(parse(&h[..h.len() - 1]), Err(ParseError::Truncated)));
    }

    #[test]
    fn compact_target_and_bits() {
        // 0x1d00ffff: mant 0x00ffff, expt 8*(0x1d-3) = 208 -> 0xffff << 208
        let t = U256::from_compact_target_bits(0x1d00ffff);
        assert_eq!(t.bits(), 224);
        assert_eq!(t.0, [0, 0, 0, 0xffffu64 << 16]);
        let t = U256::from_compact_target_bits(0x03123456);
        assert_eq!(t.0, [0x123456, 0, 0, 0]);
        let t = U256::from_compact_target_bits(0x01123456);
        assert_eq!(t.0, [0x12, 0, 0, 0]);
        assert_eq!(U256::from_compact_target_bits(0x04923456), U256::ZERO); // negative mantissa
        assert_eq!(level_from_pow(&U256([1, 0, 0, 0]), 225), 224);
        assert_eq!(level_from_pow(&U256([0, 0, 0, 1 << 63]), 225), 0);
        // the journal round-trips
        let j = Journal { n: 3, stage: Stage::Full, link: true, soft_keccak: false, first: [1; 32], last: [2; 32], min_level: 24, max_level: 33, hist: { let mut h = [0u16; 256]; h[24] = 2; h[33] = 1; h } };
        assert_eq!(Journal::decode(&j.encode()).unwrap(), j);
    }

    #[test]
    fn run_links_and_rejects_bad_links() {
        // Build a 3-header chain at Hash stage (no PoW needed) and check links.
        let a = synth_header(&[[0u8; 32]], 1, 1, 0x1d00ffff, &[1]);
        let ha = header_hashes(&a, &parse(&a).unwrap()).0;
        let b = synth_header(&[[5u8; 32], ha], 2, 2, 0x1d00ffff, &[2]);
        let hb = header_hashes(&b, &parse(&b).unwrap()).0;
        let c = synth_header(&[hb], 3, 3, 0x1d00ffff, &[3]);
        let hc = header_hashes(&c, &parse(&c).unwrap()).0;
        let j = run::<SoftKeccak>(&encode_input(Stage::Hash, true, false, &[a.clone(), b.clone(), c.clone()]));
        assert_eq!((j.n, j.first, j.last), (3, ha, hc));
        let bad = std::panic::catch_unwind(|| run::<SoftKeccak>(&encode_input(Stage::Hash, true, false, &[a.clone(), c.clone()])));
        assert!(bad.is_err());
        let ok = run::<SoftKeccak>(&encode_input(Stage::Hash, false, false, &[a, c]));
        assert_eq!(ok.n, 2);
    }
}
