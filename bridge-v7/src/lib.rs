//! BRIDGE covenant v7 (bridge.sil: v6 plus a KAS floor on every minted cell, `cell_value`) and its KCC-20 Last Call
//! token family. The v4 text follows; the only v7 additions are `Params::cell_value` (a constructor constant) and
//! `Values::token_out` being checked against it by the covenant, not by this crate.
//!
//! BRIDGE covenant v4 (bridge.sil) and its KCC-20 Last Call token family: the unmodified
//! reference cell (KCC20.sil, argent-lang/kcc20-reference c8a0871, template 9703112e…) plus
//! BridgeMint (BridgeMint.sil, template dc96afcd…), the mint authority owned by the bridge.
//! Compile for a given state, build the transactions that init, advance (mint) and transfer,
//! and run every input through rusty-kaspa 2.1.0's script engine locally before anything is
//! submitted.
//!
//! All three sources are embedded, so the redeem scripts a deployed instance uses are a
//! function of (this crate's commit, constructor args, state) and nothing else.

use borsh::BorshDeserialize;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script};
use kaspa_txscript_errors::TxScriptError;
use sha2::{Digest, Sha256};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, encode_contract_covenant_decl_sig_script, encode_contract_entry_sig_script};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const SOURCE: &str = include_str!("../bridge.sil");
pub const CELL_SOURCE: &str = include_str!("../KCC20.sil");
pub const AUTHORITY_SOURCE: &str = include_str!("../BridgeMint.sil");
/// v5: the MinerDrip (minerdrip/minerdrip.sil, the Studio's, identical), compiled with the family id at init
pub const DRIP_SOURCE: &str = include_str!("../MinerDrip.sil");
pub const CONTRACT: &str = "EthBridge";
pub const CELL_CONTRACT: &str = "KCC20";
pub const AUTHORITY_CONTRACT: &str = "BridgeMint";
pub const ENTRY_ADVANCE: &str = "advance";
pub const ENTRY_INIT: &str = "init";
pub const ENTRY_MINT: &str = "mint";
pub const ENTRY_RETIRE: &str = "retire";
pub const ENTRY_TRANSFER: &str = "transfer";
pub const JOURNAL_FIXED_LEN: usize = 270;
pub const DEPOSIT_LEN: usize = 50;
pub const STATUS_MINT: u8 = 0;
pub const STATUS_SKIP: u8 = 1;
/// Loop bound in bridge.sil and BridgeMint.sil: deposits per journal the covenant will process.
pub const MAX_DEPOSITS: usize = 4;
/// KCC-20 Last Call owner schemes (KCC20.sil).
pub const OWNER_P2PK_SCHNORR: u8 = 0x00;
pub const OWNER_P2PKH_SCHNORR: u8 = 0x01;
pub const OWNER_P2PKH_ECDSA: u8 = 0x02;
pub const OWNER_P2SH: u8 = 0x03;
pub const OWNER_COVENANT_ID: u8 = 0x04;
pub const BORROW_DISABLED: u8 = 0x00;
/// Transfer path byte at the head of the witness (KCC20.sil).
pub const PATH_NORMAL: u8 = 0x00;
/// The provably unspendable p2sh owner: BLAKE2b-256 of the one-byte script `6a` (OP_RETURN).
/// A burn is a transfer to this owner with scheme OWNER_P2SH and borrow disabled.
pub const BURN_OWNER: [u8; 32] = [
    0xd3, 0x79, 0xe5, 0x0f, 0x3e, 0x22, 0x03, 0xf9, 0xa9, 0x25, 0x84, 0x91, 0x63, 0x35, 0xbb, 0x7c, 0xd0, 0x14, 0xb2, 0x37, 0xce, 0xaa,
    0x8b, 0x36, 0xf1, 0xd3, 0xd8, 0x0d, 0x0c, 0xc8, 0x8b, 0x32,
];
pub const SUBNETWORK_NATIVE: kaspa_consensus_core::subnets::SubnetworkId = kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;

pub type Result<T> = std::result::Result<T, String>;

/// Constructor constants: fixed for the life of a covenant instance.
#[derive(Clone, Debug)]
pub struct Params {
    pub image_id: [u8; 32],
    pub chain_commitment: [u8; 32],
    pub vault: [u8; 20],
    /// the ERC-20 (USDC proxy) whose blacklist the guest reads; journal bytes 228..248
    pub eth_token: [u8; 20],
    /// that proxy's implementation; journal bytes 248..268; an upgrade by Circle stalls the covenant
    pub eth_token_impl: [u8; 20],
    pub max_fee: i64,
    /// v5: the vault's MAX_DEPOSIT in base units; a status-0 journal entry above it makes the advance invalid
    pub max_mint: u64,
    /// v7: the KAS floor (sompi) of every minted cell and of the authority's cell at init; `max_fee` is the fee
    /// ceiling alone and the covenant lets the successor lose `max_fee + cell_value * mints` at most
    pub cell_value: u64,
    /// the token's KCC-1 extension commitment; zeros for a plain token (the Studio's value too)
    pub extension_commitment: [u8; 32],
}

/// The covenant state carried in the redeem script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub header: [u8; 32],
    pub committee: [u8; 32],
    pub cursor: u64,
    pub token: [u8; 32],
}

/// One deposit entry of the journal (50 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub nonce: u64,
    pub amount: u64,
    pub version: u8,
    pub payload: [u8; 32],
    /// STATUS_MINT or STATUS_SKIP (depositor blacklisted at the finalized block)
    pub status: u8,
}

/// The journal fields the covenant reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalView {
    pub chain_commitment: [u8; 32],
    pub prev_header: [u8; 32],
    pub prev_committee: [u8; 32],
    pub new_header: [u8; 32],
    pub new_committee: [u8; 32],
    pub new_slot: u64,
    pub exec_block_number: u64,
    pub vault: [u8; 20],
    pub token: [u8; 20],
    pub implementation: [u8; 20],
    pub deposits: Vec<Deposit>,
}

impl JournalView {
    /// The deposits an advance from `cursor` mints (status 0 beyond the cursor), and the cursor after it
    /// (past every deposit beyond it, minted or skipped).
    pub fn mints(&self, cursor: u64) -> (Vec<Deposit>, u64) {
        let beyond: Vec<Deposit> = self.deposits.iter().copied().filter(|d| d.nonce > cursor).collect();
        let next = beyond.last().map(|d| d.nonce).unwrap_or(cursor);
        let m = beyond.into_iter().filter(|d| d.status == STATUS_MINT).collect();
        (m, next)
    }
    /// The state after an advance from `prev`.
    pub fn next_state(&self, prev: &State) -> State {
        let (_, cursor) = self.mints(prev.cursor);
        State { header: self.new_header, committee: self.new_committee, cursor, token: prev.token }
    }
}

pub fn parse_journal(j: &[u8]) -> Result<JournalView> {
    if j.len() < JOURNAL_FIXED_LEN {
        return Err(format!("journal is {} bytes, expected >= {JOURNAL_FIXED_LEN}", j.len()));
    }
    let b = |o: usize| -> [u8; 32] { j[o..o + 32].try_into().unwrap() };
    let u64be = |o: usize| u64::from_be_bytes(j[o..o + 8].try_into().unwrap());
    let n = u16::from_be_bytes([j[268], j[269]]) as usize;
    if j.len() != JOURNAL_FIXED_LEN + DEPOSIT_LEN * n {
        return Err(format!("journal is {} bytes but names {n} deposits (expected {})", j.len(), JOURNAL_FIXED_LEN + DEPOSIT_LEN * n));
    }
    let deposits = (0..n)
        .map(|i| {
            let o = JOURNAL_FIXED_LEN + DEPOSIT_LEN * i;
            Deposit { nonce: u64be(o), amount: u64be(o + 8), version: j[o + 16], payload: j[o + 17..o + 49].try_into().unwrap(), status: j[o + 49] }
        })
        .collect::<Vec<_>>();
    if let Some(d) = deposits.iter().find(|d| d.status != STATUS_MINT && d.status != STATUS_SKIP) {
        return Err(format!("deposit nonce {} has status {}, not 0 or 1", d.nonce, d.status));
    }
    Ok(JournalView {
        chain_commitment: b(0),
        prev_header: b(32),
        prev_committee: b(64),
        new_header: b(96),
        new_committee: b(128),
        new_slot: u64be(160),
        exec_block_number: u64be(200),
        vault: j[208..228].try_into().unwrap(),
        token: j[228..248].try_into().unwrap(),
        implementation: j[248..268].try_into().unwrap(),
        deposits,
    })
}

// ---------------------------------------------------------------------------
// The token family: reference cell + BridgeMint authority

/// The six spec fields of a KCC-20 Last Call cell (KCC20.sil `KCC20State`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub amount: u64,
    pub owner: [u8; 32],
    pub owner_scheme: u8,
    pub borrow_scheme: u8,
    pub borrow_guard: [u8; 32],
    pub extension_commitment: [u8; 32],
}

impl Cell {
    /// A plain cell: p2pk-schnorr owner (32-byte x-only key), borrow disabled, zero commitment.
    pub fn p2pk(amount: u64, owner: [u8; 32]) -> Self {
        Self { amount, owner, owner_scheme: OWNER_P2PK_SCHNORR, borrow_scheme: BORROW_DISABLED, borrow_guard: [0; 32], extension_commitment: [0; 32] }
    }
    /// A burn cell: the unspendable p2sh owner, borrow disabled so the cell is final.
    pub fn burn(amount: u64, extension_commitment: [u8; 32]) -> Self {
        Self { amount, owner: BURN_OWNER, owner_scheme: OWNER_P2SH, borrow_scheme: BORROW_DISABLED, borrow_guard: [0; 32], extension_commitment }
    }
    /// The cell a deposit mints: journal version 0 -> p2pk-schnorr owner, 8 -> p2sh owner; the
    /// 32-byte payload is the owner in both cases. Borrow disabled (BridgeMint requires it).
    pub fn for_deposit(d: &Deposit, extension_commitment: [u8; 32]) -> Result<Self> {
        let owner_scheme = match d.version {
            0 => OWNER_P2PK_SCHNORR,
            8 => OWNER_P2SH,
            v => return Err(format!("deposit nonce {} has kaspa_spk version {v}, not 0 or 8", d.nonce)),
        };
        Ok(Self { amount: d.amount, owner: d.payload, owner_scheme, borrow_scheme: BORROW_DISABLED, borrow_guard: [0; 32], extension_commitment })
    }
    pub fn abi(&self) -> ArtifactValue {
        BTreeMap::from([
            ("amount".to_string(), ArtifactValue::Int(self.amount as i64)),
            ("owner".to_string(), ArtifactValue::Bytes(self.owner.to_vec())),
            ("owner_scheme".to_string(), ArtifactValue::Byte(self.owner_scheme)),
            ("borrow_scheme".to_string(), ArtifactValue::Byte(self.borrow_scheme)),
            ("borrow_guard".to_string(), ArtifactValue::Bytes(self.borrow_guard.to_vec())),
            ("extension_commitment".to_string(), ArtifactValue::Bytes(self.extension_commitment.to_vec())),
        ])
        .into()
    }
    fn ctor(&self, cell_template: [u8; 32]) -> Vec<ArtifactValue> {
        vec![
            ArtifactValue::Bytes(cell_template.to_vec()),
            ArtifactValue::Int(self.amount as i64),
            ArtifactValue::Bytes(self.owner.to_vec()),
            ArtifactValue::Byte(self.owner_scheme),
            ArtifactValue::Byte(self.borrow_scheme),
            ArtifactValue::Bytes(self.borrow_guard.to_vec()),
            ArtifactValue::Bytes(self.extension_commitment.to_vec()),
        ]
    }
}

/// The two templates of the family. Independent of any instance, so computed once per process.
#[derive(Clone, Debug)]
pub struct Family {
    /// reference cell: prefix (1 byte, `6b`), suffix (3,885 bytes), template 9703112e…
    pub cell_prefix: Vec<u8>,
    pub cell_suffix: Vec<u8>,
    pub cell_template: [u8; 32],
    /// BridgeMint: template dc96afcd…
    pub authority_template: [u8; 32],
}

fn compile_src(src: &str, ctor: &[ArtifactValue], what: &str) -> Result<SilAbiArtifact> {
    compile_to_sil_abi_artifact_with_options(src, ctor, CompileOptions::default()).map_err(|e| format!("compile {what}: {e}"))
}

fn parts(a: &SilAbiArtifact, contract: &str) -> Result<(Vec<u8>, Vec<u8>, [u8; 32])> {
    let c = a.contracts.get(contract).ok_or_else(|| format!("no contract {contract}"))?;
    let (prefix, _state, suffix) = c.compiled.script_parts(&c.compiled.bytecode).ok_or("bad state span")?;
    Ok((prefix.to_vec(), suffix.to_vec(), c.compiled.template_hash))
}

pub fn family() -> Result<&'static Family> {
    static F: OnceLock<Result<Family>> = OnceLock::new();
    F.get_or_init(|| {
        let z = ArtifactValue::Bytes(vec![0; 32]);
        let cell = compile_src(
            CELL_SOURCE,
            &[z.clone(), ArtifactValue::Int(0), z.clone(), ArtifactValue::Byte(0), ArtifactValue::Byte(0), z.clone(), z.clone()],
            "KCC20",
        )?;
        let (cell_prefix, cell_suffix, cell_template) = parts(&cell, CELL_CONTRACT)?;
        let bm = compile_src(AUTHORITY_SOURCE, &[z.clone(), z.clone(), z.clone(), z], "BridgeMint")?;
        let (_, _, authority_template) = parts(&bm, AUTHORITY_CONTRACT)?;
        Ok(Family { cell_prefix, cell_suffix, cell_template, authority_template })
    })
    .as_ref()
    .map_err(|e| e.clone())
}

/// The KCC-1 state window of a reference cell: explicit-length pushes, the generated template
/// field first, then amount (8 bytes LE), owner, owner_scheme, borrow_scheme, borrow_guard,
/// extension_commitment. 145 bytes.
pub fn cell_window(f: &Family, c: &Cell) -> Vec<u8> {
    let mut v = Vec::with_capacity(145);
    v.push(0x20);
    v.extend_from_slice(&f.cell_template);
    v.push(0x08);
    v.extend_from_slice(&(c.amount as i64).to_le_bytes());
    v.push(0x20);
    v.extend_from_slice(&c.owner);
    v.extend_from_slice(&[0x01, c.owner_scheme, 0x01, c.borrow_scheme, 0x20]);
    v.extend_from_slice(&c.borrow_guard);
    v.push(0x20);
    v.extend_from_slice(&c.extension_commitment);
    v
}

/// Redeem script of a reference cell: prefix || window || suffix (spliced; equals the compiler's output).
pub fn cell_redeem(c: &Cell) -> Result<Vec<u8>> {
    let f = family()?;
    let mut r = f.cell_prefix.clone();
    r.extend(cell_window(f, c));
    r.extend_from_slice(&f.cell_suffix);
    Ok(r)
}

/// Redeem script of a reference cell through the compiler (slow; the test checks it equals the splice).
pub fn cell_redeem_compiled(c: &Cell) -> Result<Vec<u8>> {
    let f = family()?;
    let a = compile_src(CELL_SOURCE, &c.ctor(f.cell_template), "KCC20")?;
    Ok(a.contracts.get(CELL_CONTRACT).expect("contract KCC20").compiled.bytecode.clone())
}

/// The cell's artifact (for encoding a `transfer`).
fn cell_artifact(c: &Cell) -> Result<SilAbiArtifact> {
    let f = family()?;
    compile_src(CELL_SOURCE, &c.ctor(f.cell_template), "KCC20")
}

/// The authority's constructor: (kcc20 template, own template, bridge covenant id, extension commitment).
pub fn authority_compile(bridge_covenant_id: [u8; 32], extension_commitment: [u8; 32]) -> Result<SilAbiArtifact> {
    let f = family()?;
    compile_src(
        AUTHORITY_SOURCE,
        &[
            ArtifactValue::Bytes(f.cell_template.to_vec()),
            ArtifactValue::Bytes(f.authority_template.to_vec()),
            ArtifactValue::Bytes(bridge_covenant_id.to_vec()),
            ArtifactValue::Bytes(extension_commitment.to_vec()),
        ],
        "BridgeMint",
    )
}

pub fn authority_redeem(bridge_covenant_id: [u8; 32], extension_commitment: [u8; 32]) -> Result<Vec<u8>> {
    Ok(authority_compile(bridge_covenant_id, extension_commitment)?.contracts.get(AUTHORITY_CONTRACT).expect("contract BridgeMint").compiled.bytecode.clone())
}

/// Signature script of BridgeMint `mint(recipients, kcc20_prefix, kcc20_suffix)`: grouped-field
/// array (KCC-1 3.4.6), the cell prefix and suffix, the dispatch tag, then push(redeem).
pub fn mint_sigscript(bridge_covenant_id: [u8; 32], extension_commitment: [u8; 32], recipients: &[Cell]) -> Result<Vec<u8>> {
    let f = family()?;
    let a = authority_compile(bridge_covenant_id, extension_commitment)?;
    let args = vec![
        ArtifactValue::Array(recipients.iter().map(Cell::abi).collect()),
        ArtifactValue::Bytes(f.cell_prefix.clone()),
        ArtifactValue::Bytes(f.cell_suffix.clone()),
    ];
    let mut s = encode_contract_entry_sig_script(&a, AUTHORITY_CONTRACT, ENTRY_MINT, &args).map_err(|e| format!("encode mint: {e}"))?;
    s.extend_from_slice(&push_data(&a.contracts.get(AUTHORITY_CONTRACT).unwrap().compiled.bytecode));
    Ok(s)
}

/// Signature script of BridgeMint `retire()` (unreachable with this bridge; kept for completeness).
pub fn retire_sigscript(bridge_covenant_id: [u8; 32], extension_commitment: [u8; 32]) -> Result<Vec<u8>> {
    let a = authority_compile(bridge_covenant_id, extension_commitment)?;
    let mut s = encode_contract_entry_sig_script(&a, AUTHORITY_CONTRACT, ENTRY_RETIRE, &[]).map_err(|e| format!("encode retire: {e}"))?;
    s.extend_from_slice(&push_data(&a.contracts.get(AUTHORITY_CONTRACT).unwrap().compiled.bytecode));
    Ok(s)
}

/// Signature script of a reference cell `transfer(next_states, witness)`. For a p2pk-schnorr
/// owner the witness is PATH_NORMAL || 65-byte signature (SIG_HASH_ALL appended).
pub fn cell_transfer_sigscript(prev: &Cell, next: &[Cell], witness: &[u8]) -> Result<Vec<u8>> {
    let a = cell_artifact(prev)?;
    let args = vec![ArtifactValue::Array(next.iter().map(Cell::abi).collect()), ArtifactValue::Bytes(witness.to_vec())];
    let mut s = encode_contract_entry_sig_script(&a, CELL_CONTRACT, ENTRY_TRANSFER, &args).map_err(|e| format!("encode transfer: {e}"))?;
    s.extend_from_slice(&push_data(&a.contracts.get(CELL_CONTRACT).unwrap().compiled.bytecode));
    Ok(s)
}

// ---------------------------------------------------------------------------
// Bridge covenant

pub fn compile(params: &Params, state: &State) -> Result<SilAbiArtifact> {
    let f = family()?;
    let args: Vec<ArtifactValue> = vec![
        params.image_id.to_vec().into(),
        params.chain_commitment.to_vec().into(),
        params.vault.to_vec().into(),
        params.eth_token.to_vec().into(),
        params.eth_token_impl.to_vec().into(),
        params.max_fee.into(),
        (params.max_mint as i64).into(),
        (params.cell_value as i64).into(),
        f.cell_template.to_vec().into(),
        f.authority_template.to_vec().into(),
        params.extension_commitment.to_vec().into(),
        state.header.to_vec().into(),
        state.committee.to_vec().into(),
        (state.cursor as i64).into(),
        state.token.to_vec().into(),
    ];
    compile_src(SOURCE, &args, "bridge")
}

pub fn redeem_script(artifact: &SilAbiArtifact) -> Vec<u8> {
    artifact.contracts.get(CONTRACT).expect("contract EthBridge").compiled.bytecode.clone()
}

pub fn push_data(data: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags::default()).add_data(data).expect("push").drain()
}

fn covenant_sigscript(artifact: &SilAbiArtifact, entry: &str, args: Vec<ArtifactValue>) -> Result<Vec<u8>> {
    let mut s = encode_contract_covenant_decl_sig_script(artifact, CONTRACT, entry, false, &args).map_err(|e| format!("encode {entry}: {e}"))?;
    s.extend_from_slice(&push_data(&redeem_script(artifact)));
    Ok(s)
}

/// Full signature script for `advance`: journal, proof, the cell prefix and suffix (the bridge
/// validates recipients against the cell template), dispatch tag, push(redeem).
pub fn advance_sigscript(artifact: &SilAbiArtifact, journal: &[u8], proof: &[u8]) -> Result<Vec<u8>> {
    let f = family()?;
    covenant_sigscript(
        artifact,
        ENTRY_ADVANCE,
        vec![
            ArtifactValue::Bytes(journal.to_vec()),
            ArtifactValue::Bytes(proof.to_vec()),
            ArtifactValue::Bytes(f.cell_prefix.clone()),
            ArtifactValue::Bytes(f.cell_suffix.clone()),
        ],
    )
}

/// Full signature script for `init`: the BridgeMint prefix and suffix, then push(redeem).
pub fn init_sigscript(artifact: &SilAbiArtifact, bridge_covenant_id: [u8; 32], extension_commitment: [u8; 32]) -> Result<Vec<u8>> {
    let a = authority_compile(bridge_covenant_id, extension_commitment)?;
    let (prefix, suffix, _) = parts(&a, AUTHORITY_CONTRACT)?;
    covenant_sigscript(artifact, ENTRY_INIT, vec![ArtifactValue::Bytes(prefix), ArtifactValue::Bytes(suffix)])
}

/// borsh(Groth16Receipt<ReceiptClaim>) -> the 128-byte compressed proof the verifier takes.
pub fn proof_from_receipt(receipt_borsh: &[u8]) -> Result<Vec<u8>> {
    let receipt = risc0_zkvm::Groth16Receipt::<risc0_zkvm::ReceiptClaim>::try_from_slice(receipt_borsh)
        .map_err(|e| format!("receipt borsh: {e}"))?;
    kaspa_txscript_zk_sdk::prepare_r0_groth16_proof(&receipt).map_err(|e| format!("prepare proof: {e}"))
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// A bundle directory as written by eth-prover (image_id.hex, journal.hex, receipt.hex).
pub struct Bundle {
    pub image_id: [u8; 32],
    pub journal: Vec<u8>,
    pub proof: Vec<u8>,
}

pub fn load_bundle(dir: &std::path::Path) -> Result<Bundle> {
    let read = |n: &str| -> Result<Vec<u8>> {
        let p = dir.join(n);
        let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        hex::decode(s.trim()).map_err(|e| format!("{}: {e}", p.display()))
    };
    let image_id: [u8; 32] = read("image_id.hex")?.try_into().map_err(|_| "image_id.hex is not 32 bytes".to_string())?;
    let journal = read("journal.hex")?;
    if let Ok(h) = read("journal_hash.hex") {
        if h != sha256(&journal) {
            return Err("journal.hex does not hash to journal_hash.hex".into());
        }
    }
    let proof = proof_from_receipt(&read("receipt.hex")?)?;
    Ok(Bundle { image_id, journal, proof })
}

// ---------------------------------------------------------------------------
// Transactions

/// A UTXO being spent: everything the engine and the sighash need.
#[derive(Clone, Debug)]
pub struct Spent {
    pub outpoint: TransactionOutpoint,
    pub value: u64,
    pub spk: ScriptPublicKey,
    pub covenant_id: Option<Hash>,
}

impl Spent {
    pub fn p2sh(outpoint: TransactionOutpoint, value: u64, redeem: &[u8], covenant_id: Option<Hash>) -> Self {
        Self { outpoint, value, spk: pay_to_script_hash_script(redeem), covenant_id }
    }
    /// A plain p2pk-schnorr UTXO (`20 <xonly> ac`), no covenant.
    pub fn p2pk(outpoint: TransactionOutpoint, value: u64, xonly: &[u8; 32]) -> Self {
        Self { outpoint, value, spk: p2pk_spk(xonly), covenant_id: None }
    }
    fn entry(&self) -> UtxoEntry {
        UtxoEntry::new(self.value, self.spk.clone(), 0, false, self.covenant_id)
    }
}

pub fn p2pk_spk(xonly: &[u8; 32]) -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend_from_slice(xonly);
    s.push(0xac);
    ScriptPublicKey::from_vec(0, s)
}

pub fn xonly_of(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let secp = secp256k1::Secp256k1::new();
    let kp = secp256k1::Keypair::from_seckey_slice(&secp, secret).map_err(|e| format!("key: {e}"))?;
    Ok(kp.x_only_public_key().0.serialize())
}

pub fn outpoint(txid: [u8; 32], index: u32) -> TransactionOutpoint {
    TransactionOutpoint { transaction_id: TransactionId::from_bytes(txid), index }
}

pub fn p2sh_output(value: u64, redeem: &[u8], covenant: Option<CovenantBinding>) -> TransactionOutput {
    TransactionOutput { value, script_public_key: pay_to_script_hash_script(redeem), covenant }
}

/// A complete v1 transaction with its spent entries; what the driver submits.
pub struct BuiltTx {
    pub tx: Transaction,
    pub spent: Vec<Spent>,
}

impl BuiltTx {
    pub fn new(inputs: Vec<(Spent, Vec<u8>)>, outputs: Vec<TransactionOutput>) -> Self {
        Self::with_payload(inputs, outputs, vec![])
    }

    pub fn with_payload(inputs: Vec<(Spent, Vec<u8>)>, outputs: Vec<TransactionOutput>, payload: Vec<u8>) -> Self {
        let spent: Vec<Spent> = inputs.iter().map(|(s, _)| s.clone()).collect();
        let tx_inputs = inputs.into_iter().map(|(s, sig)| TransactionInput::new_with_compute_budget(s.outpoint, sig, 0, 0)).collect();
        Self { tx: Transaction::new(1, tx_inputs, outputs, 0, SUBNETWORK_NATIVE, 0, payload), spent }
    }

    fn populated(&self) -> PopulatedTransaction<'_> {
        PopulatedTransaction::new(&self.tx, self.spent.iter().map(Spent::entry).collect())
    }

    /// Schnorr SIG_HASH_ALL signature for one input (65 bytes, hash type appended).
    pub fn sign(&self, input_idx: usize, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let secp = secp256k1::Secp256k1::new();
        let kp = secp256k1::Keypair::from_seckey_slice(&secp, secret).map_err(|e| format!("key: {e}"))?;
        let mtx = MutableTransaction::with_entries(self.tx.clone(), self.spent.iter().map(Spent::entry).collect());
        let reused = SigHashReusedValuesUnsync::new();
        let h = calc_schnorr_signature_hash(&mtx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused);
        let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice()).map_err(|e| format!("sighash: {e}"))?;
        let mut sig = secp.sign_schnorr(&msg, &kp).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        Ok(sig)
    }

    /// Run one input through the 2.1.0 engine; returns the script units it metered.
    pub fn execute(&self, input_idx: usize) -> std::result::Result<u64, TxScriptError> {
        let populated = self.populated();
        let reused = SigHashReusedValuesUnsync::new();
        let cache = Cache::new(1_000);
        let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
        let utxo = populated.utxo(input_idx).expect("utxo");
        let mut vm = TxScriptEngine::from_transaction_input(
            &populated,
            &self.tx.inputs[input_idx],
            input_idx,
            utxo,
            EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov_ctx),
            EngineFlags::default(),
        );
        vm.execute()?;
        Ok(vm.used_script_units().0)
    }

    /// Run every input; Ok(units per input) or the first failure with its input index.
    pub fn execute_all(&self) -> std::result::Result<Vec<u64>, (usize, TxScriptError)> {
        (0..self.tx.inputs.len()).map(|i| self.execute(i).map_err(|e| (i, e))).collect()
    }

    /// The covenant id a genesis group (this tx's input `auth_input`, these output indices) gets.
    pub fn genesis_covenant_id(&self, auth_input: usize, outputs: &[usize]) -> Hash {
        covenant_id(self.tx.inputs[auth_input].previous_outpoint, outputs.iter().map(|&i| (i as u32, &self.tx.outputs[i])))
    }

    /// Bytes of all signature scripts (the part of the size that varies with the proof and the cells).
    pub fn sigscript_bytes(&self) -> usize {
        self.tx.inputs.iter().map(|i| i.signature_script.len()).sum()
    }
}

/// Values the builder chooses for a spend; everything the covenants constrain is derived.
#[derive(Clone, Copy, Debug)]
pub struct Values {
    /// KAS taken out of the bridge UTXO for the miner.
    pub fee: u64,
    /// KAS each token output carries (storage mass needs real value; the bridge pays it).
    pub token_out: u64,
}

/// The KCC-23 metadata preparation output: a p2pk UTXO of ours whose creating transaction
/// carried `00 || JSON`. Spent by `init` as input 1, it authorizes the token genesis (output 1),
/// which binds the metadata to the token's covenant id.
#[derive(Clone, Debug)]
pub struct Prep {
    pub spent: Spent,
    pub secret: [u8; 32],
}

/// The init transaction: spend the bridge at `state` (token = 0), create the BridgeMint authority
/// as output 1, the genesis of a fresh covenant family. With `prep`, the authority is authorized
/// by the preparation input (KCC-23) and the family id derives from the prep outpoint; without,
/// by the bridge input. Returns the tx, the family id and the next bridge state.
pub fn build_init(params: &Params, state: &State, bridge: &Spent, bridge_covenant_id: Hash, prep: Option<&Prep>, v: &Values) -> Result<(BuiltTx, Hash, State)> {
    // v5: the two-output shape, kept for the negative test; the covenant requires the drip (build_init_with_drip)
    build_init_with_drip(params, state, bridge, bridge_covenant_id, prep, v, None).map(|(t, id, n, _)| (t, id, n))
}

/// The advance transaction. With no new mints: one input, one output (heartbeat). With n mints:
/// input 1 is the BridgeMint authority; outputs 1.. are the authority continuation (same script,
/// same KAS) and one reference cell per minted deposit, in journal order.
pub fn build_advance(
    params: &Params,
    state: &State,
    bridge: &Spent,
    bridge_covenant_id: Hash,
    authority: Option<&Spent>,
    journal: &[u8],
    proof: &[u8],
    v: &Values,
) -> Result<(BuiltTx, State)> {
    let cur = compile(params, state)?;
    let j = parse_journal(journal)?;
    let next = j.next_state(state);
    let successor = redeem_script(&compile(params, &next)?);
    let (mints, _) = j.mints(state.cursor);
    let mut inputs = vec![(bridge.clone(), advance_sigscript(&cur, journal, proof)?)];
    let mut outputs = vec![];
    let fee_total = v.fee + v.token_out * mints.len() as u64;
    let successor_value = bridge.value.checked_sub(fee_total).ok_or("advance: bridge value too small for fee + token outputs")?;
    outputs.push(p2sh_output(successor_value, &successor, Some(CovenantBinding { authorizing_input: 0, covenant_id: bridge_covenant_id })));
    if !mints.is_empty() {
        let authority = authority.ok_or("advance: the journal carries new deposits; the BridgeMint authority UTXO is required")?;
        let token_id = Hash::from_bytes(state.token);
        let recipients: Vec<Cell> = mints.iter().map(|d| Cell::for_deposit(d, params.extension_commitment)).collect::<Result<_>>()?;
        inputs.push((authority.clone(), mint_sigscript(bridge_covenant_id.as_bytes(), params.extension_commitment, &recipients)?));
        let bind = Some(CovenantBinding { authorizing_input: 1, covenant_id: token_id });
        outputs.push(TransactionOutput { value: authority.value, script_public_key: authority.spk.clone(), covenant: bind });
        for c in &recipients {
            outputs.push(p2sh_output(v.token_out, &cell_redeem(c)?, bind));
        }
    }
    Ok((BuiltTx::new(inputs, outputs), next))
}

/// A wallet-side transfer of one p2pk-owned cell into `next` (amounts must conserve), signed
/// with `secret`. `kas_change` gets whatever KAS is not in the token outputs.
pub fn build_transfer(
    token_id: Hash,
    input: &Spent,
    prev: &Cell,
    next: &[Cell],
    secret: &[u8; 32],
    token_out: u64,
    fee: u64,
    kas_change: Option<ScriptPublicKey>,
) -> Result<BuiltTx> {
    build_transfer_with_payload(token_id, input, prev, next, secret, token_out, fee, kas_change, vec![])
}

/// `build_transfer` with a transaction payload (U4: a burn's `KZB1 | 02 | target | tip | recipient`). The v1
/// sighash covers the payload, so it is fixed before signing and nobody can swap it afterwards.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_with_payload(
    token_id: Hash,
    input: &Spent,
    prev: &Cell,
    next: &[Cell],
    secret: &[u8; 32],
    token_out: u64,
    fee: u64,
    kas_change: Option<ScriptPublicKey>,
    payload: Vec<u8>,
) -> Result<BuiltTx> {
    let kas: Vec<u64> = vec![token_out; next.len()];
    build_transfer_cells(token_id, input, prev, next, &kas, secret, fee, kas_change, payload)
}

/// `build_transfer_with_payload` with the KAS of each next cell given separately (`cell_kas[i]` for `next[i]`).
/// A burn parks the mass-optimal value in the burn cell (KIP-9: a covenant output of value v costs 4C/v grams,
/// so v + fee(v) is smallest at v = sqrt(4C * rate), 0.2 KAS at the minimum relay rate) and gives the change cell
/// the rest; with one value for every cell the burn cell would park more than it must, or the change cell less.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_cells(
    token_id: Hash,
    input: &Spent,
    prev: &Cell,
    next: &[Cell],
    cell_kas: &[u64],
    secret: &[u8; 32],
    fee: u64,
    kas_change: Option<ScriptPublicKey>,
    payload: Vec<u8>,
) -> Result<BuiltTx> {
    build_transfer_funded(token_id, input, prev, next, cell_kas, secret, fee, kas_change, payload, None)
}

/// `build_transfer_cells` with an optional KAS funding input (U5): a plain p2pk UTXO of the same key as input 1.
/// The cells' KAS and the fee are paid from both inputs and the remainder goes to `kas_change`, so a holder's
/// cell keeps its working KAS instead of losing the park and the fee on every transfer. The cell's witness is a
/// SIG_HASH_ALL signature over the whole transaction, funding input included, so the funding input cannot be
/// swapped after signing; the funding input itself carries a plain Schnorr signature of the same key.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_funded(
    token_id: Hash,
    input: &Spent,
    prev: &Cell,
    next: &[Cell],
    cell_kas: &[u64],
    secret: &[u8; 32],
    fee: u64,
    kas_change: Option<ScriptPublicKey>,
    payload: Vec<u8>,
    fund: Option<&Spent>,
) -> Result<BuiltTx> {
    if cell_kas.len() != next.len() {
        return Err(format!("transfer: {} cells but {} KAS values", next.len(), cell_kas.len()));
    }
    let bind = Some(CovenantBinding { authorizing_input: 0, covenant_id: token_id });
    let mut outputs: Vec<TransactionOutput> =
        next.iter().zip(cell_kas).map(|(c, &v)| cell_redeem(c).map(|r| p2sh_output(v, &r, bind))).collect::<Result<_>>()?;
    let spent = cell_kas.iter().sum::<u64>() + fee;
    let in_value = input.value + fund.map(|f| f.value).unwrap_or(0);
    if let Some(spk) = kas_change {
        let change = in_value.checked_sub(spent).ok_or("transfer: input value too small")?;
        if change > 0 {
            outputs.push(TransactionOutput { value: change, script_public_key: spk, covenant: None });
        }
    } else if in_value < spent {
        return Err("transfer: input value too small".into());
    }
    let mut inputs = vec![(input.clone(), vec![])];
    if let Some(f) = fund {
        inputs.push((f.clone(), vec![]));
    }
    let unsigned = BuiltTx::with_payload(inputs.clone(), outputs.clone(), payload.clone());
    let mut witness = vec![PATH_NORMAL];
    witness.extend(unsigned.sign(0, secret)?);
    inputs[0].1 = cell_transfer_sigscript(prev, next, &witness)?;
    if fund.is_some() {
        inputs[1].1 = push_data(&unsigned.sign(1, secret)?);
    }
    Ok(BuiltTx::with_payload(inputs, outputs, payload))
}

/// Script units -> the compute budget that covers them (ComputeBudget::checked_covering_script_units).
pub fn covering_budget(units: u64) -> u64 {
    units.saturating_sub(9_999).div_ceil(10_000)
}

// ---------------------------------------------------------------------------
// v5 (Tipsy.k): MinerDrip in the genesis, and init with the drip as output 2

/// The MinerDrip's terms (minerdrip/minerdrip.js `schedule`): `claim()` once every `period` DAA pays
/// `max(balance / divisor, min_prize)` as the fee; `reveal()` once, while the coin holds the whole
/// `endowment`, pays `min_prize`. The token id stamped into the script is computed by `build_init_with_drip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DripTerms {
    pub period: u64,
    pub divisor: u64,
    pub min_prize: u64,
    pub endowment: u64,
}

/// What `build_init_with_drip` made of the terms: the compiled script and where it sits in the init tx.
#[derive(Clone, Debug)]
pub struct DripInfo {
    pub terms: DripTerms,
    pub token_id: Hash,
    pub redeem: Vec<u8>,
    pub spk: ScriptPublicKey,
    pub output_index: usize,
}

pub const DRIP_CONTRACT: &str = "MinerDrip";
pub const ENTRY_CLAIM: &str = "claim";
pub const ENTRY_REVEAL: &str = "reveal";

fn drip_ctor(t: &DripTerms, token_id: [u8; 32]) -> Vec<ArtifactValue> {
    vec![
        ArtifactValue::Int(t.period as i64),
        ArtifactValue::Int(t.divisor as i64),
        ArtifactValue::Int(t.min_prize as i64),
        ArtifactValue::Bytes(token_id.to_vec()),
        ArtifactValue::Int(t.endowment as i64),
    ]
}

/// The MinerDrip artifact for these terms, stamped with `token_id` (the token's covenant id).
pub fn drip_compile(t: &DripTerms, token_id: [u8; 32]) -> Result<SilAbiArtifact> {
    compile_src(DRIP_SOURCE, &drip_ctor(t, token_id), "MinerDrip")
}

/// The drip's redeem script (`7604 26aa3fc0 ...`; about 190 bytes, the integer pushes vary with the terms).
pub fn drip_redeem(t: &DripTerms, token_id: [u8; 32]) -> Result<Vec<u8>> {
    Ok(drip_compile(t, token_id)?.contracts.get(DRIP_CONTRACT).expect("contract MinerDrip").compiled.bytecode.clone())
}

/// Signature script of `claim()` or `reveal()`: the dispatch tag, then push(redeem). Nobody signs.
pub fn drip_sigscript(t: &DripTerms, token_id: [u8; 32], entry: &str) -> Result<Vec<u8>> {
    let a = drip_compile(t, token_id)?;
    let mut s = encode_contract_entry_sig_script(&a, DRIP_CONTRACT, entry, &[]).map_err(|e| format!("encode {entry}: {e}"))?;
    s.extend_from_slice(&push_data(&a.contracts.get(DRIP_CONTRACT).unwrap().compiled.bytecode));
    Ok(s)
}

/// A spend of the drip coin: `reveal` (sequence 0, keeps balance - min_prize) or `claim` (sequence = period,
/// keeps balance - max(balance / divisor, min_prize)). One input, one output back to the same script.
pub fn build_drip_spend(t: &DripTerms, token_id: [u8; 32], coin: &Spent, entry: &str) -> Result<BuiltTx> {
    let (keep, sequence) = match entry {
        ENTRY_REVEAL => {
            if coin.value < t.endowment {
                return Err("reveal: the coin no longer holds the whole endowment (already revealed)".into());
            }
            (coin.value.checked_sub(t.min_prize).ok_or("reveal: coin smaller than min_prize")?, 0u64)
        }
        ENTRY_CLAIM => {
            let prize = std::cmp::max(coin.value / t.divisor, t.min_prize);
            let keep = coin.value.checked_sub(prize).ok_or("claim: coin smaller than the prize")?;
            if keep < t.min_prize {
                return Err("claim: finished, only the last sliver is left".into());
            }
            (keep, t.period)
        }
        _ => return Err(format!("drip entry must be {ENTRY_REVEAL} or {ENTRY_CLAIM}")),
    };
    let sig = drip_sigscript(t, token_id, entry)?;
    let input = TransactionInput::new_with_compute_budget(coin.outpoint, sig, sequence, 0);
    let output = TransactionOutput { value: keep, script_public_key: coin.spk.clone(), covenant: None };
    Ok(BuiltTx { tx: Transaction::new(1, vec![input], vec![output], 0, SUBNETWORK_NATIVE, 0, vec![]), spent: vec![coin.clone()] })
}

/// The v5 init transaction: `build_init` with the token's miner endowment as output 2. The family id depends
/// only on the authorizing input and output 1, so it is computed first (as before), the drip is compiled with
/// it, and output 2 pays the drip's P2SH with `terms.endowment` KAS, taken from the inputs beside the fee and
/// the authority's KAS (so the prep output must carry it: `--prep-kas` = 2 + endowment). Output 2 is unbound.
pub fn build_init_with_drip(
    params: &Params,
    state: &State,
    bridge: &Spent,
    bridge_covenant_id: Hash,
    prep: Option<&Prep>,
    v: &Values,
    drip: Option<&DripTerms>,
) -> Result<(BuiltTx, Hash, State, Option<DripInfo>)> {
    if state.token != [0; 32] {
        return Err("init: the covenant already names a token".into());
    }
    let cur = compile(params, state)?;
    let authority = authority_redeem(bridge_covenant_id.as_bytes(), params.extension_commitment)?;
    let endowment = drip.map(|d| d.endowment).unwrap_or(0);
    let in_value = bridge.value + prep.map(|p| p.spent.value).unwrap_or(0);
    let successor_value = in_value.checked_sub(v.fee + v.token_out + endowment).ok_or("init: inputs too small for the fee, the authority and the endowment")?;
    let auth_input: u16 = if prep.is_some() { 1 } else { 0 };
    let token_out = p2sh_output(v.token_out, &authority, None);
    let mut inputs = vec![(bridge.clone(), vec![])];
    if let Some(p) = prep {
        inputs.push((p.spent.clone(), vec![]));
    }
    // the family id: the authorizing outpoint and output 1 only; neither the successor nor the drip enter it
    let placeholder = BuiltTx::new(inputs.clone(), vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::default(), covenant: None }, token_out.clone()]);
    let token_id = placeholder.genesis_covenant_id(auth_input as usize, &[1]);
    let next = State { token: token_id.as_bytes(), ..*state };
    let successor = redeem_script(&compile(params, &next)?);
    let mut outputs = vec![
        p2sh_output(successor_value, &successor, Some(CovenantBinding { authorizing_input: 0, covenant_id: bridge_covenant_id })),
        TransactionOutput { covenant: Some(CovenantBinding { authorizing_input: auth_input, covenant_id: token_id }), ..token_out },
    ];
    let info = match drip {
        Some(t) => {
            let redeem = drip_redeem(t, token_id.as_bytes())?;
            let spk = pay_to_script_hash_script(&redeem);
            outputs.push(TransactionOutput { value: t.endowment, script_public_key: spk.clone(), covenant: None });
            Some(DripInfo { terms: *t, token_id, redeem, spk, output_index: 2 })
        }
        None => None,
    };
    inputs[0].1 = init_sigscript(&cur, bridge_covenant_id.as_bytes(), params.extension_commitment)?;
    if let Some(p) = prep {
        let unsigned = BuiltTx::new(inputs.clone(), outputs.clone());
        inputs[1].1 = push_data(&unsigned.sign(1, &p.secret)?);
    }
    let built = BuiltTx::new(inputs, outputs);
    // the id must not have moved: it is fixed by the authorizing input and output 1 (the Studio checks this on every launch)
    if built.genesis_covenant_id(auth_input as usize, &[1]) != token_id {
        return Err("init: the family id moved between the placeholder and the real transaction".into());
    }
    Ok((built, token_id, next, info))
}
