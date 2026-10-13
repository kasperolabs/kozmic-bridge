//! BRIDGE covenant (bridge.sil) and its KCC-20 token (kcc20.sil): compile for a given
//! state, build the transactions that init, advance (mint) and transfer, and run every
//! input through rusty-kaspa 2.1.0's script engine locally before anything is submitted.
//!
//! Both contract sources are embedded, so the redeem scripts a deployed instance uses are
//! a function of (this crate's commit, constructor args, state) and nothing else.

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
use silverscript_abi::{ArtifactValue, SilAbiArtifact, encode_contract_covenant_decl_sig_script};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};
use std::collections::BTreeMap;

pub const SOURCE: &str = include_str!("../bridge.sil");
pub const TOKEN_SOURCE: &str = include_str!("../kcc20.sil");
pub const CONTRACT: &str = "EthBridge";
pub const TOKEN_CONTRACT: &str = "KCC20";
pub const ENTRY_ADVANCE: &str = "advance";
pub const ENTRY_INIT: &str = "init";
pub const TOKEN_ENTRY_TRANSFER: &str = "transfer";
pub const JOURNAL_FIXED_LEN: usize = 230;
pub const DEPOSIT_LEN: usize = 49;
/// Loop bound in bridge.sil: deposits per journal the covenant will process.
pub const MAX_DEPOSITS: usize = 4;
/// KCC20 template parameters (part of the token's identity: change them and it is another token).
pub const TOKEN_MAX_COV_INS: i64 = 4;
pub const TOKEN_MAX_COV_OUTS: i64 = 1 + MAX_DEPOSITS as i64;
pub const IDENTIFIER_PUBKEY: u8 = 0x00;
pub const IDENTIFIER_SCRIPT_HASH: u8 = 0x01;
pub const IDENTIFIER_COVENANT_ID: u8 = 0x02;
pub const SUBNETWORK_NATIVE: kaspa_consensus_core::subnets::SubnetworkId = kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;

pub type Result<T> = std::result::Result<T, String>;

/// Constructor constants: fixed for the life of a covenant instance.
#[derive(Clone, Debug)]
pub struct Params {
    pub image_id: [u8; 32],
    pub chain_commitment: [u8; 32],
    pub vault: [u8; 20],
    pub max_fee: i64,
}

/// The covenant state carried in the redeem script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub header: [u8; 32],
    pub committee: [u8; 32],
    pub cursor: u64,
    pub token: [u8; 32],
}

/// One deposit entry of the journal (49 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub nonce: u64,
    pub amount: u64,
    pub version: u8,
    pub payload: [u8; 32],
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
    pub deposits: Vec<Deposit>,
}

impl JournalView {
    /// The deposits an advance from `cursor` mints, and the cursor after it.
    pub fn mints(&self, cursor: u64) -> (Vec<Deposit>, u64) {
        let m: Vec<Deposit> = self.deposits.iter().copied().filter(|d| d.nonce > cursor).collect();
        let next = m.last().map(|d| d.nonce).unwrap_or(cursor);
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
    let n = u16::from_be_bytes([j[228], j[229]]) as usize;
    if j.len() != JOURNAL_FIXED_LEN + DEPOSIT_LEN * n {
        return Err(format!("journal is {} bytes but names {n} deposits (expected {})", j.len(), JOURNAL_FIXED_LEN + DEPOSIT_LEN * n));
    }
    let deposits = (0..n)
        .map(|i| {
            let o = JOURNAL_FIXED_LEN + DEPOSIT_LEN * i;
            Deposit { nonce: u64be(o), amount: u64be(o + 8), version: j[o + 16], payload: j[o + 17..o + 49].try_into().unwrap() }
        })
        .collect();
    Ok(JournalView {
        chain_commitment: b(0),
        prev_header: b(32),
        prev_committee: b(64),
        new_header: b(96),
        new_committee: b(128),
        new_slot: u64be(160),
        exec_block_number: u64be(200),
        vault: j[208..228].try_into().unwrap(),
        deposits,
    })
}

// ---------------------------------------------------------------------------
// KCC20 token

/// The state of one KCC20 UTXO (field order = kcc20.sil).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenState {
    pub owner: [u8; 32],
    pub owner_type: u8,
    pub amount: u64,
    pub is_minter: bool,
}

impl TokenState {
    pub fn minter_branch(bridge_covenant_id: [u8; 32]) -> Self {
        Self { owner: bridge_covenant_id, owner_type: IDENTIFIER_COVENANT_ID, amount: 0, is_minter: true }
    }
    /// The recipient branch a deposit mints: version 0 -> pubkey owner, 8 -> script-hash owner.
    pub fn for_deposit(d: &Deposit) -> Result<Self> {
        let owner_type = match d.version {
            0 => IDENTIFIER_PUBKEY,
            8 => IDENTIFIER_SCRIPT_HASH,
            v => return Err(format!("deposit nonce {} has kaspa_spk version {v}, not 0 or 8", d.nonce)),
        };
        Ok(Self { owner: d.payload, owner_type, amount: d.amount, is_minter: false })
    }
    pub fn abi(&self) -> ArtifactValue {
        BTreeMap::from([
            ("ownerIdentifier".to_string(), ArtifactValue::Bytes(self.owner.to_vec())),
            ("identifierType".to_string(), ArtifactValue::Byte(self.owner_type)),
            ("amount".to_string(), ArtifactValue::Int(self.amount as i64)),
            ("isMinter".to_string(), ArtifactValue::Bool(self.is_minter)),
        ])
        .into()
    }
}

pub fn token_compile(s: &TokenState) -> Result<SilAbiArtifact> {
    let args: Vec<ArtifactValue> = vec![
        ArtifactValue::Bytes(s.owner.to_vec()),
        ArtifactValue::Int(s.amount as i64),
        ArtifactValue::Byte(s.owner_type),
        ArtifactValue::Bool(s.is_minter),
        ArtifactValue::Int(TOKEN_MAX_COV_INS),
        ArtifactValue::Int(TOKEN_MAX_COV_OUTS),
    ];
    compile_to_sil_abi_artifact_with_options(TOKEN_SOURCE, &args, CompileOptions::default()).map_err(|e| format!("compile kcc20: {e}"))
}

pub fn token_redeem(s: &TokenState) -> Result<Vec<u8>> {
    Ok(token_compile(s)?.contracts.get(TOKEN_CONTRACT).expect("contract KCC20").compiled.bytecode.clone())
}

/// The token template: redeem script minus state, and its canonical hash (what the bridge pins).
pub struct TokenTemplate {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub hash: [u8; 32],
}

pub fn token_template() -> Result<TokenTemplate> {
    let a = token_compile(&TokenState::minter_branch([0; 32]))?;
    let c = a.contracts.get(TOKEN_CONTRACT).expect("contract KCC20");
    let (prefix, _state, suffix) = c.compiled.script_parts(&c.compiled.bytecode).ok_or("bad state span")?;
    Ok(TokenTemplate { prefix: prefix.to_vec(), suffix: suffix.to_vec(), hash: c.compiled.template_hash })
}

/// Signature script of a KCC20 `transfer`: the new states (in covenant-output order), one
/// signature (ignored by the contract for covenant-id owners) and the witness byte.
pub fn token_transfer_sigscript(prev: &TokenState, new_states: &[TokenState], sig: &[u8], witness: u8) -> Result<Vec<u8>> {
    let a = token_compile(prev)?;
    let args = vec![
        ArtifactValue::Array(new_states.iter().map(|s| s.abi()).collect()),
        ArtifactValue::Bytes(sig.to_vec()),
        ArtifactValue::Byte(witness),
    ];
    let mut s = encode_contract_covenant_decl_sig_script(&a, TOKEN_CONTRACT, TOKEN_ENTRY_TRANSFER, true, &args)
        .map_err(|e| format!("encode kcc20 transfer: {e}"))?;
    s.extend_from_slice(&push_data(&a.contracts.get(TOKEN_CONTRACT).unwrap().compiled.bytecode));
    Ok(s)
}

// ---------------------------------------------------------------------------
// Bridge covenant

pub fn compile(params: &Params, state: &State) -> Result<SilAbiArtifact> {
    let t = token_template()?;
    let args: Vec<ArtifactValue> = vec![
        params.image_id.to_vec().into(),
        params.chain_commitment.to_vec().into(),
        params.vault.to_vec().into(),
        params.max_fee.into(),
        (t.prefix.len() as i64).into(),
        (t.suffix.len() as i64).into(),
        t.hash.to_vec().into(),
        state.header.to_vec().into(),
        state.committee.to_vec().into(),
        (state.cursor as i64).into(),
        state.token.to_vec().into(),
    ];
    compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default()).map_err(|e| format!("compile: {e}"))
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

/// Full signature script for `advance`: ABI-encoded args, dispatch tag, then push(redeem).
pub fn advance_sigscript(artifact: &SilAbiArtifact, journal: &[u8], proof: &[u8]) -> Result<Vec<u8>> {
    covenant_sigscript(artifact, ENTRY_ADVANCE, vec![ArtifactValue::Bytes(journal.to_vec()), ArtifactValue::Bytes(proof.to_vec())])
}

/// Full signature script for `init`: the token template bytes, then push(redeem).
pub fn init_sigscript(artifact: &SilAbiArtifact) -> Result<Vec<u8>> {
    let t = token_template()?;
    covenant_sigscript(artifact, ENTRY_INIT, vec![ArtifactValue::Bytes(t.prefix), ArtifactValue::Bytes(t.suffix)])
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
    fn entry(&self) -> UtxoEntry {
        UtxoEntry::new(self.value, self.spk.clone(), 0, false, self.covenant_id)
    }
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
        let spent: Vec<Spent> = inputs.iter().map(|(s, _)| s.clone()).collect();
        let tx_inputs = inputs.into_iter().map(|(s, sig)| TransactionInput::new_with_compute_budget(s.outpoint, sig, 0, 0)).collect();
        Self { tx: Transaction::new(1, tx_inputs, outputs, 0, SUBNETWORK_NATIVE, 0, vec![]), spent }
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
}

/// Values the builder chooses for a spend; everything the covenants constrain is derived.
#[derive(Clone, Copy, Debug)]
pub struct Values {
    /// KAS taken out of the bridge UTXO for the miner.
    pub fee: u64,
    /// KAS each token output carries (storage mass needs real value; the bridge pays it).
    pub token_out: u64,
}

/// The init transaction: spend the bridge at `state` (token = 0), create the KCC20 genesis
/// (minter branch owned by the bridge) as output 1. Returns the tx and the new token id.
pub fn build_init(params: &Params, state: &State, bridge: &Spent, bridge_covenant_id: Hash, v: &Values) -> Result<(BuiltTx, Hash, State)> {
    if state.token != [0; 32] {
        return Err("init: the covenant already names a token".into());
    }
    let cur = compile(params, state)?;
    let minter = token_redeem(&TokenState::minter_branch(bridge_covenant_id.as_bytes()))?;
    let successor_value = bridge.value.checked_sub(v.fee + v.token_out).ok_or("init: bridge value too small")?;
    // The successor's script depends on the token id, which depends on the genesis output,
    // which does not depend on the successor: build the genesis output first.
    let token_out = p2sh_output(v.token_out, &minter, None);
    let placeholder = BuiltTx::new(vec![(bridge.clone(), vec![])], vec![TransactionOutput { value: 0, script_public_key: ScriptPublicKey::default(), covenant: None }, token_out.clone()]);
    let token_id = placeholder.genesis_covenant_id(0, &[1]);
    let next = State { token: token_id.as_bytes(), ..*state };
    let successor = redeem_script(&compile(params, &next)?);
    let outputs = vec![
        p2sh_output(successor_value, &successor, Some(CovenantBinding { authorizing_input: 0, covenant_id: bridge_covenant_id })),
        TransactionOutput { covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: token_id }), ..token_out },
    ];
    let tx = BuiltTx::new(vec![(bridge.clone(), init_sigscript(&cur)?)], outputs);
    Ok((tx, token_id, next))
}

/// The advance transaction. With no new deposits: one input, one output (heartbeat).
/// With n new deposits: input 1 is the token's minter branch; outputs 1.. are the minter
/// branch continuation and one recipient branch per deposit.
pub fn build_advance(
    params: &Params,
    state: &State,
    bridge: &Spent,
    bridge_covenant_id: Hash,
    minter: Option<&Spent>,
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
        let minter = minter.ok_or("advance: the journal carries new deposits; the token minter branch UTXO is required")?;
        let token_id = Hash::from_bytes(state.token);
        let minter_state = TokenState::minter_branch(bridge_covenant_id.as_bytes());
        let mut new_states = vec![minter_state];
        for d in &mints {
            new_states.push(TokenState::for_deposit(d)?);
        }
        inputs.push((minter.clone(), token_transfer_sigscript(&minter_state, &new_states, &[0u8; 65], 0)?));
        let bind = Some(CovenantBinding { authorizing_input: 1, covenant_id: token_id });
        outputs.push(p2sh_output(minter.value, &token_redeem(&minter_state)?, bind));
        for s in &new_states[1..] {
            outputs.push(p2sh_output(v.token_out, &token_redeem(s)?, bind));
        }
    }
    Ok((BuiltTx::new(inputs, outputs), next))
}

/// A wallet-side transfer of one pubkey-owned token UTXO into `new_states` (amounts must
/// conserve), signed with `secret`. `kas_change` gets whatever KAS is not in the token outputs.
pub fn build_transfer(
    token_id: Hash,
    input: &Spent,
    prev: &TokenState,
    new_states: &[TokenState],
    secret: &[u8; 32],
    token_out: u64,
    fee: u64,
    kas_change: Option<ScriptPublicKey>,
) -> Result<BuiltTx> {
    let bind = Some(CovenantBinding { authorizing_input: 0, covenant_id: token_id });
    let mut outputs: Vec<TransactionOutput> = new_states.iter().map(|s| token_redeem(s).map(|r| p2sh_output(token_out, &r, bind))).collect::<Result<_>>()?;
    let spent = token_out * new_states.len() as u64 + fee;
    if let Some(spk) = kas_change {
        let change = input.value.checked_sub(spent).ok_or("transfer: input value too small")?;
        if change > 0 {
            outputs.push(TransactionOutput { value: change, script_public_key: spk, covenant: None });
        }
    } else if input.value < spent {
        return Err("transfer: input value too small".into());
    }
    let unsigned = BuiltTx::new(vec![(input.clone(), vec![])], outputs.clone());
    let sig = unsigned.sign(0, secret)?;
    Ok(BuiltTx::new(vec![(input.clone(), token_transfer_sigscript(prev, new_states, &sig, 0)?)], outputs))
}

/// Script units -> the compute budget that covers them (ComputeBudget::checked_covering_script_units).
pub fn covering_budget(units: u64) -> u64 {
    units.saturating_sub(9_999).div_ceil(10_000)
}
