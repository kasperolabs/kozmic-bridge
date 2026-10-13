//! bridge-covenant: the Rust half of bin/bridge.mjs. Prints JSON on stdout.
//!
//! Common covenant args (every command): --image-id H --chain-commitment H --vault H(20 B)
//!   --max-fee N --header H --committee H [--cursor N (0)] [--token H (zero = not yet initialized)]
//!
//!   script                         redeem script for this state, token template numbers
//!   journal --bundle DIR           decode a bundle's journal (deposits included)
//!   token-script --owner H --owner-type N --amount N [--minter]
//!                                  redeem script + P2SH spk of one KCC20 state
//!   init    --covenant-id H --utxo TXID:IDX --value SOMPI --fee SOMPI --token-out SOMPI
//!   advance --covenant-id H --utxo TXID:IDX --value SOMPI --fee SOMPI --token-out SOMPI --bundle DIR
//!           [--minter-utxo TXID:IDX --minter-value SOMPI]     (required when the journal mints)
//!   transfer --token-id H --utxo TXID:IDX --value SOMPI --owner H --amount N --key HEX
//!           --to H --to-type N --to-amount N [--to2 H --to2-type N --to2-amount N]
//!           --token-out SOMPI --fee SOMPI [--change-spk HEX]
//!
//! init / advance / transfer build the complete v1 transaction (inputs with signature scripts,
//! outputs with covenant bindings) and run every input through the rusty-kaspa 2.1.0 engine
//! before printing, so the driver knows locally whether the node will accept it ("simulate.ok")
//! and how many script units each input needs. The tx is printed either way: the replay test
//! submits a failing spend on purpose. Compute budgets are not part of the v1 sighash, so the
//! driver may set them freely.

use bridge_covenant::*;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    if let Err(e) = run() {
        eprintln!("bridge-covenant: {e}");
        std::process::exit(1);
    }
}

type Args = HashMap<String, String>;

fn hexn<const N: usize>(args: &Args, k: &str) -> Result<[u8; N]> {
    let v = args.get(k).ok_or_else(|| format!("missing --{k}"))?;
    hex::decode(v.trim_start_matches("0x")).map_err(|e| format!("--{k}: {e}"))?.try_into().map_err(|_| format!("--{k} must be {N} bytes"))
}
fn hexn_or<const N: usize>(args: &Args, k: &str, default: [u8; N]) -> Result<[u8; N]> {
    if args.contains_key(k) { hexn(args, k) } else { Ok(default) }
}
fn num(args: &Args, k: &str) -> Result<u64> {
    args.get(k).ok_or_else(|| format!("missing --{k}"))?.parse().map_err(|e| format!("--{k}: {e}"))
}
fn num_or(args: &Args, k: &str, d: u64) -> Result<u64> {
    if args.contains_key(k) { num(args, k) } else { Ok(d) }
}
fn outpoint_arg(args: &Args, k: &str) -> Result<TransactionOutpoint> {
    let v = args.get(k).ok_or_else(|| format!("missing --{k}"))?;
    let (txid, idx) = v.split_once(':').ok_or_else(|| format!("--{k} must be TXID:INDEX"))?;
    let txid: [u8; 32] = hex::decode(txid).map_err(|e| format!("--{k}: {e}"))?.try_into().map_err(|_| format!("--{k}: txid must be 32 bytes"))?;
    Ok(outpoint(txid, idx.parse().map_err(|e| format!("--{k}: {e}"))?))
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn tx_json(t: &BuiltTx) -> Value {
    json!({
        "inputs": t.tx.inputs.iter().zip(&t.spent).map(|(i, s)| json!({
            "transactionId": i.previous_outpoint.transaction_id.to_string(),
            "index": i.previous_outpoint.index,
            "signatureScript": h(&i.signature_script),
            "amount": s.value.to_string(),
            "scriptPublicKey": h(s.spk.script()),
            "scriptVersion": s.spk.version(),
            "covenantId": s.covenant_id.map(|c| c.to_string()),
        })).collect::<Vec<_>>(),
        "outputs": t.tx.outputs.iter().map(|o| json!({
            "value": o.value.to_string(),
            "scriptPublicKey": h(o.script_public_key.script()),
            "scriptVersion": o.script_public_key.version(),
            "covenant": o.covenant.map(|c| json!({ "authorizingInput": c.authorizing_input, "covenantId": c.covenant_id.to_string() })),
        })).collect::<Vec<_>>(),
    })
}

fn simulate_json(t: &BuiltTx) -> Value {
    match t.execute_all() {
        Ok(units) => json!({
            "ok": true,
            "scriptUnits": units,
            "budgets": units.iter().map(|&u| covering_budget(u)).collect::<Vec<_>>(),
        }),
        Err((i, e)) => json!({ "ok": false, "input": i, "error": format!("{e:?}") }),
    }
}

fn state_json(s: &State) -> Value {
    json!({ "header": h(&s.header), "committee": h(&s.committee), "cursor": s.cursor, "token": h(&s.token) })
}

fn journal_json(j: &JournalView) -> Value {
    json!({
        "chainCommitment": h(&j.chain_commitment),
        "prevHeader": h(&j.prev_header), "prevCommittee": h(&j.prev_committee),
        "newHeader": h(&j.new_header), "newCommittee": h(&j.new_committee),
        "newSlot": j.new_slot, "execBlockNumber": j.exec_block_number,
        "vault": h(&j.vault),
        "deposits": j.deposits.iter().map(|d| json!({
            "nonce": d.nonce, "amount": d.amount, "version": d.version, "payload": h(&d.payload),
            "kaspaSpk": format!("{:02x}{}", d.version, h(&d.payload)),
        })).collect::<Vec<_>>(),
    })
}

fn token_state_arg(args: &Args, owner: &str, ty: &str, amount: &str, minter: bool) -> Result<TokenState> {
    Ok(TokenState { owner: hexn(args, owner)?, owner_type: num(args, ty)? as u8, amount: num(args, amount)?, is_minter: minter })
}

fn run() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().cloned().unwrap_or_default();
    let mut args = Args::new();
    let mut flags = std::collections::HashSet::new();
    let mut i = 1;
    while i < argv.len() {
        let k = argv[i].strip_prefix("--").ok_or_else(|| format!("unexpected argument {}", argv[i]))?.to_string();
        match argv.get(i + 1) {
            Some(v) if !v.starts_with("--") => {
                args.insert(k, v.clone());
                i += 2;
            }
            _ => {
                flags.insert(k);
                i += 1;
            }
        }
    }

    if cmd == "journal" {
        let b = load_bundle(&PathBuf::from(args.get("bundle").ok_or("missing --bundle")?))?;
        let j = parse_journal(&b.journal)?;
        println!("{}", json!({ "imageId": h(&b.image_id), "journalLen": b.journal.len(), "journalHash": h(&sha256(&b.journal)), "journal": journal_json(&j) }));
        return Ok(());
    }
    if cmd == "token-script" {
        let s = token_state_arg(&args, "owner", "owner-type", "amount", flags.contains("minter"))?;
        let r = token_redeem(&s)?;
        let t = token_template()?;
        println!("{}", json!({
            "redeem": h(&r), "redeemLen": r.len(),
            "scriptPublicKey": h(kaspa_txscript::pay_to_script_hash_script(&r).script()),
            "templateHash": h(&t.hash), "prefixLen": t.prefix.len(), "suffixLen": t.suffix.len(),
            "maxCovIns": TOKEN_MAX_COV_INS, "maxCovOuts": TOKEN_MAX_COV_OUTS,
        }));
        return Ok(());
    }
    if cmd == "transfer" {
        let token_id = Hash::from_bytes(hexn(&args, "token-id")?);
        let prev = token_state_arg(&args, "owner", "owner-type", "amount", false)?;
        let input = Spent::p2sh(outpoint_arg(&args, "utxo")?, num(&args, "value")?, &token_redeem(&prev)?, Some(token_id));
        let mut new_states = vec![token_state_arg(&args, "to", "to-type", "to-amount", false)?];
        if args.contains_key("to2") {
            new_states.push(token_state_arg(&args, "to2", "to2-type", "to2-amount", false)?);
        }
        let secret: [u8; 32] = hexn(&args, "key")?;
        let change = match args.get("change-spk") {
            Some(s) => Some(ScriptPublicKey::from_vec(0, hex::decode(s).map_err(|e| format!("--change-spk: {e}"))?)),
            None => None,
        };
        let t = build_transfer(token_id, &input, &prev, &new_states, &secret, num(&args, "token-out")?, num(&args, "fee")?, change)?;
        println!("{}", json!({ "tx": tx_json(&t), "simulate": simulate_json(&t) }));
        return Ok(());
    }

    let params = Params {
        image_id: hexn(&args, "image-id")?,
        chain_commitment: hexn(&args, "chain-commitment")?,
        vault: hexn(&args, "vault")?,
        max_fee: num(&args, "max-fee")? as i64,
    };
    let state = State { header: hexn(&args, "header")?, committee: hexn(&args, "committee")?, cursor: num_or(&args, "cursor", 0)?, token: hexn_or(&args, "token", [0; 32])? };
    let artifact = compile(&params, &state)?;
    let redeem = redeem_script(&artifact);
    let span = artifact.contracts.get(CONTRACT).unwrap().compiled.state_span;
    let t = token_template()?;

    match cmd.as_str() {
        "script" => {
            println!("{}", json!({
                "redeem": h(&redeem), "redeemLen": redeem.len(), "stateSpan": [span.offset, span.len],
                "tokenTemplateHash": h(&t.hash), "tokenPrefixLen": t.prefix.len(), "tokenSuffixLen": t.suffix.len(),
                "tokenMaxCovIns": TOKEN_MAX_COV_INS, "tokenMaxCovOuts": TOKEN_MAX_COV_OUTS, "maxDeposits": MAX_DEPOSITS,
            }));
        }
        "init" => {
            let cov = Hash::from_bytes(hexn(&args, "covenant-id")?);
            let bridge = Spent::p2sh(outpoint_arg(&args, "utxo")?, num(&args, "value")?, &redeem, Some(cov));
            let v = Values { fee: num(&args, "fee")?, token_out: num(&args, "token-out")? };
            let (tx, token_id, next) = build_init(&params, &state, &bridge, cov, &v)?;
            println!("{}", json!({
                "redeem": h(&redeem),
                "tokenId": token_id.to_string(),
                "minterRedeem": h(&token_redeem(&TokenState::minter_branch(cov.as_bytes()))?),
                "nextState": state_json(&next),
                "successorRedeem": h(&redeem_script(&compile(&params, &next)?)),
                "tx": tx_json(&tx),
                "simulate": simulate_json(&tx),
            }));
        }
        "advance" => {
            let cov = Hash::from_bytes(hexn(&args, "covenant-id")?);
            let b = load_bundle(&PathBuf::from(args.get("bundle").ok_or("missing --bundle")?))?;
            if b.image_id != params.image_id {
                return Err(format!("bundle image id {} differs from the covenant's {}", h(&b.image_id), h(&params.image_id)));
            }
            let j = parse_journal(&b.journal)?;
            let bridge = Spent::p2sh(outpoint_arg(&args, "utxo")?, num(&args, "value")?, &redeem, Some(cov));
            let minter = if args.contains_key("minter-utxo") {
                let r = token_redeem(&TokenState::minter_branch(cov.as_bytes()))?;
                Some(Spent::p2sh(outpoint_arg(&args, "minter-utxo")?, num(&args, "minter-value")?, &r, Some(Hash::from_bytes(state.token))))
            } else {
                None
            };
            let v = Values { fee: num(&args, "fee")?, token_out: num(&args, "token-out")? };
            let (mints, _) = j.mints(state.cursor);
            let matches_state = j.prev_header == state.header && j.prev_committee == state.committee && j.chain_commitment == params.chain_commitment && j.vault == params.vault;
            let (tx, next) = build_advance(&params, &state, &bridge, cov, minter.as_ref(), &b.journal, &b.proof, &v)?;
            println!("{}", json!({
                "redeem": h(&redeem),
                "journal": journal_json(&j),
                "journalMatchesState": matches_state,
                "mints": mints.iter().map(|d| json!({ "nonce": d.nonce, "amount": d.amount, "kaspaSpk": format!("{:02x}{}", d.version, h(&d.payload)),
                    "tokenRedeem": TokenState::for_deposit(d).and_then(|s| token_redeem(&s)).map(|r| h(&r)).unwrap_or_default() })).collect::<Vec<_>>(),
                "nextState": state_json(&next),
                "successorRedeem": h(&redeem_script(&compile(&params, &next)?)),
                "tx": tx_json(&tx),
                "simulate": simulate_json(&tx),
            }));
        }
        _ => return Err("usage: bridge-covenant script|journal|token-script|init|advance|transfer ... (see source header)".into()),
    }
    Ok(())
}
