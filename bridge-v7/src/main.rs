//! bridge-covenant-v7: the Rust half of bin/bridge-v5.mjs for USDC.k #1 (bridge-v7: the cell floor). Prints JSON on stdout.
//! `script` reports `covenantVersion: 7` and `cellValue`; the driver refuses a tool whose version is not the state file's.
//!
//! Common covenant args (every command): --image-id H --chain-commitment H --vault H(20 B)
//!   --eth-token H(20 B) --eth-token-impl H(20 B) --max-fee N --max-mint N (v5) --cell-value N (v7) --header H --committee H
//!   [--cursor N (0)] [--token H (zero = not yet initialized)] [--extension-commitment H (zeros)]
//!
//!   script                         redeem script for this state, family template numbers
//!   journal --bundle DIR           decode a bundle's journal (deposits with status)
//!   cell-script --owner H --owner-scheme N --amount N
//!                                  redeem script + P2SH spk of one reference cell
//!   authority-script --covenant-id H
//!                                  redeem script + P2SH spk of this bridge's BridgeMint authority
//!   init    --covenant-id H --utxo TXID:IDX --value SOMPI --fee SOMPI --token-out SOMPI
//!           [--prep-utxo TXID:IDX --prep-value SOMPI --prep-key HEX]   (KCC-23 metadata output, p2pk)
//!           --drip-period N --drip-divisor N --drip-min-prize SOMPI --drip-endowment SOMPI
//!                                  (v5: the MinerDrip as output 2, stamped with the family id this init creates)
//!   drip-script --token-id H --drip-period N --drip-divisor N --drip-min-prize SOMPI --drip-endowment SOMPI
//!                                  redeem script + P2SH spk of the drip for a token id
//!   drip-spend  --entry reveal|claim --token-id H --drip-... --utxo TXID:IDX --value SOMPI
//!                                  the one-input one-output spend (sequence 0 for reveal, period for claim), simulated
//!   advance --covenant-id H --utxo TXID:IDX --value SOMPI --fee SOMPI --token-out SOMPI --bundle DIR
//!           [--authority-utxo TXID:IDX --authority-value SOMPI]        (required when the journal mints)
//!   transfer --token-id H --utxo TXID:IDX --value SOMPI --owner H --amount N --key HEX
//!           --to H --to-scheme N --to-amount N [--to2 H --to2-scheme N --to2-amount N]
//!           --token-out SOMPI [--to2-kas SOMPI] --fee SOMPI [--change-spk HEX]
//!           [--fund-utxo TXID:IDX --fund-value SOMPI]   (U5: a p2pk UTXO of --key as input 1 pays the fee and the park)
//!           (a burn: --to <BURN_OWNER> --to-scheme 3)  [--payload HEX] (U4: the KZB1 burn payload, signed over)
//!
//! init / advance / transfer build the complete v1 transaction (inputs with signature scripts,
//! outputs with covenant bindings) and run every input through the rusty-kaspa 2.1.0 engine
//! before printing, so the driver knows locally whether the node will accept it ("simulate.ok")
//! and how many script units each input needs. The tx is printed either way: the replay test
//! submits a failing spend on purpose. Compute budgets are not part of the v1 sighash, so the
//! driver may set them freely.

use bridge_covenant_v7::*;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    if let Err(e) = run() {
        eprintln!("bridge-covenant-v7: {e}");
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
            "sequence": i.sequence,
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
        "sigscriptBytes": t.sigscript_bytes(),
        "payload": h(&t.tx.payload),
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
        "vault": h(&j.vault), "token": h(&j.token), "implementation": h(&j.implementation),
        "deposits": j.deposits.iter().map(|d| json!({
            "nonce": d.nonce, "amount": d.amount, "version": d.version, "payload": h(&d.payload),
            "kaspaSpk": format!("{:02x}{}", d.version, h(&d.payload)),
            "status": if d.status == STATUS_MINT { "mint" } else { "skip" },
        })).collect::<Vec<_>>(),
    })
}

fn drip_terms(args: &Args) -> Result<DripTerms> {
    Ok(DripTerms { period: num(args, "drip-period")?, divisor: num(args, "drip-divisor")?, min_prize: num(args, "drip-min-prize")?, endowment: num(args, "drip-endowment")? })
}
fn drip_terms_json(t: &DripTerms) -> Value {
    json!({ "period": t.period, "divisor": t.divisor, "minPrize": t.min_prize.to_string(), "endowment": t.endowment.to_string() })
}

fn cell_arg(args: &Args, owner: &str, scheme: &str, amount: &str, ext: [u8; 32]) -> Result<Cell> {
    Ok(Cell {
        amount: num(args, amount)?,
        owner: hexn(args, owner)?,
        owner_scheme: num(args, scheme)? as u8,
        borrow_scheme: BORROW_DISABLED,
        borrow_guard: [0; 32],
        extension_commitment: ext,
    })
}

fn run() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().cloned().unwrap_or_default();
    let mut args = Args::new();
    let mut i = 1;
    while i < argv.len() {
        let k = argv[i].strip_prefix("--").ok_or_else(|| format!("unexpected argument {}", argv[i]))?.to_string();
        match argv.get(i + 1) {
            Some(v) if !v.starts_with("--") => {
                args.insert(k, v.clone());
                i += 2;
            }
            _ => {
                args.insert(k, String::new());
                i += 1;
            }
        }
    }
    let ext: [u8; 32] = hexn_or(&args, "extension-commitment", [0; 32])?;
    let fam = family()?;

    if cmd == "journal" {
        let b = load_bundle(&PathBuf::from(args.get("bundle").ok_or("missing --bundle")?))?;
        let j = parse_journal(&b.journal)?;
        println!("{}", json!({ "imageId": h(&b.image_id), "journalLen": b.journal.len(), "journalHash": h(&sha256(&b.journal)), "journal": journal_json(&j) }));
        return Ok(());
    }
    if cmd == "cell-script" {
        let c = cell_arg(&args, "owner", "owner-scheme", "amount", ext)?;
        let r = cell_redeem(&c)?;
        println!("{}", json!({
            "redeem": h(&r), "redeemLen": r.len(),
            "scriptPublicKey": h(kaspa_txscript::pay_to_script_hash_script(&r).script()),
            "cellTemplate": h(&fam.cell_template), "prefixLen": fam.cell_prefix.len(), "suffixLen": fam.cell_suffix.len(),
            "burnOwner": h(&BURN_OWNER),
        }));
        return Ok(());
    }
    if cmd == "authority-script" {
        let cov = hexn::<32>(&args, "covenant-id")?;
        let r = authority_redeem(cov, ext)?;
        println!("{}", json!({
            "redeem": h(&r), "redeemLen": r.len(),
            "scriptPublicKey": h(kaspa_txscript::pay_to_script_hash_script(&r).script()),
            "authorityTemplate": h(&fam.authority_template), "cellTemplate": h(&fam.cell_template),
        }));
        return Ok(());
    }
    if cmd == "transfer" {
        let token_id = Hash::from_bytes(hexn(&args, "token-id")?);
        let prev = Cell::p2pk(num(&args, "amount")?, hexn(&args, "owner")?);
        let prev = Cell { extension_commitment: ext, ..prev };
        let input = Spent::p2sh(outpoint_arg(&args, "utxo")?, num(&args, "value")?, &cell_redeem(&prev)?, Some(token_id));
        let mut next = vec![cell_arg(&args, "to", "to-scheme", "to-amount", ext)?];
        if args.contains_key("to2") {
            next.push(cell_arg(&args, "to2", "to2-scheme", "to2-amount", ext)?);
        }
        let secret: [u8; 32] = hexn(&args, "key")?;
        let change = match args.get("change-spk") {
            Some(s) => Some(ScriptPublicKey::from_vec(0, hex::decode(s).map_err(|e| format!("--change-spk: {e}"))?)),
            None => None,
        };
        let payload = match args.get("payload") {
            Some(p) => hex::decode(p.trim_start_matches("0x")).map_err(|e| format!("--payload: {e}"))?,
            None => vec![],
        };
        // --token-out is every cell's KAS; --to2-kas gives the second cell its own value (a burn: the mass-optimal
        // park in the burn cell, the rest in the change cell)
        let mut kas = vec![num(&args, "token-out")?; next.len()];
        if args.contains_key("to2-kas") {
            if next.len() < 2 {
                return Err("--to2-kas needs --to2".into());
            }
            kas[1] = num(&args, "to2-kas")?;
        }
        let fund = if args.contains_key("fund-utxo") {
            Some(Spent::p2pk(outpoint_arg(&args, "fund-utxo")?, num(&args, "fund-value")?, &xonly_of(&secret)?))
        } else {
            None
        };
        let t = build_transfer_funded(token_id, &input, &prev, &next, &kas, &secret, num(&args, "fee")?, change, payload, fund.as_ref())?;
        println!("{}", json!({ "tx": tx_json(&t), "simulate": simulate_json(&t) }));
        return Ok(());
    }

    if cmd == "drip-script" || cmd == "drip-spend" {
        let t = drip_terms(&args)?;
        let token_id: [u8; 32] = hexn(&args, "token-id")?;
        let redeem = drip_redeem(&t, token_id)?;
        let spk = kaspa_txscript::pay_to_script_hash_script(&redeem);
        if cmd == "drip-script" {
            println!("{}", json!({ "redeem": h(&redeem), "redeemLen": redeem.len(), "scriptPublicKey": h(spk.script()), "terms": drip_terms_json(&t) }));
            return Ok(());
        }
        let entry = args.get("entry").cloned().unwrap_or_default();
        let coin = Spent { outpoint: outpoint_arg(&args, "utxo")?, value: num(&args, "value")?, spk: spk.clone(), covenant_id: None };
        let t_ = build_drip_spend(&t, token_id, &coin, &entry)?;
        println!("{}", json!({ "entry": entry, "redeem": h(&redeem), "scriptPublicKey": h(spk.script()), "keep": t_.tx.outputs[0].value.to_string(),
            "fee": (coin.value - t_.tx.outputs[0].value).to_string(), "sequence": t_.tx.inputs[0].sequence, "tx": tx_json(&t_), "simulate": simulate_json(&t_) }));
        return Ok(());
    }

    let params = Params {
        image_id: hexn(&args, "image-id")?,
        chain_commitment: hexn(&args, "chain-commitment")?,
        vault: hexn(&args, "vault")?,
        eth_token: hexn(&args, "eth-token")?,
        eth_token_impl: hexn(&args, "eth-token-impl")?,
        max_fee: num(&args, "max-fee")? as i64,
        max_mint: num(&args, "max-mint")?,
        cell_value: num(&args, "cell-value")?,
        extension_commitment: ext,
    };
    let state = State { header: hexn(&args, "header")?, committee: hexn(&args, "committee")?, cursor: num_or(&args, "cursor", 0)?, token: hexn_or(&args, "token", [0; 32])? };
    let artifact = compile(&params, &state)?;
    let redeem = redeem_script(&artifact);
    let span = artifact.contracts.get(CONTRACT).unwrap().compiled.state_span;

    match cmd.as_str() {
        "script" => {
            println!("{}", json!({
                "redeem": h(&redeem), "redeemLen": redeem.len(), "stateSpan": [span.offset, span.len],
                "cellTemplate": h(&fam.cell_template), "cellPrefixLen": fam.cell_prefix.len(), "cellSuffixLen": fam.cell_suffix.len(),
                "authorityTemplate": h(&fam.authority_template), "maxDeposits": MAX_DEPOSITS, "maxMint": params.max_mint,
                "covenantVersion": 7, "cellValue": params.cell_value, "maxFee": params.max_fee,
            }));
        }
        "init" => {
            let cov = Hash::from_bytes(hexn(&args, "covenant-id")?);
            let bridge = Spent::p2sh(outpoint_arg(&args, "utxo")?, num(&args, "value")?, &redeem, Some(cov));
            let v = Values { fee: num(&args, "fee")?, token_out: num(&args, "token-out")? };
            let prep = if args.contains_key("prep-utxo") {
                let secret: [u8; 32] = hexn(&args, "prep-key")?;
                Some(Prep { spent: Spent::p2pk(outpoint_arg(&args, "prep-utxo")?, num(&args, "prep-value")?, &xonly_of(&secret)?), secret })
            } else {
                None
            };
            let drip = if args.contains_key("drip-endowment") { Some(drip_terms(&args)?) } else { None };
            let (tx, token_id, next, info) = build_init_with_drip(&params, &state, &bridge, cov, prep.as_ref(), &v, drip.as_ref())?;
            println!("{}", json!({
                "redeem": h(&redeem),
                "tokenId": token_id.to_string(),
                "authorityRedeem": h(&authority_redeem(cov.as_bytes(), ext)?),
                "kcc23": prep.is_some(),
                "drip": info.map(|d| json!({ "redeem": h(&d.redeem), "redeemLen": d.redeem.len(), "scriptPublicKey": h(d.spk.script()), "endowment": d.terms.endowment.to_string(), "outputIndex": d.output_index, "terms": drip_terms_json(&d.terms) })),
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
            let authority = if args.contains_key("authority-utxo") {
                let r = authority_redeem(cov.as_bytes(), ext)?;
                Some(Spent::p2sh(outpoint_arg(&args, "authority-utxo")?, num(&args, "authority-value")?, &r, Some(Hash::from_bytes(state.token))))
            } else {
                None
            };
            let v = Values { fee: num(&args, "fee")?, token_out: num(&args, "token-out")? };
            let (mints, _) = j.mints(state.cursor);
            let matches_state = j.prev_header == state.header
                && j.prev_committee == state.committee
                && j.chain_commitment == params.chain_commitment
                && j.vault == params.vault
                && j.token == params.eth_token
                && j.implementation == params.eth_token_impl;
            let (tx, next) = build_advance(&params, &state, &bridge, cov, authority.as_ref(), &b.journal, &b.proof, &v)?;
            println!("{}", json!({
                "redeem": h(&redeem),
                "journal": journal_json(&j),
                "journalMatchesState": matches_state,
                "mints": mints.iter().map(|d| json!({ "nonce": d.nonce, "amount": d.amount, "kaspaSpk": format!("{:02x}{}", d.version, h(&d.payload)),
                    "cellRedeem": Cell::for_deposit(d, ext).and_then(|c| cell_redeem(&c)).map(|r| h(&r)).unwrap_or_default() })).collect::<Vec<_>>(),
                "nextState": state_json(&next),
                "successorRedeem": h(&redeem_script(&compile(&params, &next)?)),
                "tx": tx_json(&tx),
                "simulate": simulate_json(&tx),
            }));
        }
        _ => return Err("usage: bridge-covenant-v7 script|journal|cell-script|authority-script|drip-script|drip-spend|init|advance|transfer ... (see source header)".into()),
    }
    Ok(())
}
