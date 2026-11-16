//! bridge-v7 (sprint 7): the v6 suite with `cell_value` in every Params, `max_fee` read as the fee ceiling alone
//! (value_drain_beyond_max_fee_is_rejected), and three new cases at the end: the copier's advance with underfunded
//! cells refused, cells above the floor accepted, an init whose authority cell is below the floor refused.
//!
//! The BRIDGE covenant v4, the reference KCC-20 cell and BridgeMint run through rusty-kaspa 2.1.0's
//! script engine with the real mainnet proof of the U3 dev-test instance (eth-prover/out-u3-devtest:
//! nonce 1 from a clean depositor -> mint, nonce 2 from a blacklisted one -> skip) and the
//! consensus-spec fixture proof (out-fixture-gpu, a different image). The family's byte-level
//! vectors come from the Silverscript session's executed run (tests/fixtures/bridgemint-fixtures.json).
//! Run: cargo test --release -- --nocapture

use bridge_covenant_v7::*;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, TransactionOutput};
use kaspa_txscript::pay_to_script_hash_script;
use std::path::Path;

const DEPOSIT_BUNDLE: &str = "../eth-prover/out-u3-devtest";
const FIXTURE_BUNDLE: &str = "../eth-prover/out-fixture-gpu";
const FIXTURES: &str = include_str!("fixtures/bridgemint-fixtures.json");
const MAX_FEE: i64 = 200_000_000; // 2 KAS: v7, the fee ceiling alone (the cells' KAS is allowed on top, cell_value each)
const BRIDGE_VALUE: u64 = 1_000_000_000; // 10 KAS
const TOKEN_KAS: u64 = 20_000_000; // 0.2 KAS per cell
const CELL_VALUE: u64 = TOKEN_KAS; // v7: the floor; the suite mints cells at exactly the floor
const AUTH_KAS: u64 = 100_000_000; // 1 KAS parked in the authority
const FEE: u64 = 3_000_000;
const COV_C: Hash = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"); // the bridge
const COV_A: Hash = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // the token family
const VALUES: Values = Values { fee: FEE, token_out: TOKEN_KAS };
const ZERO32: [u8; 32] = [0; 32];
const MAX_MINT: u64 = 10_000_000_000; // v5: $10k, the vault's MAX_DEPOSIT
const DRIP_KAS: u64 = 100_000_000; // v5: the endowment of the genesis drip
const DRIP: DripTerms = DripTerms { period: 447_556, divisor: 20, min_prize: 1_000_000, endowment: DRIP_KAS };

fn deposit() -> (Params, Bundle, JournalView) {
    let b = load_bundle(Path::new(DEPOSIT_BUNDLE)).expect("dev-test bundle (eth-prover/out-u3-devtest)");
    let j = parse_journal(&b.journal).expect("journal");
    let p = Params {
        image_id: b.image_id,
        chain_commitment: j.chain_commitment,
        vault: j.vault,
        eth_token: j.token,
        eth_token_impl: j.implementation,
        max_fee: MAX_FEE,
        max_mint: MAX_MINT,
        cell_value: CELL_VALUE,
        extension_commitment: ZERO32,
    };
    (p, b, j)
}

/// The state the covenant is in right before the dev-test proof applies, token already initialized.
fn ready(j: &JournalView) -> State {
    State { header: j.prev_header, committee: j.prev_committee, cursor: 0, token: COV_A.as_bytes() }
}

fn bridge_utxo(p: &Params, s: &State) -> Spent {
    Spent::p2sh(outpoint([7; 32], 0), BRIDGE_VALUE, &redeem_script(&compile(p, s).unwrap()), Some(COV_C))
}

fn authority_utxo() -> Spent {
    Spent::p2sh(outpoint([8; 32], 1), AUTH_KAS, &authority_redeem(COV_C.as_bytes(), ZERO32).unwrap(), Some(COV_A))
}

fn mint_tx(p: &Params, s: &State, b: &Bundle) -> (BuiltTx, State) {
    build_advance(p, s, &bridge_utxo(p, s), COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &VALUES).expect("build advance")
}

fn cell_out(c: &Cell, auth: u16) -> TransactionOutput {
    p2sh_output(TOKEN_KAS, &cell_redeem(c).unwrap(), Some(CovenantBinding { authorizing_input: auth, covenant_id: COV_A }))
}

fn assert_rejected(t: &BuiltTx, what: &str) {
    match t.execute_all() {
        Ok(_) => panic!("{what}: accepted"),
        Err((i, e)) => println!("{what}: rejected at input {i}: {e:?}"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

#[test]
fn journal_of_the_devtest_decodes() {
    let (_, b, j) = deposit();
    assert_eq!(b.journal.len(), 370, "270 + 2 x 50");
    assert_eq!(hex::encode(j.vault), "ff48a7cb05a9f3c5813c4c026df633cd69faf9ce");
    assert_eq!(hex::encode(j.token), "d84747731c6ccea205f4a122cacc177604059f45");
    assert_eq!(hex::encode(j.implementation), "43506849d7c04f9138d1a2050bbf3a0c054402dd", "Circle's real implementation");
    assert_eq!(j.deposits.len(), 2);
    let (d1, d2) = (j.deposits[0], j.deposits[1]);
    assert_eq!((d1.nonce, d1.amount, d1.version, d1.status), (1, 25_000_000, 0, STATUS_MINT));
    assert_eq!((d2.nonce, d2.amount, d2.version, d2.status), (2, 40_000_000, 0, STATUS_SKIP));
    assert_eq!(d1.payload, [0x11; 32]);
    assert_eq!(j.exec_block_number, 26_204_731);
    let (mints, cursor) = j.mints(0);
    assert_eq!(mints.len(), 1, "only the clean deposit mints");
    assert_eq!(cursor, 2, "the cursor moves past the skipped one");
}

/// Our encoders against the Silverscript session's executed vectors: the two templates, the cell
/// splice, the authority window, the grouped-field mint arguments, the burn owner.
#[test]
fn family_matches_the_silverscript_fixtures() {
    let fx: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();
    let f = family().unwrap();
    assert_eq!(hex::encode(f.cell_template), fx["kcc20"]["template"].as_str().unwrap(), "reference cell template (Studio's kcc20-reference.json)");
    assert_eq!(hex::encode(&f.cell_prefix), fx["kcc20"]["prefix"].as_str().unwrap());
    assert_eq!(hex::encode(&f.cell_suffix), fx["kcc20"]["suffix"].as_str().unwrap());
    assert_eq!(hex::encode(f.authority_template), fx["bridge_mint"]["template"].as_str().unwrap(), "BridgeMint template");
    println!("cell template {} (prefix {} + suffix {} B), authority template {}", hex::encode(f.cell_template), f.cell_prefix.len(), f.cell_suffix.len(), hex::encode(f.authority_template));

    // the burn owner is BLAKE2b-256(6a): what pay_to_script_hash_script computes for the script [6a]
    let p2sh_of_return = pay_to_script_hash_script(&[0x6a]);
    assert_eq!(&p2sh_of_return.script()[2..34], &BURN_OWNER);
    assert_eq!(hex::encode(BURN_OWNER), fx["burn_owner_p2sh"].as_str().unwrap());

    // the four fixture recipients: splice == fixture redeem == compiler; spk as the fixture shows it
    let ex = &fx["mint_example"];
    let recipients: Vec<Cell> = ex["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| Cell {
            amount: r["amount"].as_u64().unwrap(),
            owner: unhex32(r["owner"].as_str().unwrap()),
            owner_scheme: r["owner_scheme"].as_u64().unwrap() as u8,
            borrow_scheme: r["borrow_scheme"].as_u64().unwrap() as u8,
            borrow_guard: unhex32(r["borrow_guard"].as_str().unwrap()),
            extension_commitment: unhex32(r["extension_commitment"].as_str().unwrap()),
        })
        .collect();
    assert_eq!(recipients.len(), 4);
    assert_eq!(recipients[2].owner, BURN_OWNER, "fixture recipient 3 is the burn owner");
    for (c, r) in recipients.iter().zip(ex["recipients"].as_array().unwrap()) {
        let red = cell_redeem(c).unwrap();
        assert_eq!(hex::encode(cell_window(f, c)), r["state_window"].as_str().unwrap());
        assert_eq!(hex::encode(&red), r["redeem"].as_str().unwrap());
        assert_eq!(hex::encode(pay_to_script_hash_script(&red).script()), r["spk"].as_str().unwrap());
        assert_eq!(red, cell_redeem_compiled(c).unwrap(), "splice == compiler");
    }

    // the authority's redeem for the fixture's constructor: prefix || window || suffix
    let ctor = &fx["bridge_mint"]["ctor"];
    let bridge_id = unhex32(ctor["bridge_covenant_id"].as_str().unwrap());
    let ext = unhex32(ctor["extension_commitment"].as_str().unwrap());
    let mut want = unhex(fx["bridge_mint"]["prefix"].as_str().unwrap());
    want.extend(unhex(fx["bridge_mint"]["state_window"].as_str().unwrap()));
    want.extend(unhex(fx["bridge_mint"]["suffix"].as_str().unwrap()));
    assert_eq!(authority_redeem(bridge_id, ext).unwrap(), want, "BridgeMint redeem");
    assert_eq!(want.len(), 1473);

    // the mint signature script, byte for byte (arguments + tag, then push(redeem))
    let sig = mint_sigscript(bridge_id, ext, &recipients).unwrap();
    assert_eq!(hex::encode(&sig), ex["sig_script"].as_str().unwrap(), "mint sigscript");
    let args_only = unhex(ex["args_only"].as_str().unwrap());
    assert_eq!(&sig[..args_only.len()], &args_only[..]);
    assert_eq!(hex::encode(retire_sigscript(bridge_id, ext).unwrap()), fx["retire_sig_script"].as_str().unwrap());
    println!("mint sigscript with 4 recipients: {} bytes", sig.len());
}

#[test]
fn compiles_and_reports_sizes() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let a = compile(&p, &s).unwrap();
    let redeem = redeem_script(&a);
    let span = a.contracts.get(CONTRACT).unwrap().compiled.state_span;
    let sig = advance_sigscript(&a, &b.journal, &b.proof).unwrap();
    println!("bridge v4 redeem {} bytes, state span {:?}, advance sigscript {} bytes (journal {} + proof {} + cell template {})",
        redeem.len(), span, sig.len(), b.journal.len(), b.proof.len(), family().unwrap().cell_suffix.len() + 1);
    // the verifier fragment's fixed VK must be inside the redeem script
    assert!(redeem.windows(8).any(|w| w == [0xe2, 0xf2, 0x6d, 0xbe, 0xa2, 0x99, 0xf5, 0x22]));
    // two states differ only inside the state span
    let other = redeem_script(&compile(&p, &j.next_state(&s)).unwrap());
    assert_eq!(redeem.len(), other.len());
    let diff: Vec<usize> = (0..redeem.len()).filter(|&i| redeem[i] != other[i]).collect();
    assert!(!diff.is_empty() && diff.iter().all(|&i| i >= span.offset && i < span.offset + span.len), "bytes outside the state span differ");
}

#[test]
fn init_creates_the_authority_from_a_fresh_genesis() {
    let (p, _b, j) = deposit();
    let genesis = State { token: ZERO32, ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let (t, token_id, next, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, None, &VALUES, Some(&DRIP)).unwrap();
    assert_eq!(t.genesis_covenant_id(0, &[1]), token_id);
    assert_eq!(next.token, token_id.as_bytes());
    assert_eq!(t.tx.outputs[1].script_public_key, pay_to_script_hash_script(&authority_redeem(COV_C.as_bytes(), ZERO32).unwrap()));
    let units = t.execute_all().expect("init must pass");
    println!("init: {} script units -> budget {}; family id {token_id}", units[0], covering_budget(units[0]));

    // a third output in the same genesis group (a second authority) is rejected
    let mut three = t.tx.clone();
    three.outputs.push(TransactionOutput {
        value: TOKEN_KAS,
        script_public_key: pay_to_script_hash_script(&authority_redeem([9; 32], ZERO32).unwrap()),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: token_id }),
    });
    let id3 = kaspa_consensus_core::hashing::covenant_id::covenant_id(three.inputs[0].previous_outpoint, [(1u32, &three.outputs[1]), (2u32, &three.outputs[2])].into_iter());
    for o in &mut three.outputs[1..] {
        o.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: id3 });
    }
    let next3 = State { token: id3.as_bytes(), ..genesis };
    three.outputs[0].script_public_key = pay_to_script_hash_script(&redeem_script(&compile(&p, &next3).unwrap()));
    assert_rejected(&BuiltTx { tx: three, spent: t.spent.clone() }, "init with two authorities");

    // an authority naming another bridge, with the family id and the successor recomputed for it, so
    // KIP-20 is satisfied and the bridge's own validateOutputStateWithTemplate is what rejects
    let mut other = t.tx.clone();
    other.outputs[1].script_public_key = pay_to_script_hash_script(&authority_redeem([9; 32], ZERO32).unwrap());
    let id9 = kaspa_consensus_core::hashing::covenant_id::covenant_id(other.inputs[0].previous_outpoint, [(1u32, &other.outputs[1])].into_iter());
    other.outputs[1].covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: id9 });
    other.outputs[0].script_public_key = pay_to_script_hash_script(&redeem_script(&compile(&p, &State { token: id9.as_bytes(), ..genesis }).unwrap()));
    assert_rejected(&BuiltTx { tx: other, spent: t.spent.clone() }, "init with an authority owned by another bridge");

    // init twice: the state already names a token
    assert!(build_init(&p, &next, &Spent::p2sh(outpoint([7; 32], 1), BRIDGE_VALUE, &redeem_script(&compile(&p, &next).unwrap()), Some(COV_C)), COV_C, None, &VALUES).is_err());
}

/// KCC-23 shape: the init spends the metadata preparation output as input 1, which authorizes the
/// authority genesis; the family id derives from the prep outpoint; the bridge script is unchanged.
#[test]
fn init_with_a_kcc23_preparation_input() {
    let (p, _b, j) = deposit();
    let genesis = State { token: ZERO32, ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let secret = [0x42; 32];
    let prep = Prep { spent: Spent::p2pk(outpoint([0xC2; 32], 0), 50_000_000, &xonly_of(&secret).unwrap()), secret };
    let (t, token_id, next, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, Some(&prep), &VALUES, Some(&DRIP)).unwrap();
    assert_eq!(t.tx.inputs.len(), 2);
    assert_eq!(t.tx.outputs.len(), 3, "v5: successor, authority, drip; the prep KAS pays the endowment");
    assert_eq!(t.tx.outputs[1].covenant.unwrap().authorizing_input, 1);
    assert_eq!(t.genesis_covenant_id(1, &[1]), token_id, "family id from the prep outpoint");
    assert_ne!(t.genesis_covenant_id(0, &[1]), token_id);
    assert_eq!(t.tx.outputs[0].value, BRIDGE_VALUE + 50_000_000 - FEE - TOKEN_KAS - DRIP_KAS);
    assert_eq!(next.token, token_id.as_bytes());
    let units = t.execute_all().expect("init with a prep input must pass");
    println!("init (KCC-23 shape): bridge {} units, prep input {} units; family id {token_id}", units[0], units[1]);
    // the prep input signed by someone else
    let bad = Prep { secret: [0x43; 32], ..prep.clone() };
    let (t2, _, _, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, Some(&bad), &VALUES, Some(&DRIP)).unwrap();
    assert_rejected(&t2, "prep input with the wrong key");
}

#[test]
fn advance_mints_the_clean_deposit_and_skips_the_blacklisted_one() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, next) = mint_tx(&p, &s, &b);
    assert_eq!(t.tx.inputs.len(), 2);
    assert_eq!(t.tx.outputs.len(), 3, "successor, authority, ONE recipient (nonce 2 is skipped)");
    assert_eq!(next.cursor, 2, "the cursor passes the skipped deposit");
    assert_eq!((next.header, next.committee), (j.new_header, j.new_committee));
    let units = t.execute_all().expect("genuine mint must pass");
    println!(
        "mint of nonce 1 with nonce 2 skipped: bridge input {} units (budget {}), authority input {} units (budget {}); sigscripts {} bytes",
        units[0], covering_budget(units[0]), units[1], covering_budget(units[1]), t.sigscript_bytes()
    );
    let want = cell_redeem(&Cell::p2pk(25_000_000, j.deposits[0].payload)).unwrap();
    assert_eq!(t.tx.outputs[2].script_public_key, pay_to_script_hash_script(&want));
    assert_eq!(t.tx.outputs[2].covenant.unwrap().covenant_id, COV_A);
    assert_eq!(t.tx.outputs[1].script_public_key, t.spent[1].spk, "the authority continues unchanged");
    assert_eq!(t.tx.outputs[1].value, AUTH_KAS);
}

#[test]
fn minting_the_skipped_deposit_anyway_is_rejected() {
    // The prover adds a recipient output for the blacklisted nonce 2 as if its status were 0.
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, _) = mint_tx(&p, &s, &b);
    let d2 = j.deposits[1];
    let extra = Cell::p2pk(d2.amount, d2.payload);
    let d1 = Cell::for_deposit(&j.deposits[0], ZERO32).unwrap();
    let mut tx = t.tx.clone();
    tx.outputs.push(cell_out(&extra, 1));
    tx.inputs[1].signature_script = mint_sigscript(COV_C.as_bytes(), ZERO32, &[d1, extra]).unwrap();
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "minting the blacklisted deposit");
}

#[test]
fn a_skipped_deposit_is_never_minted_later() {
    // After the mint the cursor is 2. A later proof that carried nonce 2 again (any status) is at
    // or below the cursor, so it cannot mint. Here: the same journal against cursor 2 is a heartbeat.
    let (p, b, j) = deposit();
    let after = j.next_state(&ready(&j));
    assert_eq!(after.cursor, 2);
    let s = State { header: j.prev_header, committee: j.prev_committee, cursor: 2, token: COV_A.as_bytes() };
    let bridge = bridge_utxo(&p, &s);
    let (hb, next) = build_advance(&p, &s, &bridge, COV_C, None, &b.journal, &b.proof, &VALUES).unwrap();
    assert_eq!(hb.tx.inputs.len(), 1);
    assert_eq!(next.cursor, 2);
    hb.execute_all().expect("heartbeat over processed deposits must pass");
}

#[test]
fn mint_to_the_wrong_recipient_or_amount_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, _) = mint_tx(&p, &s, &b);
    let d = j.deposits[0];
    let ok = Cell::p2pk(d.amount, d.payload);
    for (what, st) in [
        ("other owner", Cell { owner: [0xEE; 32], ..ok }),
        ("p2sh scheme for a p2pk recipient", Cell { owner_scheme: OWNER_P2SH, ..ok }),
        ("covenant-id scheme", Cell { owner_scheme: OWNER_COVENANT_ID, ..ok }),
        ("double amount", Cell { amount: 2 * d.amount, ..ok }),
        ("the skipped depositor's amount", Cell { amount: j.deposits[1].amount, ..ok }),
        ("borrow enabled", Cell { borrow_scheme: 0x01, ..ok }),
        ("other extension commitment", Cell { extension_commitment: [0xEE; 32], ..ok }),
    ] {
        let mut tx = t.tx.clone();
        tx.outputs[2].script_public_key = pay_to_script_hash_script(&cell_redeem(&st).unwrap());
        tx.inputs[1].signature_script = mint_sigscript(COV_C.as_bytes(), ZERO32, &[st]).unwrap();
        let bad = BuiltTx { tx, spent: t.spent.clone() };
        let err = bad.execute(0).unwrap_err();
        println!("mint with {what}: bridge input rejected: {err:?}");
    }
}

#[test]
fn mint_shape_must_be_exact() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, _) = mint_tx(&p, &s, &b);
    let mut tx = t.tx.clone();
    tx.outputs.remove(1);
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint without authority continuation");
    let mut tx = t.tx.clone();
    tx.outputs.push(tx.outputs[2].clone());
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint with an extra token output");
    let mut tx = t.tx.clone();
    tx.outputs[1].script_public_key = pay_to_script_hash_script(&authority_redeem([9; 32], ZERO32).unwrap());
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint handing the authority to another bridge");
    let mut tx = t.tx.clone();
    tx.outputs[1].value -= 1;
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint taking KAS out of the authority");
    let tx = BuiltTx::new(vec![(t.spent[0].clone(), t.tx.inputs[0].signature_script.clone())], vec![t.tx.outputs[0].clone()]);
    assert_rejected(&tx, "mint skipped");
}

/// BridgeMint's own rules beside the bridge's: the authority alone in the family, nothing else
/// created in the family, no family output hung on the bridge input (consensus refuses that one).
#[test]
fn authority_rules_hold_beside_the_bridge() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, _) = mint_tx(&p, &s, &b);
    // a holder's cell spent alongside the authority (the authority must be the only family input)
    let mut tx = t.tx.clone();
    let holder = Cell::p2pk(5, [0x55; 32]);
    tx.inputs.push(kaspa_consensus_core::tx::TransactionInput::new_with_compute_budget(outpoint([0x55; 32], 0), vec![], 0, 0));
    let mut spent = t.spent.clone();
    spent.push(Spent::p2sh(outpoint([0x55; 32], 0), TOKEN_KAS, &cell_redeem(&holder).unwrap(), Some(COV_A)));
    match (BuiltTx { tx, spent }).execute(1) {
        Ok(_) => panic!("authority accepted a token cell spent alongside"),
        Err(e) => println!("a token cell spent alongside the authority: authority input rejected: {e:?}"),
    }
    // a family output authorized by the bridge input instead of the authority
    let mut tx = t.tx.clone();
    tx.outputs.push(cell_out(&Cell::p2pk(1, [0x66; 32]), 0));
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "family output authorized by the bridge input");
    // the authority spent without any bridge input (a thief's mint)
    let thief = Cell::p2pk(1_000_000_000, [9; 32]);
    let a = authority_utxo();
    let outs = vec![
        TransactionOutput { value: a.value, script_public_key: a.spk.clone(), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
        cell_out(&thief, 0),
    ];
    let t2 = BuiltTx::new(vec![(a, mint_sigscript(COV_C.as_bytes(), ZERO32, &[thief]).unwrap())], outs);
    assert_rejected(&t2, "authority spent without a bridge input");
    // the authority spent beside some other covenant's input
    let other = Spent { outpoint: outpoint([0x77; 32], 0), value: 1_000, spk: ScriptPublicKey::from_vec(0, vec![0x51]), covenant_id: Some(Hash::from_bytes([0x77; 32])) };
    let a = authority_utxo();
    let outs = vec![
        TransactionOutput { value: a.value, script_public_key: a.spk.clone(), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
        cell_out(&thief, 0),
        TransactionOutput { value: 1_000, script_public_key: other.spk.clone(), covenant: Some(CovenantBinding { authorizing_input: 1, covenant_id: Hash::from_bytes([0x77; 32]) }) },
    ];
    let t3 = BuiltTx::new(vec![(a, mint_sigscript(COV_C.as_bytes(), ZERO32, &[thief]).unwrap()), (other, vec![])], outs);
    assert_rejected(&t3, "authority spent beside another covenant's input");
}

/// The proof names nothing beyond the cursor (heartbeat), and the spender brings the authority and a
/// recipient anyway. The bridge's heartbeat branch requires zero family inputs and outputs; BridgeMint
/// alone would accept (a bridge input is present). This is the "supply without a proof" hole, closed.
#[test]
fn heartbeat_cannot_carry_a_mint() {
    let (p, b, j) = deposit();
    let s = State { cursor: 2, ..ready(&j) };
    let bridge = bridge_utxo(&p, &s);
    let (hb, next) = build_advance(&p, &s, &bridge, COV_C, None, &b.journal, &b.proof, &VALUES).unwrap();
    assert_eq!(hb.tx.inputs.len(), 1, "the proof mints nothing from cursor 2");
    hb.execute_all().expect("plain heartbeat passes");
    let thief = Cell::p2pk(1_000_000_000, [9; 32]);
    let a = authority_utxo();
    let mut outputs = hb.tx.outputs.clone();
    outputs.push(TransactionOutput { value: a.value, script_public_key: a.spk.clone(), covenant: Some(CovenantBinding { authorizing_input: 1, covenant_id: COV_A }) });
    outputs.push(cell_out(&thief, 1));
    let bolted = BuiltTx::new(
        vec![(bridge.clone(), hb.tx.inputs[0].signature_script.clone()), (a, mint_sigscript(COV_C.as_bytes(), ZERO32, &[thief]).unwrap())],
        outputs,
    );
    assert!(bolted.execute(1).is_ok(), "BridgeMint alone accepts: a bridge input is present");
    match bolted.execute(0) {
        Ok(_) => panic!("heartbeat with a mint bolted on: bridge accepted"),
        Err(e) => println!("heartbeat with a mint bolted on: bridge input rejected: {e:?}"),
    }
    // the same with the successor's cursor left where the proof puts it (no state excuse): still rejected
    let _ = next;
}

#[test]
fn cursor_blocks_a_second_mint_of_the_same_deposit() {
    let (p, b, j) = deposit();
    // nonce 1 already minted, nonce 2 beyond the cursor but skipped: heartbeat shape, cursor -> 2
    let s = State { cursor: 1, ..ready(&j) };
    let bridge = bridge_utxo(&p, &s);
    let (hb, next) = build_advance(&p, &s, &bridge, COV_C, None, &b.journal, &b.proof, &VALUES).unwrap();
    assert_eq!(hb.tx.inputs.len(), 1);
    assert_eq!(next.cursor, 2);
    let units = hb.execute_all().expect("heartbeat over an already-minted deposit must pass");
    println!("heartbeat (nonce 1 minted, nonce 2 skipped): {} units (budget {})", units[0], covering_budget(units[0]));
    // trying to mint nonce 1 anyway: the mint shape built for cursor 0, submitted against cursor 1
    let (mint_at_0, _) = mint_tx(&p, &ready(&j), &b);
    let mut tx = mint_at_0.tx.clone();
    tx.inputs[0].signature_script = advance_sigscript(&compile(&p, &s).unwrap(), &b.journal, &b.proof).unwrap();
    tx.outputs[0].script_public_key = pay_to_script_hash_script(&redeem_script(&compile(&p, &next).unwrap()));
    let mut spent = mint_at_0.spent.clone();
    spent[0] = bridge;
    assert_rejected(&BuiltTx { tx, spent }, "second mint of nonce 1");
}

#[test]
fn replay_of_the_same_proof_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let after = j.next_state(&s);
    let bridge = bridge_utxo(&p, &after);
    let (t, _) = build_advance(&p, &after, &bridge, COV_C, None, &b.journal, &b.proof, &VALUES).unwrap();
    assert_rejected(&t, "replay after the mint");
}

#[test]
fn wrong_successor_state_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, next) = mint_tx(&p, &s, &b);
    for (what, bad) in [
        ("header", State { header: { let mut h = next.header; h[0] ^= 1; h }, ..next }),
        ("committee", State { committee: { let mut h = next.committee; h[5] ^= 1; h }, ..next }),
        ("cursor 0", State { cursor: 0, ..next }),
        ("cursor 1 (stopping before the skipped deposit)", State { cursor: 1, ..next }),
        ("cursor 3", State { cursor: 3, ..next }),
        ("token", State { token: [0x11; 32], ..next }),
        ("unchanged", s),
    ] {
        let mut tx = t.tx.clone();
        tx.outputs[0].script_public_key = pay_to_script_hash_script(&redeem_script(&compile(&p, &bad).unwrap()));
        assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, &format!("successor with wrong {what}"));
    }
}

#[test]
fn tampered_journal_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    // offsets: chain, prev header, prev committee, new header, new committee, vault, token, implementation,
    // count, nonce 1, amount 1, version 1, payload 1, status 1 (mint -> skip), status 2 (skip -> mint)
    for off in [0usize, 40, 70, 100, 130, 215, 240, 260, 269, 277, 285, 286, 300, 319, 369] {
        let mut jr = b.journal.clone();
        jr[off] ^= 0x01;
        let bridge = bridge_utxo(&p, &s);
        match build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &jr, &b.proof, &VALUES) {
            Ok((t, _)) => assert_rejected(&t, &format!("journal byte {off} flipped")),
            Err(e) => println!("journal byte {off} flipped: not even buildable ({e})"),
        }
    }
    // a status byte outside {0, 1} does not even parse
    let mut jr = b.journal.clone();
    jr[319] = 2;
    assert!(parse_journal(&jr).is_err());
}

#[test]
fn other_constants_are_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let mut cc = p.clone();
    cc.chain_commitment[31] ^= 1;
    assert_rejected(&mint_tx(&cc, &s, &b).0, "other chain commitment");
    let mut v = p.clone();
    v.vault[0] ^= 1;
    assert_rejected(&mint_tx(&v, &s, &b).0, "other vault");
    let mut tk = p.clone();
    tk.eth_token[19] ^= 1;
    assert_rejected(&mint_tx(&tk, &s, &b).0, "other ERC-20");
    let mut im = p.clone();
    im.eth_token_impl[0] ^= 1;
    assert_rejected(&mint_tx(&im, &s, &b).0, "other implementation (what a Circle upgrade looks like to the covenant)");
    // an authority built for another extension commitment beside this bridge (zeros): the bridge is
    // satisfied (its cells carry zeros), BridgeMint refuses cells whose commitment is not its own
    let (t, _) = mint_tx(&p, &s, &b);
    let ee = [0xEE; 32];
    let auth_ee = Spent::p2sh(outpoint([8; 32], 1), AUTH_KAS, &authority_redeem(COV_C.as_bytes(), ee).unwrap(), Some(COV_A));
    let mut tx = t.tx.clone();
    let cells = vec![Cell::for_deposit(&j.deposits[0], ZERO32).unwrap()];
    tx.inputs[1].signature_script = mint_sigscript(COV_C.as_bytes(), ee, &cells).unwrap();
    tx.outputs[1].script_public_key = auth_ee.spk.clone();
    let mut spent = t.spent.clone();
    spent[1] = auth_ee;
    let bad = BuiltTx { tx, spent };
    bad.execute(0).expect("the bridge accepts: its cells carry its own commitment and the authority continues unchanged");
    assert_rejected(&bad, "authority with another extension commitment (BridgeMint's check)");
    let fx = load_bundle(Path::new(FIXTURE_BUNDLE)).unwrap();
    let mut img = p.clone();
    img.image_id = fx.image_id;
    assert_rejected(&mint_tx(&img, &s, &b).0, "other image id");
    let bridge = bridge_utxo(&p, &s);
    match build_advance(&p, &s, &bridge, COV_C, None, &fx.journal, &fx.proof, &VALUES) {
        Ok((t, _)) => assert_rejected(&t, "fixture proof"),
        Err(e) => println!("fixture proof: not buildable ({e})"),
    }
}

/// v7: max_fee is the fee ceiling alone; the one minted cell's KAS (cell_value) is allowed on top of it.
#[test]
fn value_drain_beyond_max_fee_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let bridge = bridge_utxo(&p, &s);
    let exact = Values { fee: MAX_FEE as u64, token_out: CELL_VALUE };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &exact).unwrap();
    assert_eq!(t.tx.outputs[0].value, BRIDGE_VALUE - MAX_FEE as u64 - CELL_VALUE);
    t.execute_all().expect("a fee of exactly max_fee with the cell at the floor passes");
    let over = Values { fee: MAX_FEE as u64 + 1, token_out: CELL_VALUE };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &over).unwrap();
    assert_rejected(&t, "a fee of max_fee + 1 sompi");
    // the v6 split (fee max_fee - cell, cell at the floor) still passes: it loses less than v7 allows
    let v6_split = Values { fee: MAX_FEE as u64 - CELL_VALUE, token_out: CELL_VALUE };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &v6_split).unwrap();
    t.execute_all().expect("the v6 split passes on v7");
}

#[test]
fn wallet_transfer_spends_a_minted_cell() {
    let alice_sk = [0x51; 32];
    let alice = xonly_of(&alice_sk).unwrap();
    let bob = xonly_of(&[0x62; 32]).unwrap();
    let held = Cell::p2pk(1_000_000, alice);
    let utxo = Spent::p2sh(outpoint([3; 32], 2), 100_000_000, &cell_redeem(&held).unwrap(), Some(COV_A));
    let to_bob = Cell::p2pk(600_000, bob);
    let change = Cell::p2pk(400_000, alice);
    let kas_change = ScriptPublicKey::from_vec(0, vec![0x51]);
    let t = build_transfer(COV_A, &utxo, &held, &[to_bob, change], &alice_sk, TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    assert_eq!(t.tx.outputs.len(), 3);
    let units = t.execute_all().expect("wallet transfer must pass");
    println!("wallet transfer 1 -> 2: {} units (budget {}), sigscript {} bytes", units[0], covering_budget(units[0]), t.tx.inputs[0].signature_script.len());
    let t2 = build_transfer(COV_A, &utxo, &held, &[to_bob, change], &[0x77; 32], TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    assert_rejected(&t2, "transfer signed with the wrong key");
    let more = Cell { amount: 500_000, ..change };
    let t3 = build_transfer(COV_A, &utxo, &held, &[to_bob, more], &alice_sk, TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    assert_rejected(&t3, "transfer creating tokens");
    let t4 = build_transfer(COV_A, &utxo, &held, &[Cell { extension_commitment: [1; 32], ..held }], &alice_sk, TOKEN_KAS, FEE, Some(kas_change)).unwrap();
    assert_rejected(&t4, "transfer changing the extension commitment");
}

/// A burn is a transfer to the unspendable p2sh owner with borrow disabled. The cell is created like
/// any other and can never be spent: its owner check needs an input whose redeem script is `6a`.
#[test]
fn burn_cell_is_final() {
    let alice_sk = [0x51; 32];
    let alice = xonly_of(&alice_sk).unwrap();
    let held = Cell::p2pk(1_000_000, alice);
    let utxo = Spent::p2sh(outpoint([3; 32], 2), 100_000_000, &cell_redeem(&held).unwrap(), Some(COV_A));
    let burn = Cell::burn(250_000, ZERO32);
    let change = Cell::p2pk(750_000, alice);
    let kas_change = ScriptPublicKey::from_vec(0, vec![0x51]);
    let t = build_transfer(COV_A, &utxo, &held, &[burn, change], &alice_sk, TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    let units = t.execute_all().expect("burn transfer must pass");
    println!("burn of 250,000 with change: {} units; burn cell spk {}", units[0], hex::encode(t.tx.outputs[0].script_public_key.script()));
    // the burn cell's redeem is the reference cell with the burn owner: what U4's guest will read
    assert_eq!(t.tx.outputs[0].script_public_key, pay_to_script_hash_script(&cell_redeem(&burn).unwrap()));

    // trying to spend it: PATH_NORMAL with the p2sh witness (one byte: the index of an input whose
    // spk is p2sh(owner)). That input has to run the script `6a`, which is OP_RETURN.
    let burn_utxo = Spent::p2sh(outpoint([4; 32], 0), TOKEN_KAS, &cell_redeem(&burn).unwrap(), Some(COV_A));
    let proof_utxo = Spent::p2sh(outpoint([4; 32], 1), 1_000, &[0x6a], None);
    let taker = Cell::p2pk(250_000, [9; 32]);
    let outs = vec![cell_out(&taker, 0)];
    let sig = cell_transfer_sigscript(&burn, &[taker], &[PATH_NORMAL, 0x01]).unwrap();
    let steal = BuiltTx::new(vec![(burn_utxo.clone(), sig), (proof_utxo, push_data(&[0x6a]))], outs);
    match steal.execute(0) {
        Ok(u) => println!("burn cell's own script is satisfied by the p2sh witness ({u} units); the OP_RETURN input is what fails"),
        Err(e) => println!("burn cell's own script refused the p2sh witness: {e:?}"),
    }
    assert_rejected(&steal, "spending a burn cell");
    // the borrow path on it (same amount, so conservation holds and the scheme check is what decides)
    let sig = cell_transfer_sigscript(&burn, &[burn], &[0x01]).unwrap();
    let grow = BuiltTx::new(vec![(burn_utxo, sig)], vec![cell_out(&burn, 0)]);
    assert_rejected(&grow, "borrow path on a burn cell (borrow disabled)");
}

/// U4: a burn carrying the KZB1 payload the relay guest reads. The v1 sighash covers the payload, so the holder's
/// signature binds it: the same transaction with another payload (another recipient, say) is refused. Without
/// this, anyone could swap the Ethereum recipient of a burn in the mempool.
#[test]
fn burn_with_payload_is_signed() {
    let alice_sk = [0x51; 32];
    let alice = xonly_of(&alice_sk).unwrap();
    let held = Cell::p2pk(1_000_000, alice);
    let utxo = Spent::p2sh(outpoint([3; 32], 2), 100_000_000, &cell_redeem(&held).unwrap(), Some(COV_A));
    let burn = Cell::burn(250_000, ZERO32);
    let change = Cell::p2pk(750_000, alice);
    let kas_change = ScriptPublicKey::from_vec(0, vec![0x51]);
    let mut payload = b"KZB1".to_vec();
    payload.push(2);
    payload.extend([0xcd; 20]);
    payload.extend(10_000u64.to_be_bytes());
    payload.extend([0xab; 20]);
    let t = build_transfer_with_payload(COV_A, &utxo, &held, &[burn, change], &alice_sk, TOKEN_KAS, FEE, Some(kas_change), payload.clone()).unwrap();
    assert_eq!(t.tx.payload, payload);
    let units = t.execute_all().expect("burn with payload must pass");
    println!("burn with KZB1 payload: {} units (budget {}), sigscript {} bytes, tx id {}", units[0], covering_budget(units[0]), t.tx.inputs[0].signature_script.len(), t.tx.id());
    let mut other = payload.clone();
    other[52] ^= 1;
    let swapped = BuiltTx::with_payload(vec![(utxo.clone(), t.tx.inputs[0].signature_script.clone())], t.tx.outputs.clone(), other);
    assert_rejected(&swapped, "burn payload changed after signing");
}

/// U5: a transfer funded by a plain p2pk UTXO of the same key (input 1). The cells take their own KAS, the fee and
/// the park come from the funding input, the remainder returns as KAS change, so the holder's cell is not drained.
/// The cell's witness signs over every input, so a funding input swapped after signing is refused; a funding input
/// that belongs to another key cannot be signed by the holder.
#[test]
fn transfer_with_a_kas_funding_input() {
    let alice_sk = [0x51; 32];
    let alice = xonly_of(&alice_sk).unwrap();
    let held = Cell::p2pk(1_000_000, alice);
    let utxo = Spent::p2sh(outpoint([3; 32], 2), 30_000_000, &cell_redeem(&held).unwrap(), Some(COV_A));
    let fund = Spent::p2pk(outpoint([0xF1; 32], 0), 300_000_000, &alice);
    let burn = Cell::burn(250_000, ZERO32);
    let change = Cell::p2pk(750_000, alice);
    let kas_change = p2pk_spk(&alice);
    let kas = [20_000_000u64, 30_000_000];
    let mut payload = b"KZB1".to_vec();
    payload.push(2);
    payload.extend([0xcd; 20]);
    payload.extend(10_000u64.to_be_bytes());
    payload.extend([0xab; 20]);
    let t = build_transfer_funded(COV_A, &utxo, &held, &[burn, change], &kas, &alice_sk, FEE, Some(kas_change.clone()), payload.clone(), Some(&fund)).unwrap();
    assert_eq!(t.tx.inputs.len(), 2);
    assert_eq!(t.tx.outputs.len(), 3, "burn cell, change cell, KAS change");
    assert_eq!(t.tx.outputs[0].value, 20_000_000, "the burn cell parks the given value");
    assert_eq!(t.tx.outputs[1].value, 30_000_000, "the change cell keeps the cell's KAS");
    assert_eq!(t.tx.outputs[2].value, 30_000_000 + 300_000_000 - 50_000_000 - FEE, "the funding input pays the park and the fee");
    assert_eq!(t.tx.outputs[2].script_public_key, kas_change);
    assert_eq!(t.tx.payload, payload);
    let units = t.execute_all().expect("funded burn must pass");
    println!(
        "funded burn: cell input {} units (budget {}), funding input {} units (budget {}); sigscripts {} bytes",
        units[0], covering_budget(units[0]), units[1], covering_budget(units[1]), t.sigscript_bytes()
    );
    // the funding input swapped for another UTXO of the same key after signing: both signatures stop matching
    let other = Spent::p2pk(outpoint([0xF2; 32], 0), 300_000_000, &alice);
    let swapped = BuiltTx::with_payload(
        vec![(utxo.clone(), t.tx.inputs[0].signature_script.clone()), (other, t.tx.inputs[1].signature_script.clone())],
        t.tx.outputs.clone(),
        payload.clone(),
    );
    assert_rejected(&swapped, "funding input swapped after signing");
    // a funding input of another key, signed by the holder
    let bob_fund = Spent::p2pk(outpoint([0xF3; 32], 0), 300_000_000, &xonly_of(&[0x62; 32]).unwrap());
    let t2 = build_transfer_funded(COV_A, &utxo, &held, &[burn, change], &kas, &alice_sk, FEE, Some(kas_change), payload, Some(&bob_fund)).unwrap();
    assert_rejected(&t2, "funding input owned by another key");
    // without a funding input the same shape must be paid from the cell: 30 KAS is not enough for 50 + fee
    assert!(build_transfer_funded(COV_A, &utxo, &held, &[burn, change], &kas, &alice_sk, FEE, Some(p2pk_spk(&alice)), vec![], None).is_err());
}

/// F5 (REVIEW-2026-11-02, bridge-v6): every nonce above the cursor must be consecutive, so nobody can skip a
/// deposit. Needs a real proof whose journal starts above nonce 1: set F5_BUNDLE to a bundle directory (a Sepia.k
/// advance that minted deposit 2 on its own does); the case skips with a note otherwise.
#[test]
fn skipping_a_nonce_is_rejected() {
    let Ok(dir) = std::env::var("F5_BUNDLE") else {
        println!("skipping_a_nonce_is_rejected: set F5_BUNDLE to a bundle whose first deposit nonce is above 1");
        return;
    };
    let b = load_bundle(Path::new(&dir)).expect("F5 bundle");
    let j = parse_journal(&b.journal).expect("journal");
    let first = j.deposits.first().expect("a deposit").nonce;
    assert!(first > 1, "the bundle's first deposit must be above nonce 1 (it is {first})");
    let p = Params {
        image_id: b.image_id,
        chain_commitment: j.chain_commitment,
        vault: j.vault,
        eth_token: j.token,
        eth_token_impl: j.implementation,
        max_fee: MAX_FEE,
        max_mint: MAX_MINT,
        cell_value: CELL_VALUE,
        extension_commitment: ZERO32,
    };
    // at cursor first - 1 the journal is consecutive: it builds and passes
    let ok_state = State { header: j.prev_header, committee: j.prev_committee, cursor: first - 1, token: COV_A.as_bytes() };
    let bridge_ok = bridge_utxo(&p, &ok_state);
    let (t, next) = build_advance(&p, &ok_state, &bridge_ok, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &VALUES).expect("build at the consecutive cursor");
    let units = t.execute_all().expect("a consecutive nonce passes");
    println!("consecutive (cursor {} -> nonce {first}): {} units (budget {})", first - 1, units[0], covering_budget(units[0]));
    assert_eq!(next.cursor, j.deposits.last().unwrap().nonce);
    // at cursor first - 2 the journal skips a deposit: refused
    let gap = State { header: j.prev_header, committee: j.prev_committee, cursor: first - 2, token: COV_A.as_bytes() };
    let bridge_gap = bridge_utxo(&p, &gap);
    match build_advance(&p, &gap, &bridge_gap, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &VALUES) {
        Ok((t2, _)) => assert_rejected(&t2, &format!("a journal that skips nonce {} (cursor {})", first - 1, first - 2)),
        Err(e) => println!("a journal that skips a nonce: not even buildable ({e})"),
    }
}

// ---------------------------------------------------------------------------
// v7: the cell floor (the gap found in kUSDT's code on 11-14; bridge-v6/tests/underfunded.rs shows v6 accepting it)

/// The copier's transaction (bridge-v6/tests/underfunded.rs, the same shape): the honest proof and journal, the
/// cells at 1,000 sompi, the successor at `input - max_fee`, the rest in the copier's own output. v7 refuses it at
/// the bridge input, and refuses the floor alone too (cells at cell_value - 1 with nothing drained).
#[test]
fn underfunded_cells_are_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let bridge = bridge_utxo(&p, &s);
    let (mints, _) = j.mints(s.cursor);
    let cells_kas = 1_000 * mints.len() as u64;
    // the copier: cells at 1,000 sompi, the successor keeps input - max_fee (v6 would accept this)
    let copy = Values { fee: MAX_FEE as u64 - cells_kas, token_out: 1_000 };
    let (mut t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &copy).unwrap();
    assert_eq!(t.tx.outputs[0].value, BRIDGE_VALUE - MAX_FEE as u64);
    let copier = xonly_of(&[0xC0; 32]).unwrap();
    t.tx.outputs.push(TransactionOutput { value: MAX_FEE as u64 - cells_kas - FEE, script_public_key: p2pk_spk(&copier), covenant: None });
    assert_rejected(&t, "the copier's advance (cells at 1,000 sompi, the rest of max_fee to the copier)");
    // the floor alone: one sompi short, nothing drained beyond the honest fee
    let short = Values { fee: FEE, token_out: CELL_VALUE - 1 };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &short).unwrap();
    assert_rejected(&t, "a minted cell one sompi below cell_value");
    // the successor drained by max_fee + cell_value while the cell is empty-ish: both rules fail; the engine stops at the first
    let both = Values { fee: MAX_FEE as u64 + CELL_VALUE - 1_000, token_out: 1_000 };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &both).unwrap();
    assert_rejected(&t, "the successor at input - max_fee - cell_value with the cell at 1,000 sompi");
}

/// Cells above the floor pass; the successor may lose max_fee plus exactly one cell_value per mint, not more.
#[test]
fn cells_above_the_floor_pass() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let bridge = bridge_utxo(&p, &s);
    let rich = Values { fee: FEE, token_out: CELL_VALUE * 3 };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &rich).unwrap();
    let units = t.execute_all().expect("a cell above the floor passes");
    println!("cell at 3 x cell_value: {} units (budget {})", units[0], covering_budget(units[0]));
    // the allowance is cell_value per mint, whatever the cell really carries: a rich cell plus a fee of max_fee drains
    // more than input - max_fee - cell_value and is refused
    let rich_and_max = Values { fee: MAX_FEE as u64, token_out: CELL_VALUE * 3 };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &rich_and_max).unwrap();
    assert_rejected(&t, "a rich cell paid for out of the max_fee allowance");
}

/// init: the authority's cell (output 1) must carry at least cell_value, prep or no prep.
#[test]
fn init_authority_below_the_floor_is_rejected() {
    let (p, _b, j) = deposit();
    let genesis = State { token: ZERO32, ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let low = Values { fee: FEE, token_out: CELL_VALUE - 1 };
    let (t, _, _, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, None, &low, Some(&DRIP)).unwrap();
    assert_eq!(t.tx.outputs[1].value, CELL_VALUE - 1);
    assert_rejected(&t, "init with the authority's cell one sompi below cell_value");
    // at the floor it passes (the suite's init tests run at exactly the floor too)
    let (t, _, _, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, None, &VALUES, Some(&DRIP)).unwrap();
    t.execute_all().expect("init with the authority at the floor passes");
    // the drain rule at init: the successor may lose max_fee + cell_value (no prep: the endowment comes out of the bridge too)
    let drain = Values { fee: MAX_FEE as u64 - DRIP_KAS, token_out: CELL_VALUE };
    let (t, _, _, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, None, &drain, Some(&DRIP)).unwrap();
    assert_eq!(t.tx.outputs[0].value, BRIDGE_VALUE - MAX_FEE as u64 - CELL_VALUE);
    t.execute_all().expect("init losing exactly max_fee + cell_value passes");
    let over = Values { fee: MAX_FEE as u64 - DRIP_KAS + 1, token_out: CELL_VALUE };
    let (t, _, _, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, None, &over, Some(&DRIP)).unwrap();
    assert_rejected(&t, "init losing max_fee + cell_value + 1");
}
