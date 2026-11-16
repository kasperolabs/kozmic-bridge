//! Tipsy.k (REHEARSAL-2-PLAN section 4): the v5 additions through rusty-kaspa 2.1.0's script engine, with the
//! same real proof the v4 suite uses (eth-prover/out-u3-devtest: nonce 1 mints 25 units, nonce 2 is skipped).
//!   - max_mint: an entry at the maximum accepted, one above rejected, a skipped entry above it still advances;
//!   - init with the MinerDrip output: accepted; a bound output 2, a second family output, a fourth output rejected;
//!   - the drip script: the claim guard and the reveal entry at the expected bytes, the token id stamped in;
//!   - the Studio's eight MinerDrip cases rerun against the drip compiled with Tipsy.k's terms and this family id.
//! Run: cargo test --release --test tipsy -- --nocapture

use bridge_covenant_v7::*;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, TransactionOutput};
use kaspa_txscript::pay_to_script_hash_script;
use std::path::Path;

const DEPOSIT_BUNDLE: &str = "../eth-prover/out-u3-devtest";
const MAX_FEE: i64 = 200_000_000;
const BRIDGE_VALUE: u64 = 1_000_000_000;
const TOKEN_KAS: u64 = 20_000_000;
const AUTH_KAS: u64 = 100_000_000;
const FEE: u64 = 3_000_000;
const COV_C: Hash = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const COV_A: Hash = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
const VALUES: Values = Values { fee: FEE, token_out: TOKEN_KAS };
const ZERO32: [u8; 32] = [0; 32];
/// Tipsy.k's terms (minerdrip.js schedule(1 KAS, 0.05 KAS, 7 days)): a claim every ~12.4 h, floor 0.01 KAS
const TIPSY: DripTerms = DripTerms { period: 447_556, divisor: 20, min_prize: 1_000_000, endowment: 100_000_000 };

fn deposit(max_mint: u64) -> (Params, Bundle, JournalView) {
    let b = load_bundle(Path::new(DEPOSIT_BUNDLE)).expect("dev-test bundle (eth-prover/out-u3-devtest)");
    let j = parse_journal(&b.journal).expect("journal");
    let p = Params {
        image_id: b.image_id,
        chain_commitment: j.chain_commitment,
        vault: j.vault,
        eth_token: j.token,
        eth_token_impl: j.implementation,
        max_fee: MAX_FEE,
        max_mint,
        cell_value: TOKEN_KAS, // v7: the suite's cells sit exactly at the floor
        extension_commitment: ZERO32,
    };
    (p, b, j)
}

fn ready(j: &JournalView) -> State {
    State { header: j.prev_header, committee: j.prev_committee, cursor: 0, token: COV_A.as_bytes() }
}
fn bridge_utxo(p: &Params, s: &State) -> Spent {
    Spent::p2sh(outpoint([7; 32], 0), BRIDGE_VALUE, &redeem_script(&compile(p, s).unwrap()), Some(COV_C))
}
fn authority_utxo() -> Spent {
    Spent::p2sh(outpoint([8; 32], 1), AUTH_KAS, &authority_redeem(COV_C.as_bytes(), ZERO32).unwrap(), Some(COV_A))
}
fn assert_rejected(t: &BuiltTx, what: &str) {
    match t.execute_all() {
        Ok(_) => panic!("{what}: accepted"),
        Err((i, e)) => println!("{what}: rejected at input {i}: {e:?}"),
    }
}

// ---------------------------------------------------------------- max_mint

#[test]
fn max_mint_boundary() {
    // nonce 1 mints 25,000,000 units; nonce 2 (40,000,000) is skipped by the guest
    let (p, b, j) = deposit(25_000_000);
    let s = ready(&j);
    let (t, next) = build_advance(&p, &s, &bridge_utxo(&p, &s), COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &VALUES).unwrap();
    let units = t.execute_all().expect("an entry exactly at max_mint mints");
    assert_eq!(next.cursor, 2);
    println!("mint at max_mint: {} units (budget {})", units[0], covering_budget(units[0]));

    let (p1, b, j) = deposit(24_999_999);
    let (t1, _) = build_advance(&p1, &s, &bridge_utxo(&p1, &s), COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &VALUES).unwrap();
    assert_rejected(&t1, "an entry one unit above max_mint");

    // the skipped entry (40,000,000) is above a max_mint of 30,000,000 and is not compared: the cursor passes it
    let (p2, b, j2) = deposit(30_000_000);
    let (t2, next2) = build_advance(&p2, &s, &bridge_utxo(&p2, &s), COV_C, Some(&authority_utxo()), &b.journal, &b.proof, &VALUES).unwrap();
    t2.execute_all().expect("a skipped entry above max_mint still advances");
    assert_eq!(next2.cursor, 2, "past the skipped deposit");
    let _ = (j, j2);
}

#[test]
fn max_mint_is_a_constructor_constant() {
    // two max_mint values give two different redeem scripts of the same length (the constant lives in the script)
    let (p, _, j) = deposit(10_000_000_000);
    let (q, _, _) = deposit(10_000_000_001);
    let s = ready(&j);
    let a = redeem_script(&compile(&p, &s).unwrap());
    let b = redeem_script(&compile(&q, &s).unwrap());
    assert_eq!(a.len(), b.len());
    assert_ne!(a, b);
}

// ---------------------------------------------------------------- init with the drip

#[test]
fn init_with_the_drip_output_is_accepted() {
    let (p, _b, j) = deposit(10_000_000_000);
    let genesis = State { token: ZERO32, ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let secret = [0x42; 32];
    let prep = Prep { spent: Spent::p2pk(outpoint([0xC2; 32], 0), 250_000_000, &xonly_of(&secret).unwrap()), secret };
    let (t, token_id, next, drip) = build_init_with_drip(&p, &genesis, &bridge, COV_C, Some(&prep), &VALUES, Some(&TIPSY)).unwrap();
    let drip = drip.expect("drip info");
    assert_eq!(t.tx.outputs.len(), 3, "successor, authority, drip");
    assert_eq!(t.tx.outputs[2].value, TIPSY.endowment);
    assert!(t.tx.outputs[2].covenant.is_none(), "the drip output is unbound");
    assert_eq!(t.tx.outputs[2].script_public_key, drip.spk);
    assert_eq!(t.tx.outputs[0].value, BRIDGE_VALUE + 250_000_000 - FEE - TOKEN_KAS - TIPSY.endowment, "the endowment comes from the prep KAS");
    assert_eq!(t.genesis_covenant_id(1, &[1]), token_id, "family id from the prep outpoint and output 1 only");
    assert_eq!(drip.token_id, token_id);
    assert_eq!(next.token, token_id.as_bytes());
    let units = t.execute_all().expect("init with the drip must pass");
    println!("init v5 (drip): bridge {} units (budget {}), prep {} units; family id {token_id}; drip {} B at {}", units[0], covering_budget(units[0]), units[1], drip.redeem.len(), hex::encode(drip.spk.script()));

    // the family id does not depend on the drip: the same init with other terms names the same token
    let other = DripTerms { endowment: 150_000_000, ..TIPSY };
    let (_, id2, _, _) = build_init_with_drip(&p, &genesis, &bridge, COV_C, Some(&prep), &VALUES, Some(&other)).unwrap();
    assert_eq!(id2, token_id);

    // without the drip (two outputs) the v5 bridge refuses
    let (two, _, _) = build_init(&p, &genesis, &bridge, COV_C, Some(&prep), &VALUES).unwrap();
    assert_eq!(two.tx.outputs.len(), 2);
    assert_rejected(&two, "init with two outputs (no drip)");

    // output 2 bound to the bridge's own group
    let mut tx = t.tx.clone();
    tx.outputs[2].covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_C });
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "init with output 2 bound to the bridge");

    // output 2 a second member of the token family (a second authority): the id is recomputed over outputs 1 and 2,
    // and the successor for it, so KIP-20 holds and the bridge's `OpOutputCovenantId(2) == ZERO32` is what rejects
    // (OpCovOutputCount cannot count genesis outputs: the engine keeps them out of the covenant contexts)
    let mut tx = t.tx.clone();
    tx.outputs[2] = TransactionOutput { value: TOKEN_KAS, script_public_key: tx.outputs[1].script_public_key.clone(), covenant: None };
    let id3 = kaspa_consensus_core::hashing::covenant_id::covenant_id(tx.inputs[1].previous_outpoint, [(1u32, &tx.outputs[1]), (2u32, &tx.outputs[2])].into_iter());
    for o in &mut tx.outputs[1..] {
        o.covenant = Some(CovenantBinding { authorizing_input: 1, covenant_id: id3 });
    }
    tx.outputs[0].script_public_key = pay_to_script_hash_script(&redeem_script(&compile(&p, &State { token: id3.as_bytes(), ..genesis }).unwrap()));
    let unsigned = BuiltTx { tx: tx.clone(), spent: t.spent.clone() };
    tx.inputs[1].signature_script = push_data(&unsigned.sign(1, &secret).unwrap());
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "init with two family outputs");

    // a fourth output (unbound)
    let mut tx = t.tx.clone();
    tx.outputs.push(TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::from_vec(0, vec![0x51]), covenant: None });
    tx.outputs[0].value -= 1_000_000;
    let unsigned = BuiltTx { tx: tx.clone(), spent: t.spent.clone() };
    tx.inputs[1].signature_script = push_data(&unsigned.sign(1, &secret).unwrap());
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "init with four outputs");

    // the drip output rebound after signing (another drip script): the prep signature no longer matches
    let mut tx = t.tx.clone();
    tx.outputs[2].script_public_key = ScriptPublicKey::from_vec(0, vec![0x51]);
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "drip output changed after signing");
}

#[test]
fn init_with_the_drip_and_no_prep_input() {
    // the authority authorized by the bridge input (no KCC-23 prep): still three outputs, the endowment from the pool
    let (p, _b, j) = deposit(10_000_000_000);
    let genesis = State { token: ZERO32, ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let (t, token_id, _, drip) = build_init_with_drip(&p, &genesis, &bridge, COV_C, None, &VALUES, Some(&TIPSY)).unwrap();
    assert_eq!(t.tx.outputs.len(), 3);
    assert_eq!(t.genesis_covenant_id(0, &[1]), token_id);
    assert_eq!(drip.unwrap().token_id, token_id);
    t.execute_all().expect("init (no prep) with the drip must pass");
}

// ---------------------------------------------------------------- the drip itself

#[test]
fn drip_script_shape_and_stamp() {
    let redeem = drip_redeem(&TIPSY, COV_A.as_bytes()).unwrap();
    let hex = hex::encode(&redeem);
    assert!((180..=200).contains(&redeem.len()), "a MinerDrip is about 190 bytes (the int pushes vary with the terms): {}", redeem.len());
    assert!(hex.starts_with("760426aa3fc0"), "claim guard at the start: {}", &hex[..16]);
    assert!(hex.contains("04fcffbcc1"), "reveal entry");
    assert!(hex.contains(&hex::encode(COV_A.as_bytes())), "the token id is stamped into the script");
    // the sigscripts: tag then push(redeem), as minerdrip.js builds them
    let claim = drip_sigscript(&TIPSY, COV_A.as_bytes(), ENTRY_CLAIM).unwrap();
    let reveal = drip_sigscript(&TIPSY, COV_A.as_bytes(), ENTRY_REVEAL).unwrap();
    assert_eq!(hex::encode(&claim[..5]), "0426aa3fc0");
    assert_eq!(hex::encode(&reveal[..5]), "04fcffbcc1");
    assert_eq!(&claim[5..], &push_data(&redeem)[..]);
    // another token id: another script, another address
    let other = drip_redeem(&TIPSY, COV_C.as_bytes()).unwrap();
    assert_ne!(other, redeem);
    assert_ne!(pay_to_script_hash_script(&other), pay_to_script_hash_script(&redeem));
    println!("drip for {}: {}", COV_A, hex::encode(pay_to_script_hash_script(&redeem).script()));
}

/// The Studio's eight cases (minerdrip/minerdrip_js_tests.rs), against this drip: reveal once, only back to itself,
/// only min_prize; claim on time, never early, never skimming, never with a second output.
#[test]
fn minerdrip_cases_with_tipsy_terms() {
    let redeem = drip_redeem(&TIPSY, COV_A.as_bytes()).unwrap();
    let spk = pay_to_script_hash_script(&redeem);
    let coin = |value: u64| Spent { outpoint: outpoint([3; 32], 0), value, spk: spk.clone(), covenant_id: None };
    let endow = TIPSY.endowment;
    let after = endow - TIPSY.min_prize;
    let prize = std::cmp::max(after / TIPSY.divisor, TIPSY.min_prize);
    let t = |name: &str, r: std::result::Result<Vec<u64>, (usize, kaspa_txscript_errors::TxScriptError)>, want: bool| {
        assert_eq!(r.is_ok(), want, "{name}: {r:?}");
        println!("  PASS  {name}{}", r.err().map(|(_, e)| format!(" (refused: {e:?})")).unwrap_or_default());
    };
    // a hand-built variant of a spend: the same input, other outputs / sequence
    let variant = |built: &BuiltTx, outs: Vec<TransactionOutput>, seq: u64| {
        let mut tx = built.tx.clone();
        tx.outputs = outs;
        tx.inputs[0].sequence = seq;
        BuiltTx { tx, spent: built.spent.clone() }
    };
    let own = |v: u64| TransactionOutput { value: v, script_public_key: spk.clone(), covenant: None };
    let elsewhere = |v: u64| TransactionOutput { value: v, script_public_key: pay_to_script_hash_script(&[0x51]), covenant: None };

    let reveal = build_drip_spend(&TIPSY, COV_A.as_bytes(), &coin(endow), ENTRY_REVEAL).unwrap();
    assert_eq!(reveal.tx.outputs[0].value, after);
    t("reveal on the fresh endowment", reveal.execute_all(), true);
    assert!(build_drip_spend(&TIPSY, COV_A.as_bytes(), &coin(after), ENTRY_REVEAL).is_err(), "the builder refuses a second reveal");
    let reveal2 = BuiltTx { tx: { let mut x = reveal.tx.clone(); x.outputs[0].value = after - TIPSY.min_prize; x }, spent: vec![coin(after)] };
    t("reveal a second time", reveal2.execute_all(), false);
    t("reveal paying elsewhere", variant(&reveal, vec![elsewhere(after)], 0).execute_all(), false);
    t("reveal taking more than min_prize", variant(&reveal, vec![own(after - 1)], 0).execute_all(), false);

    let claim = build_drip_spend(&TIPSY, COV_A.as_bytes(), &coin(after), ENTRY_CLAIM).unwrap();
    assert_eq!(claim.tx.inputs[0].sequence, TIPSY.period);
    assert_eq!(claim.tx.outputs[0].value, after - prize);
    t("claim one DAA early", variant(&claim, vec![own(after - prize)], TIPSY.period - 1).execute_all(), false);
    t("claim on time", claim.execute_all(), true);
    t("claim skimming one sompi", variant(&claim, vec![own(after - prize - 1)], TIPSY.period).execute_all(), false);
    t("claim with a second output", variant(&claim, vec![own(after - prize - 10_000_000), elsewhere(10_000_000)], TIPSY.period).execute_all(), false);
    // the schedule: 1 KAS at divisor 20 pays 0.0495 first, then 5% of what is left each claim, floor 0.01
    println!("first claim prize {} sompi, period {} DAA (~{:.1} h)", prize, TIPSY.period, TIPSY.period as f64 / 864_000.0 * 24.0);
}

/// Cold-review finding (2026-10-17), fixed by MinerDrip v2 (the Studio session's `require(tx.inputs.length == 1)` in both
/// entries): two coins of equal value at the drip script can no longer be spent together into one output. On v1 this
/// merge was accepted by both inputs' scripts and the second coin became the fee (measured on the box: 103,950,000 sompi).
#[test]
fn minerdrip_two_equal_coins_cannot_merge() {
    let redeem = drip_redeem(&TIPSY, COV_A.as_bytes()).unwrap();
    let spk = pay_to_script_hash_script(&redeem);
    let after = TIPSY.endowment - TIPSY.min_prize;
    let prize = std::cmp::max(after / TIPSY.divisor, TIPSY.min_prize);
    let coin = |i: u32, v: u64| Spent { outpoint: outpoint([3; 32], i), value: v, spk: spk.clone(), covenant_id: None };
    let merge = |entry: &str, v: u64, keep: u64, seq: u64| {
        let sig = drip_sigscript(&TIPSY, COV_A.as_bytes(), entry).unwrap();
        let mut t = BuiltTx::new(vec![(coin(0, v), sig.clone()), (coin(1, v), sig)], vec![TransactionOutput { value: keep, script_public_key: spk.clone(), covenant: None }]);
        for i in &mut t.tx.inputs {
            i.sequence = seq;
        }
        t
    };
    assert_rejected(&merge(ENTRY_CLAIM, after, after - prize, TIPSY.period), "claim merging two equal coins");
    assert_rejected(&merge(ENTRY_REVEAL, TIPSY.endowment, TIPSY.endowment - TIPSY.min_prize, 0), "reveal merging two equal endowments");
    // a single top-up coin still drips on its own
    let one = build_drip_spend(&TIPSY, COV_A.as_bytes(), &coin(0, 300_000_000), ENTRY_CLAIM).unwrap();
    one.execute_all().expect("a single coin claims on its own");
}
