//! The BRIDGE covenant and its KCC20 token run through rusty-kaspa 2.1.0's script engine
//! with the real mainnet proof that carries Vault deposit #1 (eth-prover/out-deposit-1) and
//! the consensus-spec fixture proof (out-fixture-gpu, a different image, a 210-byte journal).
//! Run: cargo test --release -- --nocapture

use bridge_covenant::*;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, TransactionOutput};
use std::path::Path;

const DEPOSIT_BUNDLE: &str = "../eth-prover/out-deposit-1";
const FIXTURE_BUNDLE: &str = "../eth-prover/out-fixture-gpu";
const MAX_FEE: i64 = 200_000_000; // 2 KAS: fee + KAS carried by the token outputs
const BRIDGE_VALUE: u64 = 1_000_000_000; // 10 KAS
const TOKEN_KAS: u64 = 20_000_000; // 0.2 KAS per token UTXO
const FEE: u64 = 3_000_000;
const COV_C: Hash = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"); // the bridge
const COV_A: Hash = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // the token
const VALUES: Values = Values { fee: FEE, token_out: TOKEN_KAS };

fn deposit() -> (Params, Bundle, JournalView) {
    let b = load_bundle(Path::new(DEPOSIT_BUNDLE)).expect("deposit bundle");
    let j = parse_journal(&b.journal).expect("journal");
    let p = Params { image_id: b.image_id, chain_commitment: j.chain_commitment, vault: j.vault, max_fee: MAX_FEE };
    (p, b, j)
}

/// The state the covenant is in right before out-deposit-1 applies, token already initialized.
fn ready(j: &JournalView) -> State {
    State { header: j.prev_header, committee: j.prev_committee, cursor: 0, token: COV_A.as_bytes() }
}

fn bridge_utxo(p: &Params, s: &State) -> Spent {
    Spent::p2sh(outpoint([7; 32], 0), BRIDGE_VALUE, &redeem_script(&compile(p, s).unwrap()), Some(COV_C))
}

fn minter_utxo() -> Spent {
    Spent::p2sh(outpoint([8; 32], 1), TOKEN_KAS, &token_redeem(&TokenState::minter_branch(COV_C.as_bytes())).unwrap(), Some(COV_A))
}

fn mint_tx(p: &Params, s: &State, b: &Bundle) -> (BuiltTx, State) {
    build_advance(p, s, &bridge_utxo(p, s), COV_C, Some(&minter_utxo()), &b.journal, &b.proof, &VALUES).expect("build advance")
}

fn assert_rejected(t: &BuiltTx, what: &str) {
    match t.execute_all() {
        Ok(_) => panic!("{what}: accepted"),
        Err((i, e)) => println!("{what}: rejected at input {i}: {e:?}"),
    }
}

#[test]
fn journal_of_deposit_1_decodes() {
    let (_, b, j) = deposit();
    assert_eq!(b.journal.len(), 279);
    assert_eq!(hex::encode(j.vault), "3dd8cd71c3efe664d4db96d30fbfecbeea06d529");
    assert_eq!(j.deposits.len(), 1);
    let d = j.deposits[0];
    assert_eq!((d.nonce, d.amount, d.version), (1, 1_000_000, 0));
    assert_eq!(hex::encode(d.payload), "856bc60330866c89f02fc502c265416b906e4c4eb7b2bab38af18c6f36e6829c");
    assert_eq!(j.exec_block_number, 26_178_455);
}

#[test]
fn compiles_and_reports_sizes() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let a = compile(&p, &s).unwrap();
    let redeem = redeem_script(&a);
    let span = a.contracts.get(CONTRACT).unwrap().compiled.state_span;
    let sig = advance_sigscript(&a, &b.journal, &b.proof).unwrap();
    let t = token_template().unwrap();
    println!(
        "bridge redeem {} bytes, state span {:?}, advance sigscript {} bytes; token template prefix {} + suffix {} bytes, hash {}",
        redeem.len(), span, sig.len(), t.prefix.len(), t.suffix.len(), hex::encode(t.hash)
    );
    // the verifier fragment's fixed VK must be inside the redeem script
    assert!(redeem.windows(8).any(|w| w == [0xe2, 0xf2, 0x6d, 0xbe, 0xa2, 0x99, 0xf5, 0x22]));
    // two states differ only inside the state span
    let other = redeem_script(&compile(&p, &j.next_state(&s)).unwrap());
    assert_eq!(redeem.len(), other.len());
    let diff: Vec<usize> = (0..redeem.len()).filter(|&i| redeem[i] != other[i]).collect();
    assert!(!diff.is_empty() && diff.iter().all(|&i| i >= span.offset && i < span.offset + span.len), "bytes outside the state span differ");
    // the token template is the same for every state
    let r1 = token_redeem(&TokenState::minter_branch(COV_C.as_bytes())).unwrap();
    let r2 = token_redeem(&TokenState { owner: [3; 32], owner_type: IDENTIFIER_PUBKEY, amount: 123_456, is_minter: false }).unwrap();
    assert_eq!(r1.len(), r2.len());
    assert!(r1.starts_with(&t.prefix) && r1.ends_with(&t.suffix) && r2.starts_with(&t.prefix) && r2.ends_with(&t.suffix));
}

#[test]
fn init_creates_the_token_from_a_fresh_genesis() {
    let (p, _b, j) = deposit();
    let genesis = State { token: [0; 32], ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let (t, token_id, next) = build_init(&p, &genesis, &bridge, COV_C, &VALUES).unwrap();
    assert_eq!(t.genesis_covenant_id(0, &[1]), token_id);
    assert_eq!(next.token, token_id.as_bytes());
    let units = t.execute_all().expect("init must pass");
    println!("init: {} script units -> budget {}; token id {token_id}", units[0], covering_budget(units[0]));

    // a third output in the same genesis group (a second minter branch) is rejected
    let mut three = t.tx.clone();
    three.outputs.push(TransactionOutput {
        value: TOKEN_KAS,
        script_public_key: kaspa_txscript::pay_to_script_hash_script(&token_redeem(&TokenState { owner: [9; 32], owner_type: IDENTIFIER_PUBKEY, amount: 1 << 40, is_minter: true }).unwrap()),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: token_id }),
    });
    let id3 = kaspa_consensus_core::hashing::covenant_id::covenant_id(three.inputs[0].previous_outpoint, [(1u32, &three.outputs[1]), (2u32, &three.outputs[2])].into_iter());
    for o in &mut three.outputs[1..] {
        o.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: id3 });
    }
    // the successor must name id3 for the state check to be the thing that fails, so rebuild it
    let next3 = State { token: id3.as_bytes(), ..genesis };
    three.outputs[0].script_public_key = kaspa_txscript::pay_to_script_hash_script(&redeem_script(&compile(&p, &next3).unwrap()));
    assert_rejected(&BuiltTx { tx: three, spent: t.spent.clone() }, "init with two minter branches");

    // a token genesis owned by someone else is rejected
    let mut other = t.tx.clone();
    other.outputs[1].script_public_key = kaspa_txscript::pay_to_script_hash_script(&token_redeem(&TokenState { owner: [9; 32], owner_type: IDENTIFIER_PUBKEY, amount: 0, is_minter: true }).unwrap());
    let ido = kaspa_consensus_core::hashing::covenant_id::covenant_id(other.inputs[0].previous_outpoint, [(1u32, &other.outputs[1])].into_iter());
    other.outputs[1].covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: ido });
    other.outputs[0].script_public_key = kaspa_txscript::pay_to_script_hash_script(&redeem_script(&compile(&p, &State { token: ido.as_bytes(), ..genesis }).unwrap()));
    assert_rejected(&BuiltTx { tx: other, spent: t.spent.clone() }, "init with a foreign owner");

    // init twice: the state already names a token
    assert!(build_init(&p, &next, &Spent::p2sh(outpoint([7; 32], 1), BRIDGE_VALUE, &redeem_script(&compile(&p, &next).unwrap()), Some(COV_C)), COV_C, &VALUES).is_err());
}

#[test]
fn init_rejects_a_continuation_of_an_existing_token() {
    // Output 1 is a minter branch owned by the bridge, but bound to a token that already exists
    // (an attacker's token X whose minter branch they spend as input 1). The bridge would then
    // mint X, which has other minters. OpCovInputCount(X) == 0 is what stops it.
    let (p, _b, j) = deposit();
    let genesis = State { token: [0; 32], ..ready(&j) };
    let bridge = bridge_utxo(&p, &genesis);
    let cov_x = Hash::from_bytes([0x58; 32]);
    let attacker = TokenState { owner: [9; 32], owner_type: IDENTIFIER_PUBKEY, amount: 0, is_minter: true };
    let x_in = Spent::p2sh(outpoint([5; 32], 0), TOKEN_KAS, &token_redeem(&attacker).unwrap(), Some(cov_x));
    let next = State { token: cov_x.as_bytes(), ..genesis };
    let cur = compile(&p, &genesis).unwrap();
    let minter = TokenState::minter_branch(COV_C.as_bytes());
    let outputs = vec![
        p2sh_output(BRIDGE_VALUE - FEE, &redeem_script(&compile(&p, &next).unwrap()), Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_C })),
        p2sh_output(TOKEN_KAS, &token_redeem(&minter).unwrap(), Some(CovenantBinding { authorizing_input: 1, covenant_id: cov_x })),
    ];
    let t = BuiltTx::new(vec![(bridge, init_sigscript(&cur).unwrap()), (x_in, token_transfer_sigscript(&attacker, &[minter], &[0u8; 65], 0).unwrap())], outputs);
    let err = t.execute(0).unwrap_err();
    println!("init against an existing token: bridge input rejected: {err:?}");
}

#[test]
fn advance_mints_deposit_1() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, next) = mint_tx(&p, &s, &b);
    assert_eq!(t.tx.inputs.len(), 2);
    assert_eq!(t.tx.outputs.len(), 3, "successor, minter branch, one recipient");
    assert_eq!(next.cursor, 1);
    assert_eq!((next.header, next.committee), (j.new_header, j.new_committee));
    let units = t.execute_all().expect("genuine mint must pass");
    println!(
        "mint of deposit 1: bridge input {} units (budget {}), token input {} units (budget {})",
        units[0], covering_budget(units[0]), units[1], covering_budget(units[1])
    );
    // the recipient output is the KCC20 state the depositor named on Ethereum
    let want = token_redeem(&TokenState { owner: j.deposits[0].payload, owner_type: IDENTIFIER_PUBKEY, amount: 1_000_000, is_minter: false }).unwrap();
    assert_eq!(t.tx.outputs[2].script_public_key, kaspa_txscript::pay_to_script_hash_script(&want));
    assert_eq!(t.tx.outputs[2].covenant.unwrap().covenant_id, COV_A);
}

#[test]
fn mint_to_the_wrong_recipient_or_amount_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let (t, _) = mint_tx(&p, &s, &b);
    let d = j.deposits[0];
    for (what, st) in [
        ("other owner", TokenState { owner: [0xEE; 32], owner_type: IDENTIFIER_PUBKEY, amount: d.amount, is_minter: false }),
        ("script-hash type", TokenState { owner: d.payload, owner_type: IDENTIFIER_SCRIPT_HASH, amount: d.amount, is_minter: false }),
        ("double amount", TokenState { owner: d.payload, owner_type: IDENTIFIER_PUBKEY, amount: 2 * d.amount, is_minter: false }),
        ("recipient as minter", TokenState { owner: d.payload, owner_type: IDENTIFIER_PUBKEY, amount: d.amount, is_minter: true }),
    ] {
        let mut tx = t.tx.clone();
        tx.outputs[2].script_public_key = kaspa_txscript::pay_to_script_hash_script(&token_redeem(&st).unwrap());
        // the token input's sigscript names the same (wrong) state, so only the bridge can object
        let minter = TokenState::minter_branch(COV_C.as_bytes());
        tx.inputs[1].signature_script = token_transfer_sigscript(&minter, &[minter, st], &[0u8; 65], 0).unwrap();
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
    // no minter-branch continuation (burning the minter)
    let mut tx = t.tx.clone();
    tx.outputs.remove(1);
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint without minter continuation");
    // an extra recipient output
    let mut tx = t.tx.clone();
    tx.outputs.push(tx.outputs[2].clone());
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint with an extra token output");
    // the minter branch handed to someone else
    let mut tx = t.tx.clone();
    tx.outputs[1].script_public_key = kaspa_txscript::pay_to_script_hash_script(&token_redeem(&TokenState { owner: [9; 32], owner_type: IDENTIFIER_PUBKEY, amount: 0, is_minter: true }).unwrap());
    assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, "mint handing over the minter branch");
    // bridge advances without the token at all although the journal carries a new deposit
    let tx = BuiltTx::new(vec![(t.spent[0].clone(), t.tx.inputs[0].signature_script.clone())], vec![t.tx.outputs[0].clone()]);
    assert_rejected(&tx, "mint skipped");
}

#[test]
fn cursor_blocks_a_second_mint_of_the_same_deposit() {
    let (p, b, j) = deposit();
    // Same light-client state the proof names, but nonce 1 already minted: the proof is still
    // valid for the light-client step (heartbeat) and must not mint again.
    let s = State { cursor: 1, ..ready(&j) };
    let bridge = bridge_utxo(&p, &s);
    let (hb, next) = build_advance(&p, &s, &bridge, COV_C, None, &b.journal, &b.proof, &VALUES).unwrap();
    assert_eq!(hb.tx.inputs.len(), 1);
    assert_eq!(next.cursor, 1);
    let units = hb.execute_all().expect("heartbeat over an already-minted deposit must pass");
    println!("heartbeat (deposit 1 already minted): {} units (budget {})", units[0], covering_budget(units[0]));
    // trying to mint it anyway: the mint shape built for cursor 0, submitted against cursor 1
    let (mint_at_0, _) = mint_tx(&p, &ready(&j), &b);
    let mut tx = mint_at_0.tx.clone();
    tx.inputs[0].signature_script = advance_sigscript(&compile(&p, &s).unwrap(), &b.journal, &b.proof).unwrap();
    tx.outputs[0].script_public_key = kaspa_txscript::pay_to_script_hash_script(&redeem_script(&compile(&p, &next).unwrap()));
    let mut spent = mint_at_0.spent.clone();
    spent[0] = bridge;
    assert_rejected(&BuiltTx { tx, spent }, "second mint of nonce 1");
}

#[test]
fn replay_of_the_same_proof_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let after = j.next_state(&s);
    // after the mint the state is `after`; the same proof names the old header (and nonce 1 <= cursor)
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
        ("cursor 2", State { cursor: 2, ..next }),
        ("token", State { token: [0x11; 32], ..next }),
        ("unchanged", s),
    ] {
        let mut tx = t.tx.clone();
        tx.outputs[0].script_public_key = kaspa_txscript::pay_to_script_hash_script(&redeem_script(&compile(&p, &bad).unwrap()));
        assert_rejected(&BuiltTx { tx, spent: t.spent.clone() }, &format!("successor with wrong {what}"));
    }
}

#[test]
fn tampered_journal_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    for off in [0usize, 40, 70, 100, 130, 215, 229, 237, 245, 246, 270] {
        let mut jr = b.journal.clone();
        jr[off] ^= 0x01;
        let bridge = bridge_utxo(&p, &s);
        match build_advance(&p, &s, &bridge, COV_C, Some(&minter_utxo()), &jr, &b.proof, &VALUES) {
            Ok((t, _)) => assert_rejected(&t, &format!("journal byte {off} flipped")),
            Err(e) => println!("journal byte {off} flipped: not even buildable ({e})"),
        }
    }
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
    let fx = load_bundle(Path::new(FIXTURE_BUNDLE)).unwrap();
    let mut im = p.clone();
    im.image_id = fx.image_id;
    assert_rejected(&mint_tx(&im, &s, &b).0, "other image id");
    // the fixture proof (210-byte journal, other image) cannot open the bridge
    let bridge = bridge_utxo(&p, &s);
    match build_advance(&p, &s, &bridge, COV_C, None, &fx.journal, &fx.proof, &VALUES) {
        Ok((t, _)) => assert_rejected(&t, "fixture proof"),
        Err(e) => println!("fixture proof: not buildable ({e})"),
    }
}

#[test]
fn value_drain_beyond_max_fee_is_rejected() {
    let (p, b, j) = deposit();
    let s = ready(&j);
    let bridge = bridge_utxo(&p, &s);
    let exact = Values { fee: MAX_FEE as u64 - TOKEN_KAS, token_out: TOKEN_KAS }; // drain exactly max_fee
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&minter_utxo()), &b.journal, &b.proof, &exact).unwrap();
    t.execute_all().expect("drain of exactly max_fee passes");
    let over = Values { fee: MAX_FEE as u64 - TOKEN_KAS + 1, token_out: TOKEN_KAS };
    let (t, _) = build_advance(&p, &s, &bridge, COV_C, Some(&minter_utxo()), &b.journal, &b.proof, &over).unwrap();
    assert_rejected(&t, "drain of max_fee + 1 sompi");
}

#[test]
fn minter_branch_cannot_move_without_the_bridge() {
    let minter = TokenState::minter_branch(COV_C.as_bytes());
    let thief = TokenState { owner: [9; 32], owner_type: IDENTIFIER_PUBKEY, amount: 1_000_000_000, is_minter: false };
    let out = p2sh_output(TOKEN_KAS, &token_redeem(&thief).unwrap(), Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }));
    let t = BuiltTx::new(vec![(minter_utxo(), token_transfer_sigscript(&minter, &[thief], &[0u8; 65], 0).unwrap())], vec![out]);
    assert_rejected(&t, "minter branch spent without a bridge input");
}

#[test]
fn wallet_transfer_spends_a_minted_utxo() {
    // A pubkey-owned recipient branch (what a mint creates) moves with a plain Schnorr signature.
    let secp = secp256k1::Secp256k1::new();
    let alice_sk = [0x51; 32];
    let alice = secp256k1::Keypair::from_seckey_slice(&secp, &alice_sk).unwrap().x_only_public_key().0.serialize();
    let bob = secp256k1::Keypair::from_seckey_slice(&secp, &[0x62; 32]).unwrap().x_only_public_key().0.serialize();
    let held = TokenState { owner: alice, owner_type: IDENTIFIER_PUBKEY, amount: 1_000_000, is_minter: false };
    let utxo = Spent::p2sh(outpoint([3; 32], 2), 100_000_000, &token_redeem(&held).unwrap(), Some(COV_A));
    let to_bob = TokenState { owner: bob, owner_type: IDENTIFIER_PUBKEY, amount: 600_000, is_minter: false };
    let change = TokenState { owner: alice, owner_type: IDENTIFIER_PUBKEY, amount: 400_000, is_minter: false };
    let kas_change = ScriptPublicKey::from_vec(0, vec![0x51]); // OP_TRUE, stands in for a wallet address
    let t = build_transfer(COV_A, &utxo, &held, &[to_bob, change], &alice_sk, TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    assert_eq!(t.tx.outputs.len(), 3);
    let units = t.execute_all().expect("wallet transfer must pass");
    println!("wallet transfer 1 -> 2: {} units (budget {}), sigscript {} bytes", units[0], covering_budget(units[0]), t.tx.inputs[0].signature_script.len());
    // wrong key
    let t2 = build_transfer(COV_A, &utxo, &held, &[to_bob, change], &[0x77; 32], TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    assert_rejected(&t2, "transfer signed with the wrong key");
    // inflation
    let more = TokenState { amount: 500_000, ..change };
    let t3 = build_transfer(COV_A, &utxo, &held, &[to_bob, more], &alice_sk, TOKEN_KAS, FEE, Some(kas_change.clone())).unwrap();
    assert_rejected(&t3, "transfer creating tokens");
    // promoting oneself to minter
    let t4 = build_transfer(COV_A, &utxo, &held, &[TokenState { is_minter: true, ..held }], &alice_sk, TOKEN_KAS, FEE, Some(kas_change)).unwrap();
    assert_rejected(&t4, "transfer setting isMinter");
}
