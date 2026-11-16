//! Adversarial witnesses against the relay guest v2 (U4, `KZO3`, token burns). `kaspa_prover_primitives::relay::run`
//! is the exact code the guest runs, so every case below is what the zkVM would do with that witness; with
//! RELAY_ZKVM=1 each case is also executed by the zkVM in dev mode (no proving) and must agree. The O5 suite
//! (v1, KAS burns) is this file's previous revision; its cases are kept, the burn cases now act on burn cells, and
//! U4 adds the reference-cell and three-step cases.
//!
//!   cd outbound/kaspa-prover
//!   RELAY_WITNESS=../burnwitness/witness-u4.json cargo test --release -p kaspa-prover-host -- adversarial --nocapture
//!   RELAY_ZKVM=1 RELAY_WITNESS=... cargo test --release -p kaspa-prover-host -- adversarial --nocapture --test-threads 1
//!   RELAY_BUNDLE=out-u4-devtest ...   also checks that the unmodified witness gives the bundle's journal hash
//!
//! Every case takes a real witness (a format-3 `burnwitness` file from mainnet), changes one thing and asserts either
//! the panic the guest raises (the mutation is detected) or, for what the guest cannot tell apart from an honest but
//! weaker witness, that the journal only gets weaker: fewer attesters, never more, and the contract's gates then
//! refuse it. Journals the contract should see are written to `out-adversarial/<case>.journal.hex`
//! (RELAY_ADVERSARIAL_OUT overrides the directory). Without a witness every case prints "skipped" and passes; the
//! same refusals are unit-tested on synthetic data in primitives/src/relay.rs.

use crate::witness::{build_witness, WFile};
use kaspa_prover_methods::KASPA_RELAY_GUEST_ELF;
use kaspa_prover_primitives::relay::{self, h_seq, BurnCell, Journal, Witness, KCC20_PREFIX, KCC20_SUFFIX, MAX_BURNS};
use kaspa_prover_primitives::{verify_header, Hash, SoftKeccak, Stage};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_executor, ExecutorEnv};
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::OnceLock;

/// The relay v2 gates at a small amount (usdc/src/KaspaRelayV2.sol, docs/USDC-PARAMETERS.md): CMP_LEVEL 30,
/// FLOOR 100, requiredAttest(A) = max(ATTEST_FLOOR 100, ceil(A / ATTEST_UNIT)).
const CMP_LEVEL: u8 = 30;
const FLOOR: u32 = 100;
const MIN_ATTEST: u32 = 100;

struct Fixture {
    w: Witness,
    base: Journal,
    extra_nonchain: Vec<(Hash, Vec<u8>, bool)>, // (hash, preimage, selected parent is a chain block)
    /// headers on hop-4 paths that are not already in the witness
    late: Vec<Vec<u8>>,
    /// burnwitness's view of the comparison level: attesters by hop, hop-4 joins, the deep and late paths
    by_steps: Vec<u32>,
    joins_late: u32,
    deep_paths: Vec<Vec<Hash>>,
    lmax: u32,
}

static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();

fn witness_path() -> PathBuf {
    match std::env::var("RELAY_WITNESS") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../burnwitness/witness-u4.json"),
    }
}

fn out_dir() -> PathBuf {
    let d = match std::env::var("RELAY_ADVERSARIAL_OUT") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../out-adversarial"),
    };
    std::fs::create_dir_all(&d).expect("create out-adversarial");
    d
}

fn fixture() -> Option<&'static Fixture> {
    FIXTURE
        .get_or_init(|| {
            let path = witness_path();
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    println!("adversarial: no witness at {} ({e}); set RELAY_WITNESS. Cases skipped.", path.display());
                    return None;
                }
            };
            let f: WFile = serde_json::from_str(&text).expect("witness.json parses");
            crate::witness::check_format(&f).expect("witness format");
            let levels: Vec<u8> = match std::env::var("RELAY_LEVELS") {
                Ok(s) => s.split(',').map(|x| x.trim().parse().expect("RELAY_LEVELS")).collect(),
                Err(_) => f.levels.clone(),
            };
            let w = build_witness(&f, &levels, false, true, [0x77u8; 20]).expect("build witness");
            let base = run_native(&w).expect("the unmodified witness must verify");
            let extra_nonchain = f
                .extra_headers
                .iter()
                .filter(|x| !x.is_chain)
                .map(|x| (crate::unhex32(&x.hash).expect("extra hash"), crate::unhex(&x.preimage).expect("extra preimage"), x.selected_parent_is_chain))
                .collect();
            let present: HashSet<Hash> = w.headers.iter().chain(w.y_headers.iter()).map(|hb| hash_of(hb)).collect();
            let late = f
                .y_late_headers
                .iter()
                .map(|h| crate::unhex(&h.preimage).expect("late preimage"))
                .filter(|pre| !present.contains(&hash_of(pre)))
                .collect::<Vec<_>>();
            let cmp = f.per_level.iter().find(|p| p.level == CMP_LEVEL);
            let by_steps = cmp.map(|p| p.attesting_by_steps.clone()).unwrap_or_default();
            let joins_late = cmp.map(|p| p.joins_late).unwrap_or(0);
            let deep_paths: Vec<Vec<Hash>> = cmp
                .map(|p| p.deep_paths.iter().map(|path| path.iter().map(|s| crate::unhex32(s).expect("path hash")).collect()).collect())
                .unwrap_or_default();
            println!(
                "adversarial: witness {} ({}), levels {:?}, {} PoW headers, {} first-parent headers, {} attestation roots, {} burn(s), token {}, {} extra non-chain, {} hop-4 header(s)",
                path.display(),
                f.source.as_deref().unwrap_or("?"),
                levels,
                w.headers.len(),
                w.y_headers.len(),
                w.attest_roots.len(),
                w.burns.len(),
                &relay::hx(&w.token_cov_id)[..16],
                f.extra_headers.len(),
                late.len()
            );
            for lc in &base.levels {
                println!("adversarial: baseline level {:>3}: {} superblocks, {} attesting", lc.level, lc.count, lc.attesting);
            }
            println!("adversarial: burnwitness at level {CMP_LEVEL}: attesters by hop {:?}, {joins_late} join at hop 4", by_steps);
            if let Ok(bundle) = std::env::var("RELAY_BUNDLE") {
                let want = std::fs::read_to_string(PathBuf::from(bundle).join("journal_hash.hex")).expect("RELAY_BUNDLE/journal_hash.hex");
                let got = hex::encode(risc0_zkvm::Journal::new(base.encode()).digest().as_bytes());
                assert_eq!(got, want.trim(), "the unmodified witness does not give the bundle's journal hash");
                println!("adversarial: baseline journal hash {} = the bundle's", got);
            }
            let lmax = *levels.last().unwrap() as u32;
            Some(Fixture { w, base, extra_nonchain, late, by_steps, joins_late, deep_paths, lmax })
        })
        .as_ref()
}

// ------------------------------------------------------------------ helpers

fn panic_msg(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "<non-string panic>".into()
    }
}

fn run_native(w: &Witness) -> Result<Journal, String> {
    let input = w.encode();
    catch_unwind(AssertUnwindSafe(|| relay::run::<SoftKeccak>(&input))).map_err(panic_msg)
}

fn zkvm_on() -> bool {
    std::env::var("RELAY_ZKVM").map(|v| v == "1").unwrap_or(false)
}

/// The guest in dev mode: Err when it panics, else its journal bytes.
fn run_zkvm(w: &Witness) -> Result<Vec<u8>, String> {
    let env = ExecutorEnv::builder().write_frame(&w.encode()).build().map_err(|e| e.to_string())?;
    default_executor().execute(env, KASPA_RELAY_GUEST_ELF).map(|info| info.journal.bytes).map_err(|e| e.to_string())
}

fn hash_of(hb: &[u8]) -> Hash {
    verify_header::<SoftKeccak>(hb, Stage::Hash).expect("header parses").hash
}

fn aimr_of(hb: &[u8]) -> Hash {
    let p = verify_header::<SoftKeccak>(hb, Stage::Parse).expect("header parses").parsed;
    hb[p.ts_off - 64..p.ts_off - 32].try_into().unwrap()
}

fn level_of(hb: &[u8]) -> u32 {
    verify_header::<SoftKeccak>(hb, Stage::Full).expect("header parses").level
}

fn index_of(w: &Witness, h: &Hash) -> usize {
    w.headers.iter().position(|hb| hash_of(hb) == *h).unwrap_or_else(|| panic!("{} is not among the headers", relay::hx(h)))
}

/// Index of a ladder header that is neither T nor B and lies after B (every such header is visited by the walk).
fn ladder_index(w: &Witness) -> usize {
    let b_daa = verify_header::<SoftKeccak>(&w.headers[index_of(w, &w.b)], Stage::Parse).unwrap().parsed.daa_score;
    w.headers
        .iter()
        .position(|hb| {
            let h = hash_of(hb);
            h != w.t && h != w.b && verify_header::<SoftKeccak>(hb, Stage::Parse).unwrap().parsed.daa_score > b_daa
        })
        .expect("a ladder header")
}

fn level_entry(j: &Journal, level: u8) -> (u32, u32) {
    let lc = j.levels.iter().find(|l| l.level == level).unwrap_or_else(|| panic!("no level {level} in the journal"));
    (lc.count, lc.attesting)
}

fn write_journal(name: &str, j: &Journal) {
    let p = out_dir().join(format!("{name}.journal.hex"));
    std::fs::write(&p, hex::encode(j.encode())).expect("write journal");
    println!("{name:<26} journal written to {} (sha256 {})", p.display(), hex::encode(risc0_zkvm::Journal::new(j.encode()).digest().as_bytes()));
}

/// The guest must refuse the witness with a panic whose message contains `needle`; the zkVM (when on) must
/// refuse it too.
fn expect_refused(name: &str, w: &Witness, needle: &str) {
    match run_native(w) {
        Err(m) => {
            assert!(m.contains(needle), "{name}: panicked with {m:?}, expected a message containing {needle:?}");
            println!("{name:<26} refused: {m}");
        }
        Ok(j) => panic!("{name}: accepted (levels {:?}), expected a panic containing {needle:?}", j.levels),
    }
    if zkvm_on() {
        match run_zkvm(w) {
            Err(e) => println!("{name:<26} zkVM refused too: {}", e.lines().next().unwrap_or("")),
            Ok(_) => panic!("{name}: the zkVM accepted a witness the native run refused"),
        }
    }
}

/// The guest accepts the witness (it cannot tell it from an honest one) and `check` says what the journal must
/// look like; the zkVM (when on) must produce the same journal byte for byte.
fn expect_accepted(name: &str, w: &Witness, check: impl FnOnce(&Journal)) -> Journal {
    let j = run_native(w).unwrap_or_else(|m| panic!("{name}: refused with {m:?}, expected a journal"));
    check(&j);
    if zkvm_on() {
        let bytes = run_zkvm(w).unwrap_or_else(|e| panic!("{name}: the zkVM refused a witness the native run accepted: {e}"));
        assert_eq!(bytes, j.encode(), "{name}: zkVM journal differs from the native journal");
        println!("{name:<26} zkVM journal equal");
    }
    j
}

/// A header the guest accepts at face value: it parses, hashes and passes proof of work at the easiest
/// compact target (`bits` 0x207fffff, half of all nonces pass), so it costs nothing to make. Level 0, which
/// the guest never asks B for (B's weight is the attestation, not its own work).
fn forge_header(first_parent: &Hash, aimr: &Hash, daa_score: u64) -> Vec<u8> {
    for nonce in 0u64..1_000_000 {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes()); // one level of parents
        b.extend_from_slice(&1u64.to_le_bytes()); // one direct parent
        b.extend_from_slice(first_parent);
        b.extend_from_slice(&[0x11u8; 32]); // hash_merkle_root
        b.extend_from_slice(aimr); // accepted_id_merkle_root: the fabricated commitment
        b.extend_from_slice(&[0x22u8; 32]); // utxo_commitment
        b.extend_from_slice(&1_760_000_000_000u64.to_le_bytes()); // timestamp
        b.extend_from_slice(&0x207fffffu32.to_le_bytes()); // bits: the easiest target
        b.extend_from_slice(&nonce.to_le_bytes());
        b.extend_from_slice(&daa_score.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // blue_score
        b.extend_from_slice(&1u64.to_le_bytes()); // blue_work: one byte
        b.push(1);
        b.extend_from_slice(&[0u8; 32]); // pruning_point
        let v = verify_header::<SoftKeccak>(&b, Stage::Full).expect("forged header parses");
        if v.passed {
            return b;
        }
    }
    unreachable!("no nonce passes the easiest target in a million tries")
}

/// The first named burn cell's output index.
fn burn_cell_index(w: &Witness, burn: usize) -> usize {
    w.burns[burn].cells[0].index as usize
}

// ------------------------------------------------------------------ baseline

#[test]
fn baseline_is_accepted() {
    let Some(f) = fixture() else { return };
    let (count, attesting) = level_entry(&f.base, CMP_LEVEL);
    assert!(count >= FLOOR && attesting >= MIN_ATTEST, "the baseline witness itself does not pass the contract's gates ({count} / {attesting})");
    let _ = expect_accepted("baseline", &f.w, |j| assert_eq!(*j, f.base));
    assert_eq!(f.base.template_hash, relay::KCC20_TEMPLATE);
    assert_eq!(f.base.token_cov_id, f.w.token_cov_id);
    println!(
        "{:<26} level {CMP_LEVEL}: {count} superblocks, {attesting} attesting; r_bits 0x{:08x}; T {} B {}; token {}",
        "baseline",
        f.base.r_bits,
        &relay::hx(&f.w.t)[..16],
        &relay::hx(&f.w.b)[..16],
        &relay::hx(&f.w.token_cov_id)[..16]
    );
}

// ------------------------------------------------------------------ the reference cell (U4)

#[test]
fn burn_cell_amount_off_by_one() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.burns[0].cells[0].amount += 1;
    expect_refused("cell_amount_plus_one", &w, "is not a burn cell of amount");
    let mut w = f.w.clone();
    w.burns[0].cells[0].amount -= 1;
    expect_refused("cell_amount_minus_one", &w, "is not a burn cell of amount");
}

/// The change cell (or any other token output of the burn tx) named as a burn: its hash is another owner's.
#[test]
fn change_cell_named_as_burn() {
    let Some(f) = fixture() else { return };
    let named: HashSet<u32> = f.w.burns[0].cells.iter().map(|c| c.index).collect();
    let token = f.w.token_cov_id;
    let other = f.w.burns[0].tx.outputs.iter().enumerate().position(|(i, o)| !named.contains(&(i as u32)) && o.covenant.map(|(_, c)| c) == Some(token));
    let Some(i) = other else {
        println!("{:<26} skipped: the burn tx has no other token output", "change_cell_as_burn");
        return;
    };
    let mut w = f.w.clone();
    let amount = w.burns[0].cells[0].amount;
    w.burns[0].cells = vec![BurnCell { index: i as u32, amount }];
    expect_refused("change_cell_as_burn", &w, "is not a burn cell of amount");
}

#[test]
fn another_tokens_id() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.token_cov_id[0] ^= 0x01;
    expect_refused("another_token", &w, "not the token's");
}

#[test]
fn duplicate_or_missing_cells() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let c = w.burns[0].cells[0];
    w.burns[0].cells.push(c);
    expect_refused("duplicate_cell", &w, "named twice");
    let mut w = f.w.clone();
    w.burns[0].cells.clear();
    expect_refused("no_cells", &w, "names no cells");
    let mut w = f.w.clone();
    w.burns[0].cells[0].index = w.burns[0].tx.outputs.len() as u32;
    expect_refused("cell_out_of_range", &w, "out of range");
}

/// Any change to the burn tx body (spk version, KAS value, covenant binding, payload) changes its id, which the
/// node's activity leaf pins: the reader never even runs on a rewritten transaction.
#[test]
fn rewritten_burn_output_changes_the_tx_id() {
    let Some(f) = fixture() else { return };
    let o = burn_cell_index(&f.w, 0);
    let mut w = f.w.clone();
    w.burns[0].tx.outputs[o].spk_version = 1;
    expect_refused("cell_spk_version_1", &w, "activity leaf tx id");
    let mut w = f.w.clone();
    w.burns[0].tx.outputs[o].value += 1;
    expect_refused("cell_kas_value", &w, "activity leaf tx id");
    let mut w = f.w.clone();
    w.burns[0].tx.outputs[o].covenant = None;
    expect_refused("cell_covenant_dropped", &w, "activity leaf tx id");
}

/// The embedded reference cell changed by one bit: the template the guest recomputes is not 9703112e…, and the
/// guest stops before reading the witness. (The guest only calls `run`; `run_with` exists for this case.)
#[test]
fn template_constant_tampered() {
    let Some(f) = fixture() else { return };
    let mut s = KCC20_SUFFIX.to_vec();
    s[1000] ^= 0x01;
    let input = f.w.encode();
    match catch_unwind(AssertUnwindSafe(|| relay::run_with::<SoftKeccak>(&input, KCC20_PREFIX, &s))).map_err(panic_msg) {
        Err(m) => {
            assert!(m.contains("reference cell template"), "panicked with {m:?}");
            println!("{:<26} refused: {m}", "template_tampered");
        }
        Ok(_) => panic!("a tampered reference cell was accepted"),
    }
}

// ------------------------------------------------------------------ three-step attestation (U4)

/// burnwitness counts a hop as joined when its header is a chain block (the node's `is_chain`); the guest when the
/// header's commitment is on the chain c_0 = B.aimr, c_i = H_seq(c_{i-1}, root_i). Every chain block in [B, T] has
/// its commitment there, so the guest's attesters include burnwitness's; a non-chain sibling with the same selected
/// parent and mergeset has the same commitment as a chain block and joins earlier in the guest (8.1 (1): such a
/// join proves the same statement). This case measures both hop histograms on the real paths, then removes the
/// last header of a deep path that has no earlier commitment join: exactly that path's attester is lost (when the
/// header serves no other path), never more, never a refusal.
#[test]
fn deep_attesters_are_counted() {
    let Some(f) = fixture() else { return };
    let (c0, a0) = level_entry(&f.base, CMP_LEVEL);
    if f.by_steps.len() == 3 {
        assert!(a0 >= f.by_steps.iter().sum::<u32>(), "the guest counts at least burnwitness's attesters");
        println!("{:<26} level {CMP_LEVEL}: guest {a0} attesting; burnwitness {} at hop 1 + {} at hop 2 + {} at hop 3 (by chain membership)", "deep_attesters", f.by_steps[0], f.by_steps[1], f.by_steps[2]);
    }
    // the guest's view: commitment of every header in the witness, and the commitment chain
    let aimr: std::collections::HashMap<Hash, Hash> = f.w.headers.iter().chain(f.w.y_headers.iter()).map(|hb| (hash_of(hb), aimr_of(hb))).collect();
    let mut chain: HashSet<Hash> = HashSet::new();
    let mut c = aimr_of(&f.w.headers[index_of(&f.w, &f.w.b)]);
    chain.insert(c);
    for r in &f.w.attest_roots {
        c = h_seq(&c, r);
        chain.insert(c);
    }
    let guest_hop = |path: &[Hash]| path.iter().position(|h| aimr.get(h).is_some_and(|a| chain.contains(a))).map(|i| i + 1);
    let mut hist = [0u32; 4];
    for p in &f.deep_paths {
        match guest_hop(p) {
            Some(k) if k <= 3 => hist[k] += 1,
            _ => hist[0] += 1,
        }
    }
    println!(
        "{:<26} {} deep paths (hop 2 or 3 by chain membership): the guest joins them at hop 1: {}, hop 2: {}, hop 3: {}, not at all: {}",
        "deep_attesters",
        f.deep_paths.len(),
        hist[1],
        hist[2],
        hist[3],
        hist[0]
    );
    assert_eq!(hist[0], 0, "every path burnwitness counted must attest in the guest too");
    // a path the guest also joins only at its last header; remove that header if no other path uses it
    let mut uses: std::collections::HashMap<Hash, u32> = std::collections::HashMap::new();
    for p in &f.deep_paths {
        for h in p {
            *uses.entry(*h).or_default() += 1;
        }
    }
    let ladder: HashSet<Hash> = f.w.headers.iter().map(|hb| hash_of(hb)).collect();
    let Some(path) = f.deep_paths.iter().find(|p| {
        let end = *p.last().unwrap();
        guest_hop(p) == Some(p.len()) && !ladder.contains(&end) && uses.get(&end) == Some(&1)
    }) else {
        println!("{:<26} skipped: every deep path also joins earlier by commitment, or shares its last header", "deep_path_header_removed");
        return;
    };
    let end = *path.last().unwrap();
    let mut w = f.w.clone();
    let before = w.y_headers.len();
    w.y_headers.retain(|hb| hash_of(hb) != end);
    assert_eq!(w.y_headers.len(), before - 1, "the deep path's chain block is a hash-only header");
    let j = expect_accepted("deep_path_header_removed", &w, |j| {
        let (c, a) = level_entry(j, CMP_LEVEL);
        assert_eq!(c, c0, "the superblock count must not move");
        assert!(a < a0, "attesting must drop ({a} vs {a0})");
    });
    let (_, a) = level_entry(&j, CMP_LEVEL);
    println!("{:<26} accepted, weaker: a {}-hop path's chain block removed, attesting {a0} -> {a}", "deep_path_header_removed", path.len());
}

/// The headers of the paths that reach the chain only at hop 4, added to the witness: the guest stops after three
/// hops, so the journal is unchanged.
#[test]
fn hop_four_join_does_not_attest() {
    let Some(f) = fixture() else { return };
    if f.late.is_empty() {
        println!("{:<26} skipped: no hop-4 joins in this witness ({} recorded)", "hop4_join", f.joins_late);
        return;
    }
    let mut w = f.w.clone();
    w.y_headers.extend(f.late.iter().cloned());
    // Twin commitments: a non-chain block with the same selected parent, an empty mergeset and the same context as a
    // chain block carries the same accepted_id_merkle_root, so by the guest's rule (commitment equality) it is on
    // the chain while burnwitness (hash membership) says it is not. A hop-4 path through such a block attests in the
    // guest once its headers are present (seen 2026-11-08 on witness out-s2: 274 -> 275). Sound: the commitment is
    // unpredictable before its chain block exists, so the timing bound of rule 4.1 holds through a twin. So: the
    // counts never change, attesting never drops, and it rises by at most the number of hop-4 paths.
    let (c0, a0) = level_entry(&f.base, CMP_LEVEL);
    let j = expect_accepted("hop4_join", &w, |j| {
        let (c, a) = level_entry(j, CMP_LEVEL);
        assert_eq!(c, c0, "a hop-4 join must not change the superblock count");
        assert!(a >= a0 && a - a0 <= f.joins_late, "attesting {a0} -> {a} with {} hop-4 paths added", f.joins_late);
    });
    let (_, a) = level_entry(&j, CMP_LEVEL);
    println!("{:<26} accepted: {} hop-4 header(s) added, {} superblock(s) join at hop 4, attesting {a0} -> {a}{}", "hop4_join", f.late.len(), f.joins_late,
        if a > a0 { format!(" ({} twin commitment(s) among the hop-4 paths: on the chain by commitment, not by hash)", a - a0) } else { String::new() });
}

// ------------------------------------------------------------------ headers and ladders (O5)

#[test]
fn duplicate_header() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let i = ladder_index(&w);
    w.headers.push(w.headers[i].clone());
    expect_refused("duplicate_header", &w, "is listed twice");
}

#[test]
fn missing_ladder_header_breaks_closure() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let i = ladder_index(&w);
    w.headers.remove(i);
    expect_refused("missing_ladder_header", &w, "is not in the witness");
}

#[test]
fn tampered_header_fails_pow() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let i = ladder_index(&w);
    let n = w.headers[i].len();
    w.headers[i][n - 1] ^= 0x01; // the pruning point: part of the preimage, so the hash and the PoW change
    expect_refused("tampered_header", &w, "fails proof of work");
}

/// The attestation cannot be rewired: pointing a superblock's first parent at B changes its hash, so its proof of
/// work no longer holds. An attester is a miner who spent 2^(31+L) hashes on that pointer.
#[test]
fn rewired_first_parent_fails_pow() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let i = ladder_index(&w);
    let p = verify_header::<SoftKeccak>(&w.headers[i], Stage::Parse).unwrap().parsed;
    let (a, _) = p.parents0;
    let b = w.b;
    w.headers[i][a..a + 32].copy_from_slice(&b);
    expect_refused("rewired_first_parent", &w, "fails proof of work");
}

/// v4: the ladder ends at B. The median difficulty reading (over the attesters, F15) sits inside the target range
/// of the top level's expanded superblocks and within the spread of B's own difficulty (an honest window).
#[test]
fn difficulty_reading_matches_the_ladder() {
    let Some(f) = fixture() else { return };
    let w = &f.w;
    let ib = index_of(w, &w.b);
    let bv = verify_header::<SoftKeccak>(&w.headers[ib], Stage::Full).unwrap();
    let mut pairs: Vec<(kaspa_prover_primitives::U256, u32)> = w
        .headers
        .iter()
        .map(|hb| verify_header::<SoftKeccak>(hb, Stage::Full).unwrap())
        .filter(|v| v.parsed.daa_score > bv.parsed.daa_score && v.level >= f.lmax)
        .map(|v| (v.target, v.parsed.bits))
        .collect();
    assert!(!pairs.is_empty());
    pairs.sort();
    let top_median = pairs[pairs.len() / 2].1;
    let rb = kaspa_prover_primitives::U256::from_compact_target_bits(f.base.r_bits);
    let (lo, hi) = (pairs[0].0, pairs[pairs.len() - 1].0);
    assert!(rb >= lo && rb <= hi, "the reading is inside the ladder's target range");
    let ratio = |a: &kaspa_prover_primitives::U256, b: &kaspa_prover_primitives::U256| (a.bits() as i64 - b.bits() as i64).abs();
    assert!(ratio(&rb, &bv.target) <= 1, "the reading is within a factor of 2 of B's own difficulty (bit length)");
    println!(
        "{:<26} r_bits 0x{:08x}; top-level median 0x{:08x} over {} superblocks; B's bits 0x{:08x}",
        "difficulty_reading", f.base.r_bits, top_median, pairs.len(), bv.parsed.bits
    );
}

#[test]
fn attested_block_missing() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.b = [0x5au8; 32];
    expect_refused("attested_block_missing", &w, "is not among the headers");
}

/// T must sit at the ladder's top level; a chain block below it (B usually is one) cannot play that role. B itself
/// need not be a superblock (v4). A tip at B is refused either way (nothing after B).
#[test]
fn tip_below_top_level_or_at_b() {
    let Some(f) = fixture() else { return };
    let bl = level_of(&f.w.headers[index_of(&f.w, &f.w.b)]);
    let mut w = f.w.clone();
    w.t = w.b;
    if bl >= f.lmax {
        expect_refused("t_at_b", &w, "does not come after B");
    } else {
        expect_refused("t_below_top_level", &w, "T is at level");
    }
}

#[test]
fn levels_must_ascend_and_be_present() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.levels = vec![CMP_LEVEL, CMP_LEVEL - 2];
    expect_refused("levels_unordered", &w, "strictly ascending");
}

// ------------------------------------------------------------------ attestation (O5)

/// A first-parent header rewritten so its commitment lands on the chain: its hash changes, so the path that ran
/// through it is broken; the attesters behind it are lost, nothing gained.
#[test]
fn tampered_first_parent_header_loses_attesters() {
    let Some(f) = fixture() else { return };
    if f.w.y_headers.is_empty() {
        println!("{:<26} skipped: no separate first-parent headers in this witness", "tampered_fp_header");
        return;
    }
    let mut w = f.w.clone();
    let b_aimr = aimr_of(&w.headers[index_of(&w, &w.b)]);
    let p = verify_header::<SoftKeccak>(&w.y_headers[0], Stage::Parse).unwrap().parsed;
    w.y_headers[0][p.ts_off - 64..p.ts_off - 32].copy_from_slice(&b_aimr);
    let (c0, a0) = level_entry(&f.base, CMP_LEVEL);
    let j = expect_accepted("tampered_fp_header", &w, |j| {
        let (c, a) = level_entry(j, CMP_LEVEL);
        assert_eq!(c, c0, "the superblock count must not move");
        assert!(a <= a0, "attesting must not grow ({a} vs {a0})");
    });
    let (_, a) = level_entry(&j, CMP_LEVEL);
    println!("{:<26} accepted, not stronger: attesting {a0} -> {a}", "tampered_fp_header");
}

#[test]
fn duplicate_first_parent_header() {
    let Some(f) = fixture() else { return };
    if f.w.y_headers.is_empty() {
        println!("{:<26} skipped: no separate first-parent headers in this witness", "duplicate_fp_header");
        return;
    }
    let mut w = f.w.clone();
    w.y_headers.push(w.y_headers[0].clone());
    expect_refused("duplicate_fp_header", &w, "is listed twice");
}

#[test]
fn first_parent_header_already_pow_verified() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let i = index_of(&w, &w.b);
    w.y_headers.push(w.headers[i].clone());
    expect_refused("fp_header_in_pow_set", &w, "already a PoW-verified header");
}

/// One wrong state root in the attestation chain: every commitment after it is garbage, so every attester whose
/// path joins after that point stops attesting. The chain cannot be patched; it can only be shortened.
#[test]
fn wrong_attestation_root_loses_attesters() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let n = w.attest_roots.len();
    if n < 2 {
        println!("{:<26} skipped: attestation chain has {n} root(s)", "wrong_attest_root");
        return;
    }
    w.attest_roots[n / 2][0] ^= 0x01;
    let (c0, a0) = level_entry(&f.base, CMP_LEVEL);
    let j = expect_accepted("wrong_attest_root", &w, |j| {
        let (c, a) = level_entry(j, CMP_LEVEL);
        assert_eq!(c, c0);
        assert!(a < a0, "attesting must drop ({a} vs {a0})");
    });
    let (_, a) = level_entry(&j, CMP_LEVEL);
    println!("{:<26} accepted, weaker: attesting {a0} -> {a} (root {} of {n} flipped)", "wrong_attest_root", n / 2);
}

/// An honest prover who did not wait for depth: the chain after B cut short until fewer than MIN_ATTEST attest.
/// The guest proves it; the contract refuses it ("not enough attestation"). The journal is written for mainnet.
#[test]
fn thin_attestation_is_a_valid_but_refused_journal() {
    let Some(f) = fixture() else { return };
    let (c0, a0) = level_entry(&f.base, CMP_LEVEL);
    let mut keep = f.w.attest_roots.len();
    let mut w = f.w.clone();
    loop {
        keep /= 2;
        w.attest_roots.truncate(keep);
        let j = run_native(&w).expect("a shortened attestation chain is a valid witness");
        let (c, a) = level_entry(&j, CMP_LEVEL);
        assert_eq!(c, c0);
        assert!(a <= a0);
        if a < MIN_ATTEST || keep == 0 {
            break;
        }
    }
    let j = expect_accepted("thin_attestation", &w, |j| {
        let (c, a) = level_entry(j, CMP_LEVEL);
        assert_eq!(c, c0);
        assert!(a < MIN_ATTEST, "could not get below MIN_ATTEST by truncation (attesting {a})");
    });
    let (c, a) = level_entry(&j, CMP_LEVEL);
    println!("{:<26} accepted, weaker: {keep} of {} roots kept, level {CMP_LEVEL} {c} superblocks, attesting {a0} -> {a} < {MIN_ATTEST}: the contract refuses it", "thin_attestation", f.w.attest_roots.len());
    write_journal("thin_attestation", &j);
}

/// No attestation data at all: only superblocks whose path runs through PoW-verified headers can attest. On a real
/// ladder none does within three hops without the first-parent headers, so there is no attester and, since the
/// 11-08 review (F15: the difficulty reading is over the attesters), no reading: the guest refuses the witness
/// instead of producing a journal the relay would refuse.
#[test]
fn no_attestation_data() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.y_headers.clear();
    w.attest_roots.clear();
    expect_refused("no_attestation", &w, "no attesting superblock");
}

// ------------------------------------------------------------------ B: real non-chain, forged (O5)

/// A real block that is not on the selected chain, taken from a chain block's mergeset, as B. Its commitment is
/// its own (relative to its selected parent), so the burn's commitment chain, built from the node's data, cannot
/// end at it: the only data that would is the state root of that block, which only its miner holds.
#[test]
fn real_nonchain_block_as_b() {
    let Some(f) = fixture() else { return };
    if f.extra_nonchain.is_empty() {
        println!("{:<26} skipped: no extra non-chain headers (burnwitness --extra-nonchain N)", "real_nonchain_b");
        return;
    }
    for (n, (h, pre, sp_chain)) in f.extra_nonchain.iter().enumerate() {
        let mut w = f.w.clone();
        w.headers.push(pre.clone());
        w.b = *h;
        expect_refused(&format!("real_nonchain_b[{n}]"), &w, "sequencing commitment chain ends at");
        println!("{:<26} block {} (level {}, selected parent on the chain: {sp_chain})", format!("real_nonchain_b[{n}]"), &relay::hx(h)[..16], level_of(pre));
    }
}

/// The attack v1 closed, re-run on v2 and v4. A forged B' whose commitment "accepts" the burn: aimr(B') =
/// H_seq(aimr(B), r) for a root r of the attacker's choosing, the burn's chain extended by r. B' passes proof of work
/// (at the easiest target, for free) and the burn chains to it. What the attacker cannot forge is the attestation,
/// at any hop: no honest superblock's first-parent path reaches a commitment that descends from aimr(B'), so there
/// is no attester. Since the 11-08 review (F15) the difficulty reading is taken over the attesters, so the guest
/// itself refuses the witness; before, it produced a journal with attesting 0 that the contract refused.
#[test]
fn forged_b_gets_no_attesters() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let ib = index_of(&w, &w.b);
    let b_aimr = aimr_of(&w.headers[ib]);
    let b_daa = verify_header::<SoftKeccak>(&w.headers[ib], Stage::Parse).unwrap().parsed.daa_score;
    let fake_root: Hash = [0x42u8; 32];
    let forged_aimr = h_seq(&b_aimr, &fake_root);
    let forged = forge_header(&w.b, &forged_aimr, b_daa + 1);
    let forged_hash = hash_of(&forged);
    w.headers.push(forged);
    w.b = forged_hash;
    for bn in &mut w.burns {
        bn.chain_state_roots.push(fake_root);
    }
    w.attest_roots.clear();
    w.y_headers.clear();
    let (c0, a0) = level_entry(&f.base, CMP_LEVEL);
    expect_refused("forged_b", &w, "no attesting superblock");
    println!("{:<26} B' {} (forged, level {}) chains the burn but has no attester among the honest ladder's {c0} superblocks ({a0} attest B): no reading, refused", "forged_b", &relay::hx(&forged_hash)[..16], level_of(&w.headers[w.headers.len() - 1]));
}

// ------------------------------------------------------------------ burns (O5, on cells)

#[test]
fn wrong_target_changes_the_tx_id() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.burns[0].tx.payload[5] ^= 0x01; // first byte of the target
    expect_refused("wrong_target", &w, "activity leaf tx id");
}

#[test]
fn tampered_tip_changes_the_tx_id() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.burns[0].tx.payload[32] ^= 0x01; // low byte of the tip
    expect_refused("tampered_tip", &w, "activity leaf tx id");
}

#[test]
fn tampered_recipient_changes_the_tx_id() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.burns[0].tx.payload[52] ^= 0x01; // last byte of the recipient
    expect_refused("tampered_recipient", &w, "activity leaf tx id");
}

#[test]
fn duplicate_burn() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.burns.push(w.burns[0].clone());
    expect_refused("duplicate_burn", &w, "appears twice");
}

#[test]
fn wrong_chain_state_root() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    let n = w.burns[0].chain_state_roots.len();
    if n == 0 {
        // C == B: the chain is empty; fake one step instead
        w.burns[0].chain_state_roots.push([0x42u8; 32]);
    } else {
        w.burns[0].chain_state_roots[n - 1][0] ^= 0x01;
    }
    expect_refused("wrong_chain_root", &w, "sequencing commitment chain ends at");
}

#[test]
fn burn_count_bounds() {
    let Some(f) = fixture() else { return };
    let mut w = f.w.clone();
    w.burns.clear();
    expect_refused("no_burns", &w, &format!("1 to {MAX_BURNS} burns"));
    let mut w = f.w.clone();
    while w.burns.len() <= MAX_BURNS {
        w.burns.push(w.burns[0].clone());
    }
    expect_refused("seventeen_burns", &w, &format!("1 to {MAX_BURNS} burns"));
}
