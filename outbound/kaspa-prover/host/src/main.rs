//! kaspa-prover: host for the Kaspa header guest (outbound study, E1) and the relay guest (O1, v1).
//!
//!   kaspa-prover check   --vectors kpow/sol/vectors.json              # native: every stage against rusty-kaspa's values
//!   kaspa-prover execute --vectors V [--count N] [--stage full] [--soft-keccak] [--no-link]   # one dev-mode run
//!   kaspa-prover sweep   --vectors V [--counts 0,1,2,4,...] --out e1-results.json            # the E1 table
//!   kaspa-prover relay   --witness burnwitness/witness.json [--levels 30,32] [--soft-keccak] [--native-only]
//!                        [--no-attest] [--out-input relay-input.bin]
//!                                                                     # O1/v1: native check, then dev-mode execution
//!   kaspa-prover prove   --input relay-input.bin --out DIR [--no-wrap] # O2: real receipt of the relay guest (GPU image)
//!   kaspa-prover wrap    --receipt DIR/receipt.succinct.bin --out DIR  # O2: Groth16-wrap a succinct receipt (Docker)
//!   kaspa-prover verify  --bundle DIR                                  # O2: check a Groth16 bundle against the relay image id; writes eth-seal.hex
//!   kaspa-prover journal --file DIR/journal.hex                        # decode a relay journal
//!   kaspa-prover ids                                                   # image ids of both guests
//!   cargo test --release -p kaspa-prover-host -- adversarial          # O5: adversarial witnesses (src/adversarial.rs)
//!
//! Vectors come from `outbound/kpow/vectors` (rusty-kaspa v2.1.0 reading real headers from a node and
//! recording every intermediate value). The native check runs the exact code the guest runs
//! (`kaspa_prover_primitives`) against those values, so a guest journal that matches the native
//! result is a journal that matches rusty-kaspa. The relay witness comes from `outbound/burnwitness`
//! (rusty-kaspa crates), which records the node's own values for every intermediate hash.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use kaspa_prover_methods::{KASPA_HEADER_GUEST_ELF, KASPA_HEADER_GUEST_ID, KASPA_RELAY_GUEST_ELF, KASPA_RELAY_GUEST_ID};
use kaspa_prover_primitives::relay;
use kaspa_prover_primitives::{
    direct_parents, encode_input, run, verify_header, Journal, SoftKeccak, Stage, U256, MAX_BLOCK_LEVEL,
};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_executor, default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(about = "Kaspa header verifier in the RISC Zero zkVM (outbound study E1, relay O1/v1)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the verifier natively on every vector and compare each stage with rusty-kaspa's values.
    Check {
        #[arg(long)]
        vectors: PathBuf,
    },
    /// One dev-mode execution of the guest; prints cycles and checks the journal against the native run.
    Execute {
        #[arg(long)]
        vectors: PathBuf,
        /// Number of headers (first N in chain order). Default: all.
        #[arg(long)]
        count: Option<usize>,
        /// parse | hash | powhash | full
        #[arg(long, default_value = "full")]
        stage: String,
        /// Use the software keccak-f in the guest instead of the zkVM keccak accelerator.
        #[arg(long)]
        soft_keccak: bool,
        /// Do not require each header to be a direct parent of the next.
        #[arg(long)]
        no_link: bool,
    },
    /// The E1 measurement: full verification at several counts (marginal cycles per header), each
    /// stage at the full count (cost breakdown), and the software-keccak comparison.
    Sweep {
        #[arg(long)]
        vectors: PathBuf,
        #[arg(long, default_value = "0,1,2,4,8,16,32,64,128")]
        counts: String,
        /// Also run every count with the software keccak path (slow; default runs it once at the largest count).
        #[arg(long)]
        soft_all: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// O1/v1: verify a burnwitness witness natively (every intermediate against the node's values),
    /// then execute the relay guest in dev mode and report cycles.
    Relay {
        #[arg(long)]
        witness: PathBuf,
        /// Subset of the witness's ladder levels to prove (ascending). Default: all levels in the witness.
        #[arg(long)]
        levels: Option<String>,
        #[arg(long)]
        soft_keccak: bool,
        /// Stop after the native check (no zkVM execution).
        #[arg(long)]
        native_only: bool,
        /// Measurement only (v1 to v3): drop the first-parent headers and the attestation chain from the input.
        /// Since KZO6 the guest refuses a witness without attesters (no difficulty reading), so the native run
        /// stops with that message; kept for the record.
        #[arg(long)]
        no_attest: bool,
        /// Write the encoded guest input frame here (for `prove` later).
        #[arg(long)]
        out_input: Option<PathBuf>,
        /// The Ethereum address the relay pays this proof's tips to (0x + 40 hex). In the journal (KZO6, F16).
        #[arg(long)]
        prover: String,
    },
    /// O2: prove the relay guest on the input frame written by `relay --out-input` and write the bundle
    /// (image_id.hex, journal.hex, journal_hash.hex, timing.txt, and receipt.hex or receipt.succinct.bin).
    Prove {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "out")]
        out: PathBuf,
        /// Stop at the succinct STARK receipt (no Docker needed); `wrap` turns it into Groth16 later.
        #[arg(long)]
        no_wrap: bool,
    },
    /// Groth16-wrap a succinct receipt saved by `prove --no-wrap` (r0vm + Docker on a CPU box).
    Wrap {
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long, default_value = "out")]
        out: PathBuf,
    },
    /// Verify a Groth16 bundle (receipt.hex + journal.hex) against this build's relay image id, or `--image-id`.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        image_id: Option<String>,
    },
    /// Decode a relay journal (journal.hex or raw bytes).
    Journal {
        #[arg(long)]
        file: PathBuf,
    },
    /// Print the guest image ids.
    Ids,
    /// Write synthetic, parent-linked headers in vectors.json format (values computed by this crate,
    /// so only the plumbing is tested; PoW does not pass on them). For a box without a node.
    Synth {
        #[arg(long, default_value = "8")]
        count: usize,
        #[arg(long)]
        out: PathBuf,
    },
}

// ---------------------------------------------------------------------------------------------
// vectors.json (kpow)
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    source: Option<String>,
    preimages: Vec<String>,
    hashes: Vec<String>,
    pre_pows: Vec<String>,
    pow_hashes: Vec<String>,
    matrices: Vec<String>,
    pows: Vec<String>,
    levels: Vec<u64>,
    attempts: Vec<u64>,
    passed: Vec<u64>,
}

pub(crate) fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| anyhow!("bad hex: {e}"))
}

pub(crate) fn unhex32(s: &str) -> Result<[u8; 32]> {
    let v = unhex(s)?;
    v.as_slice().try_into().map_err(|_| anyhow!("expected 32 bytes, got {}", v.len()))
}

struct Loaded {
    /// preimages in chain order (oldest first)
    headers: Vec<Vec<u8>>,
    /// index into the vectors arrays for each chain-order position
    idx: Vec<usize>,
    linked: bool,
    v: Vectors,
}

fn load(path: &PathBuf) -> Result<Loaded> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: Vectors = serde_json::from_str(&text).context("parsing vectors.json")?;
    let n = v.preimages.len();
    if n == 0 {
        bail!("no vectors");
    }
    let pre: Vec<Vec<u8>> = v.preimages.iter().map(|s| unhex(s)).collect::<Result<_>>()?;
    let parsed: Vec<_> = pre.iter().map(|b| verify_header::<SoftKeccak>(b, Stage::Hash)).collect::<std::result::Result<_, _>>().map_err(|e| anyhow!("preimage does not parse: {e:?}"))?;
    // Order: ascending means pre[i] is a direct parent of pre[i+1]; descending the reverse.
    let is_parent = |child: usize, parent: usize| direct_parents(&pre[child], &parsed[child].parsed).any(|p| p == parsed[parent].hash);
    let asc = (0..n - 1).all(|i| is_parent(i + 1, i));
    let desc = (0..n - 1).all(|i| is_parent(i, i + 1));
    let (idx, linked): (Vec<usize>, bool) = if asc {
        ((0..n).collect(), true)
    } else if desc {
        ((0..n).rev().collect(), true)
    } else {
        eprintln!("warning: vectors are not a parent-linked chain in either direction; link checks disabled");
        ((0..n).collect(), false)
    };
    let headers = idx.iter().map(|&i| pre[i].clone()).collect();
    Ok(Loaded { headers, idx, linked, v })
}

// ---------------------------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------------------------

fn same_or_reversed(got: &[u8; 32], want: &[u8; 32]) -> Option<&'static str> {
    if got == want {
        Some("as is")
    } else {
        let mut r = *got;
        r.reverse();
        if &r == want { Some("reversed") } else { None }
    }
}

fn check(path: &PathBuf) -> Result<()> {
    let l = load(path)?;
    let v = &l.v;
    let n = v.preimages.len();
    println!("vectors       : {} headers from {}", n, v.source.as_deref().unwrap_or("?"));
    println!("order         : {}", if !l.linked { "not chain-linked" } else if l.idx[0] == 0 { "ascending (oldest first)" } else { "descending (newest first), reversed for the guest" });
    let mut sizes = Vec::new();
    let mut hist: BTreeMap<u32, usize> = BTreeMap::new();
    let mut orders: BTreeMap<&str, &str> = BTreeMap::new();
    let mut matrix_unknown = 0usize;
    // per header, in vector order: (level, timestamp, daa_score, blue_score, blue_work as f64, own work from target)
    let mut rows: Vec<(u32, u64, u64, u64, f64, f64)> = Vec::with_capacity(n);
    for i in 0..n {
        let b = unhex(&v.preimages[i])?;
        if v.attempts[i] != 1 {
            bail!("vector {i}: rusty-kaspa needed {} matrix attempts; this verifier only uses the first matrix", v.attempts[i]);
        }
        let r = verify_header::<SoftKeccak>(&b, Stage::Full).map_err(|e| anyhow!("vector {i}: parse error {e:?}"))?;
        sizes.push(b.len());
        let want_hash = unhex32(&v.hashes[i])?;
        let o = same_or_reversed(&r.hash, &want_hash).ok_or_else(|| anyhow!("vector {i}: block hash mismatch: got {} want {}", hex::encode(r.hash), hex::encode(want_hash)))?;
        orders.insert("hashes", o);
        let want = unhex32(&v.pre_pows[i])?;
        let o = same_or_reversed(&r.pre_pow, &want).ok_or_else(|| anyhow!("vector {i}: pre_pow_hash mismatch: got {} want {}", hex::encode(r.pre_pow), hex::encode(want)))?;
        orders.insert("prePows", o);
        let want = unhex32(&v.pow_hashes[i])?;
        let o = same_or_reversed(&r.pow_hash, &want).ok_or_else(|| anyhow!("vector {i}: pow hash mismatch: got {} want {}", hex::encode(r.pow_hash), hex::encode(want)))?;
        orders.insert("powHashes", o);
        // pow / level / passed first: if these match, the matrix is right whatever the vector's packing
        let want_pow = unhex32(&v.pows[i])?;
        let pow_o = if r.pow.to_be_bytes() == want_pow { "Uint256 big-endian" } else if U256::from_le_bytes(&want_pow) == r.pow { "hash bytes (LE)" } else {
            bail!("vector {i}: pow mismatch: got {} want {}", hex::encode(r.pow.to_be_bytes()), hex::encode(want_pow));
        };
        // matrix: 64 rows of 32 bytes; the vector's nibble packing is not documented, so try the four
        // natural ones (byte order x nibble order). A row that matches none is only an encoding question
        // once pow matched above (the heavy hash is a keccak over the product, so a wrong matrix cannot pass).
        let m = kaspa_prover_primitives::gen_matrix(&r.pre_pow);
        let want_m = unhex(&v.matrices[i])?;
        if want_m.len() != 2048 {
            bail!("vector {i}: matrix blob is {} bytes, expected 2048", want_m.len());
        }
        let pack = |hi_first: bool, reverse_bytes: bool| -> Vec<u8> {
            let mut out = Vec::with_capacity(2048);
            for row in m.iter() {
                let mut rb = [0u8; 32];
                for k in 0..32 {
                    let (a, b2) = (row[2 * k], row[2 * k + 1]);
                    rb[k] = if hi_first { (a << 4) | b2 } else { (b2 << 4) | a };
                }
                if reverse_bytes { rb.reverse(); }
                out.extend_from_slice(&rb);
            }
            out
        };
        let o = if pack(true, false) == want_m { "nibble 2k high, bytes in order" }
            else if pack(false, false) == want_m { "nibble 2k low, bytes in order" }
            else if pack(true, true) == want_m { "nibble 2k high, bytes reversed" }
            else if pack(false, true) == want_m { "nibble 2k low, bytes reversed" }
            else { matrix_unknown += 1; "unrecognized packing (pow matched, so the matrix itself is right)" };
        orders.insert("matrices", o);
        orders.insert("pows", pow_o);
        if r.level as u64 != v.levels[i] {
            bail!("vector {i}: level {} != {}", r.level, v.levels[i]);
        }
        if (r.passed as u64) != v.passed[i] {
            bail!("vector {i}: passed {} != {}", r.passed, v.passed[i]);
        }
        *hist.entry(r.level).or_default() += 1;
        let bw = r.parsed.blue_work.iter().fold(0f64, |acc, &b| acc * 256.0 + b as f64);
        let t = r.target.0.iter().enumerate().fold(0f64, |acc, (k, &w)| acc + (w as f64) * 2f64.powi(64 * k as i32));
        rows.push((r.level, r.parsed.timestamp, r.parsed.daa_score, r.parsed.blue_score, bw, 2f64.powi(256) / (t + 1.0)));
    }
    println!("all stages    : {} of {} headers equal the vectors (block hash, pre_pow_hash, pow hash, pow, level, passed{})", n, n, if matrix_unknown == 0 { ", matrix rows" } else { "" });
    if matrix_unknown > 0 {
        println!("matrix rows   : the vector's row packing matched none of the four candidates for {matrix_unknown} headers; pow matched for all, so the matrix is correct and only the dump format is undocumented (row 0 of header 0 shown below)");
        let r0 = verify_header::<SoftKeccak>(&unhex(&v.preimages[0])?, Stage::Full).unwrap();
        let m0 = kaspa_prover_primitives::gen_matrix(&r0.pre_pow);
        println!("  ours (nibbles 0..63): {}", m0[0].iter().map(|x| format!("{x:x}")).collect::<String>());
        println!("  vector row 0        : {}", &v.matrices[0][..66.min(v.matrices[0].len())]);
    }
    println!("vector encodings seen: {}", orders.iter().map(|(k, o)| format!("{k}: {o}")).collect::<Vec<_>>().join(", "));
    println!("header bytes  : min {} / avg {} / max {}", sizes.iter().min().unwrap(), sizes.iter().sum::<usize>() / n, sizes.iter().max().unwrap());
    println!("block levels  : {}", hist.iter().map(|(l, c)| format!("{l}:{c}")).collect::<Vec<_>>().join("  "));
    println!("max_block_level {} ; level = max({} - bitlen(pow), 0)", MAX_BLOCK_LEVEL, MAX_BLOCK_LEVEL);
    if n > 1 {
        summary(&l.idx, &rows);
    }
    Ok(())
}

/// What the headers say about the window they span and how well superblock counts estimate its work.
fn summary(idx: &[usize], rows: &[(u32, u64, u64, u64, f64, f64)]) {
    let first = &rows[idx[0]];
    let last = &rows[*idx.last().unwrap()];
    let n = rows.len() as f64;
    let span_s = (last.1 as f64 - first.1 as f64) / 1000.0;
    let d_daa = last.2 as f64 - first.2 as f64;
    let d_blue = last.3 as f64 - first.3 as f64;
    let d_work = last.4 - first.4;
    let chain_work: f64 = rows.iter().map(|r| r.5).sum();
    println!();
    println!("== window from the headers (chain order) ==");
    println!("time span     : {:.0} s ({:.2} h) from timestamp {} to {}", span_s, span_s / 3600.0, first.1, last.1);
    println!("chain blocks  : {} ({:.2} per s)", rows.len(), n / span_s.max(1.0));
    println!("daa_score     : +{:.0} ({:.2} per s; ~all DAG blocks in the window)", d_daa, d_daa / span_s.max(1.0));
    println!("blue_score    : +{:.0} ({:.2} per s; blue blocks merged by the chain)", d_blue, d_blue / span_s.max(1.0));
    println!("blue_work     : +{:.4e} hashes claimed by the headers over the window", d_work);
    println!("chain work    : {:.4e} hashes = sum over chain blocks of 2^256/(target+1); {:.1}% of blue_work (E2, selected chain only)", chain_work, 100.0 * chain_work / d_work.max(1.0));
    println!("per block     : {:.3e} expected hashes at the current target (log2 {:.2})", chain_work / n, (chain_work / n).log2());
    println!();
    println!("== superblock estimator on the chain blocks: blocks at level >= L, times 2^(31+L) expected hashes each ==");
    println!("{:>5} {:>8} {:>10} {:>14} {:>12}", "level", "at L", "at >= L", "est. hashes", "/ chain work");
    let mut levels: Vec<u32> = rows.iter().map(|r| r.0).collect();
    levels.sort_unstable();
    levels.dedup();
    for &lv in &levels {
        let at = rows.iter().filter(|r| r.0 == lv).count();
        let cum = rows.iter().filter(|r| r.0 >= lv).count();
        let est = cum as f64 * 2f64.powi(31 + lv as i32);
        println!("{:>5} {:>8} {:>10} {:>14.3e} {:>12.3}", lv, at, cum, est, est / chain_work);
    }
    println!("(a sound estimator reads ~1.0 at every level from the base level up; a level below the base reads 2^(225-L)/target < 1");
    println!(" because every valid block is already at or above it; the spread at the top is the luck of few blocks)");
}

// ---------------------------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------------------------

fn parse_stage(s: &str) -> Result<Stage> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "parse" | "0" => Stage::Parse,
        "hash" | "1" => Stage::Hash,
        "powhash" | "2" => Stage::PowHash,
        "full" | "3" => Stage::Full,
        _ => bail!("stage must be parse | hash | powhash | full"),
    })
}

#[derive(Clone, Debug, serde::Serialize)]
struct RunResult {
    count: usize,
    stage: String,
    soft_keccak: bool,
    link: bool,
    input_bytes: usize,
    segments: usize,
    user_cycles: u64,
    padded_cycles: u64,
    seconds: f64,
}

fn execute_once(headers: &[Vec<u8>], stage: Stage, soft_keccak: bool, link: bool, quiet: bool) -> Result<RunResult> {
    let input = encode_input(stage, link, soft_keccak, headers);
    let expect = run::<SoftKeccak>(&input);
    let env = ExecutorEnv::builder().write_frame(&input).build()?;
    let t0 = Instant::now();
    let info = default_executor().execute(env, KASPA_HEADER_GUEST_ELF)?;
    let secs = t0.elapsed().as_secs_f64();
    let user: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded: u64 = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    let j = Journal::decode(&info.journal.bytes).ok_or_else(|| anyhow!("journal is {} bytes, expected {}", info.journal.bytes.len(), kaspa_prover_primitives::JOURNAL_LEN))?;
    if j != expect {
        bail!("guest journal differs from the native run:\n guest  {:?}\n native {:?}", j, expect);
    }
    let r = RunResult {
        count: headers.len(),
        stage: format!("{stage:?}").to_lowercase(),
        soft_keccak,
        link,
        input_bytes: input.len(),
        segments: info.segments.len(),
        user_cycles: user,
        padded_cycles: padded,
        seconds: secs,
    };
    if !quiet {
        println!("headers       : {} ({} input bytes), stage {}, keccak {}, links {}", r.count, r.input_bytes, r.stage, if soft_keccak { "software" } else { "accelerated" }, if link { "checked" } else { "not checked" });
        println!("executed in   : {:.1} s", secs);
        println!("segments      : {}", r.segments);
        println!("user cycles   : {user}");
        println!("padded cycles : {padded} (sum of 2^po2 per segment; what proving pays for)");
        if r.count > 0 {
            println!("per header    : {} user cycles (total / n; includes the fixed overhead)", user / r.count as u64);
        }
        println!("journal       : n {} first {} last {} levels {}..{}", j.n, hex::encode(j.first), hex::encode(j.last), j.min_level, j.max_level);
        if stage == Stage::Full {
            let h: Vec<String> = j.hist.iter().enumerate().filter(|(_, c)| **c > 0).map(|(l, c)| format!("{l}:{c}")).collect();
            println!("level hist    : {}", h.join("  "));
        }
        println!("journal matches the native run");
    }
    Ok(r)
}

fn execute(vectors: &PathBuf, count: Option<usize>, stage: &str, soft_keccak: bool, no_link: bool) -> Result<()> {
    let l = load(vectors)?;
    let n = count.unwrap_or(l.headers.len()).min(l.headers.len());
    println!("image id      : {}", hex::encode(Digest::from(KASPA_HEADER_GUEST_ID).as_bytes()));
    execute_once(&l.headers[..n], parse_stage(stage)?, soft_keccak, l.linked && !no_link, false)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// sweep
// ---------------------------------------------------------------------------------------------

fn lsq_slope(points: &[(f64, f64)]) -> (f64, f64) {
    let n = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let intercept = (sy - slope * sx) / n;
    (slope, intercept)
}

fn sweep(vectors: &PathBuf, counts: &str, soft_all: bool, out: Option<PathBuf>) -> Result<()> {
    let l = load(vectors)?;
    let max = l.headers.len();
    let mut counts: Vec<usize> = counts.split(',').map(|s| s.trim().parse::<usize>()).collect::<std::result::Result<_, _>>()?;
    counts.retain(|&c| c <= max);
    if !counts.contains(&max) {
        counts.push(max);
    }
    counts.sort_unstable();
    counts.dedup();
    let image = hex::encode(Digest::from(KASPA_HEADER_GUEST_ID).as_bytes());
    println!("image id      : {image}");
    println!("vectors       : {} headers, links {}", max, if l.linked { "checked" } else { "not checked" });
    let mut results: Vec<RunResult> = Vec::new();

    println!("\n== full verification, accelerated keccak, by count ==");
    println!("{:>7} {:>9} {:>14} {:>14} {:>12} {:>8}", "headers", "segments", "user cycles", "padded cycles", "per header", "seconds");
    for &c in &counts {
        let r = execute_once(&l.headers[..c], Stage::Full, false, l.linked, true)?;
        println!("{:>7} {:>9} {:>14} {:>14} {:>12} {:>8.1}", c, r.segments, r.user_cycles, r.padded_cycles, if c > 0 { r.user_cycles / c as u64 } else { 0 }, r.seconds);
        results.push(r);
    }
    let pts: Vec<(f64, f64)> = results.iter().filter(|r| r.count >= 1).map(|r| (r.count as f64, r.user_cycles as f64)).collect();
    let (slope, intercept) = lsq_slope(&pts);
    let overhead = results.iter().find(|r| r.count == 0).map(|r| r.user_cycles);
    println!("marginal cost : {:.0} user cycles per header (least squares over counts >= 1), intercept {:.0}", slope, intercept);
    if let Some(o) = overhead {
        println!("fixed cost    : {o} user cycles with zero headers (program setup)");
    }
    if let (Some(a), Some(b)) = (results.iter().rev().nth(1), results.last()) {
        if b.count > a.count {
            println!("last interval : {} user cycles per header between {} and {} headers", (b.user_cycles - a.user_cycles) / (b.count - a.count) as u64, a.count, b.count);
        }
    }

    println!("\n== cost by stage at {} headers (each stage includes the ones before it) ==", max);
    println!("{:>9} {:>14} {:>14} {:>14}", "stage", "user cycles", "per header", "delta/header");
    let mut prev: Option<u64> = None;
    let mut stage_cycles: BTreeMap<String, u64> = BTreeMap::new();
    for st in [Stage::Parse, Stage::Hash, Stage::PowHash, Stage::Full] {
        let r = execute_once(&l.headers, st, false, l.linked, true)?;
        let per = r.user_cycles / max as u64;
        let delta = prev.map(|p| (r.user_cycles.saturating_sub(p)) / max as u64);
        println!("{:>9} {:>14} {:>14} {:>14}", r.stage, r.user_cycles, per, delta.map(|d| d.to_string()).unwrap_or_else(|| "-".into()));
        prev = Some(r.user_cycles);
        stage_cycles.insert(r.stage.clone(), r.user_cycles);
        results.push(r);
    }

    println!("\n== software keccak-f (no accelerator), full verification ==");
    let soft_counts: Vec<usize> = if soft_all { counts.clone() } else { vec![max] };
    for &c in &soft_counts {
        let r = execute_once(&l.headers[..c], Stage::Full, true, l.linked, true)?;
        let accel = results.iter().find(|x| x.count == c && x.stage == "full" && !x.soft_keccak).map(|x| x.user_cycles).unwrap_or(0);
        println!("{:>7} headers: {} user cycles ({} per header); accelerated was {} ({} per header); the two keccak-f cost {} per header in software vs {} accelerated",
            c, r.user_cycles, if c > 0 { r.user_cycles / c as u64 } else { 0 }, accel, if c > 0 { accel / c as u64 } else { 0 },
            if c > 0 { (r.user_cycles.saturating_sub(stage_cycles["hash"] * c as u64 / max as u64)) / c as u64 } else { 0 },
            if c > 0 { (accel.saturating_sub(stage_cycles["hash"] * c as u64 / max as u64)) / c as u64 } else { 0 });
        results.push(r);
    }

    if let Some(out) = out {
        let doc = serde_json::json!({
            "image_id": image,
            "vectors": vectors.display().to_string(),
            "headers": max,
            "links_checked": l.linked,
            "marginal_user_cycles_per_header": slope,
            "intercept": intercept,
            "runs": results,
        });
        std::fs::write(&out, serde_json::to_string_pretty(&doc)?)?;
        println!("\nwrote {}", out.display());
    }
    Ok(())
}

fn synth(count: usize, out: &PathBuf) -> Result<()> {
    // xorshift so the file is reproducible
    let mut x = 0x9E3779B97F4A7C15u64;
    let mut rnd = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let mut prev: [u8; 32] = [0u8; 32];
    let (mut pre, mut hashes, mut pre_pows, mut pow_hashes, mut matrices, mut pows, mut levels, mut passed) =
        (vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![]);
    for i in 0..count {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_le_bytes());
        let n_levels = 3 + (rnd() % 4);
        b.extend_from_slice(&n_levels.to_le_bytes());
        for lvl in 0..n_levels {
            let k = if lvl == 0 { 1 + rnd() % 3 } else { 1 };
            b.extend_from_slice(&k.to_le_bytes());
            for j in 0..k {
                if lvl == 0 && j == 0 { b.extend_from_slice(&prev); } else { for _ in 0..4 { b.extend_from_slice(&rnd().to_le_bytes()); } }
            }
        }
        for _ in 0..12 { b.extend_from_slice(&rnd().to_le_bytes()); } // three roots
        b.extend_from_slice(&(1_700_000_000_000u64 + i as u64 * 100).to_le_bytes());
        b.extend_from_slice(&0x1d00ffffu32.to_le_bytes());
        b.extend_from_slice(&rnd().to_le_bytes()); // nonce
        b.extend_from_slice(&(1000 + i as u64).to_le_bytes());
        b.extend_from_slice(&(2000 + i as u64).to_le_bytes());
        let bw = (rnd() >> 20).to_be_bytes();
        let start = bw.iter().position(|&c| c != 0).unwrap_or(8);
        b.extend_from_slice(&((8 - start) as u64).to_le_bytes());
        b.extend_from_slice(&bw[start..]);
        for _ in 0..4 { b.extend_from_slice(&rnd().to_le_bytes()); } // pruning point
        let r = verify_header::<SoftKeccak>(&b, Stage::Full).map_err(|e| anyhow!("{e:?}"))?;
        let m = kaspa_prover_primitives::gen_matrix(&r.pre_pow);
        let mut mb = Vec::with_capacity(2048);
        for row in m.iter() { for k in 0..32 { mb.push((row[2 * k] << 4) | row[2 * k + 1]); } }
        pre.push(format!("0x{}", hex::encode(&b)));
        hashes.push(format!("0x{}", hex::encode(r.hash)));
        pre_pows.push(format!("0x{}", hex::encode(r.pre_pow)));
        pow_hashes.push(format!("0x{}", hex::encode(r.pow_hash)));
        matrices.push(format!("0x{}", hex::encode(&mb)));
        pows.push(format!("0x{}", hex::encode(r.pow.to_be_bytes())));
        levels.push(r.level);
        passed.push(r.passed as u64);
        prev = r.hash;
    }
    let doc = serde_json::json!({
        "source": "synthetic (kaspa-prover synth; PoW does not pass)",
        "preimages": pre, "hashes": hashes, "prePows": pre_pows, "powHashes": pow_hashes, "matrices": matrices,
        "pows": pows, "levels": levels, "attempts": vec![1u64; count], "passed": passed,
    });
    std::fs::write(out, serde_json::to_string(&doc)?)?;
    println!("wrote {} synthetic headers to {}", count, out.display());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// relay (O1/v1): witness.json from burnwitness -> native check -> dev-mode execution
// ---------------------------------------------------------------------------------------------

mod witness;
use witness::{build_witness, WFile};
#[cfg(test)]
mod adversarial;

fn relay_cmd(witness: &PathBuf, levels: Option<String>, soft_keccak: bool, native_only: bool, no_attest: bool, out_input: Option<PathBuf>, prover: &str) -> Result<()> {
    let prover: [u8; 20] = unhex(prover)?.as_slice().try_into().map_err(|_| anyhow!("--prover must be 20 bytes (0x + 40 hex)"))?;
    if prover == [0u8; 20] {
        bail!("--prover is the zero address");
    }
    let text = std::fs::read_to_string(witness).with_context(|| format!("reading {}", witness.display()))?;
    let f: WFile = serde_json::from_str(&text).context("parsing witness.json (v1 format: needs t, y_headers, attest_roots; rerun burnwitness)")?;
    witness::check_format(&f)?;
    let want_levels: Vec<u8> = match levels {
        Some(s) => s.split(',').map(|x| x.trim().parse::<u8>()).collect::<std::result::Result<_, _>>()?,
        None => f.levels.clone(),
    };
    let w = build_witness(&f, &want_levels, soft_keccak, !no_attest, prover)?;
    println!("witness       : {} ({})", witness.display(), f.source.as_deref().unwrap_or("?"));
    println!("prover        : 0x{} (the tips go here; in the journal)", hex::encode(prover));
    println!("relay image   : {}", hex::encode(Digest::from(KASPA_RELAY_GUEST_ID).as_bytes()));
    println!("levels        : {:?}   T {}   B {}   (v4: the ladder is anchored at B; no checkpoint)", want_levels, &f.t[..16], &f.b[..16]);
    if let (Some(td), Some(bd)) = (f.t_daa_score, f.b_daa_score) {
        println!("daa           : B {bd}, T {td}; B to T {} ({:.1} min)", td - bd, (td - bd) as f64 / 600.0);
    }
    println!("headers       : {} in the witness, {} used for these levels ({} bytes); first-parent headers {} ({} bytes); attestation chain {} roots{}",
        f.headers.len(), w.headers.len(), w.headers.iter().map(|h| h.len()).sum::<usize>(), w.y_headers.len(), w.y_headers.iter().map(|h| h.len()).sum::<usize>(), w.attest_roots.len(),
        if no_attest { "   (--no-attest: attestation data dropped)" } else { "" });
    println!("burns         : {}", f.burns.len());
    println!("token         : {} (reference cell template {})", hex::encode(w.token_cov_id), hex::encode(relay::KCC20_TEMPLATE));
    for (i, b) in f.burns.iter().enumerate() {
        if b.b != f.b {
            bail!("burn {i}: witness b ({}) and burn.b ({}) differ", f.b, b.b);
        }
        println!("  [{i}] tx {} accepted in C {}, {} chain blocks from C to B", &b.txid[..16], &b.c[..16], b.chain_state_roots.len());
    }

    // 1. inclusion intermediates against the node's values (burnwitness recorded them)
    let mut bad = 0;
    for (i, (wb, fb)) in w.burns.iter().zip(f.burns.iter()).enumerate() {
        let inc = relay::inclusion(wb, &w.token_cov_id);
        let e = &fb.expected;
        let rows: [(&str, String, &String); 7] = [
            ("tx id", hex::encode(inc.tx_id), &fb.txid),
            ("activity digest", hex::encode(inc.activity_digest), &e.activity_digest),
            ("context hash", hex::encode(inc.context_hash), &e.context_hash),
            ("lane tip", hex::encode(inc.lane_tip), &e.lane_tip),
            ("lanes root", hex::encode(inc.lanes_root), &e.lanes_root),
            ("seq_commit(C)", hex::encode(inc.seq_commit_c), &e.seq_commit_c),
            ("seq_commit(B)", hex::encode(inc.seq_commit_final), &e.b_accepted_id_merkle_root),
        ];
        println!("\n== burn {i}: this code vs the node ==");
        for (name, ours, theirs) in rows.iter() {
            let theirs: &str = theirs.as_str();
            let theirs = theirs.strip_prefix("0x").unwrap_or(theirs);
            let ok = ours == theirs;
            if !ok {
                bad += 1;
            }
            println!("{:>16}: {} {}", name, if ok { "ok  " } else { "DIFF" }, &ours[..16]);
            if !ok {
                println!("{:>16}  node: {}", "", theirs);
            }
        }
        println!("{:>16}: {} units in {} burn cell(s), tip {} units, recipient 0x{}, target 0x{}", "burn", inc.amount, inc.burn_cells, inc.tip, hex::encode(inc.recipient), hex::encode(inc.target));
    }
    if bad > 0 {
        bail!("{bad} intermediate value(s) differ from the node's; fix the port before proving");
    }

    // 2. the whole program natively
    let input = w.encode();
    if let Some(p) = &out_input {
        std::fs::write(p, &input)?;
        println!("input frame   : {} bytes written to {}", input.len(), p.display());
    }
    let t0 = Instant::now();
    let expect = relay::run::<SoftKeccak>(&input);
    println!("\n== native run ({:.2} s) ==", t0.elapsed().as_secs_f64());
    for lc in &expect.levels {
        let node = f.per_level.iter().find(|p| p.level == lc.level);
        let (nc, na) = node.map(|p| (p.count, p.attesting)).unwrap_or((0, 0));
        println!(
            "level {:>3}: {:>6} superblocks counted (burnwitness {}){}, {:>6} attesting (burnwitness {}){}  {:.1}%",
            lc.level,
            lc.count,
            nc,
            if lc.count == nc { "" } else { "   DIFF" },
            lc.attesting,
            na,
            if lc.attesting == na { "" } else { "   DIFF" },
            100.0 * lc.attesting as f64 / lc.count.max(1) as f64
        );
    }
    println!("journal: T daa {}, B daa {} (depth {} DAA), {} headers, target 0x{}, {} burn(s), {} bytes", expect.t_daa, expect.b_daa, expect.t_daa - expect.b_daa, expect.n_headers, hex::encode(expect.target), expect.burns.len(), expect.len());
    for bn in &expect.burns {
        println!("  tx {} amount {} tip {} -> 0x{}", hex::encode(bn.tx_id), bn.amount, bn.tip, hex::encode(bn.recipient));
    }
    if native_only {
        return Ok(());
    }

    // 3. the guest, dev mode
    let env = ExecutorEnv::builder().write_frame(&input).build()?;
    let t0 = Instant::now();
    let info = default_executor().execute(env, KASPA_RELAY_GUEST_ELF)?;
    let secs = t0.elapsed().as_secs_f64();
    let user: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded: u64 = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    let j = relay::Journal::decode(&info.journal.bytes).ok_or_else(|| anyhow!("journal is {} bytes and does not decode (expected {})", info.journal.bytes.len(), expect.len()))?;
    if j != expect {
        bail!("guest journal differs from the native run:\n guest  {:?}\n native {:?}", j, expect);
    }
    println!("\n== zkVM execution (dev mode) ==");
    println!("executed in   : {:.1} s", secs);
    println!("segments      : {}", info.segments.len());
    println!("user cycles   : {user}");
    println!("padded cycles : {padded}");
    println!("per header    : {} user cycles (total / PoW headers; includes attestation, inclusion and setup)", user / (w.headers.len().max(1) as u64));
    println!("journal       : {} bytes, sha256 {}", info.journal.bytes.len(), hex::encode(info.journal.digest().as_bytes()));
    println!("journal matches the native run");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Check { vectors } => check(&vectors),
        Cmd::Execute { vectors, count, stage, soft_keccak, no_link } => execute(&vectors, count, &stage, soft_keccak, no_link),
        Cmd::Sweep { vectors, counts, soft_all, out } => sweep(&vectors, &counts, soft_all, out),
        Cmd::Relay { witness, levels, soft_keccak, native_only, no_attest, out_input, prover } => relay_cmd(&witness, levels, soft_keccak, native_only, no_attest, out_input, &prover),
        Cmd::Synth { count, out } => synth(count, &out),
        Cmd::Prove { input, out, no_wrap } => prove_cmd(&input, &out, no_wrap),
        Cmd::Wrap { receipt, out } => wrap_cmd(&receipt, &out),
        Cmd::Verify { bundle, image_id } => verify_cmd(&bundle, image_id),
        Cmd::Journal { file } => {
            let raw = std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            let bytes = match std::str::from_utf8(&raw).ok().and_then(|t| hex::decode(t.trim().trim_start_matches("0x")).ok()) {
                Some(b) => b,
                None => raw,
            };
            print_relay_journal(&bytes);
            Ok(())
        }
        Cmd::Ids => {
            println!("header guest  : {}", hex::encode(Digest::from(KASPA_HEADER_GUEST_ID).as_bytes()));
            println!("relay guest   : {}", hex::encode(Digest::from(KASPA_RELAY_GUEST_ID).as_bytes()));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// O2: prove / wrap / verify (same bundle layout as eth-prover and prover/: image_id.hex, journal.hex,
// journal_hash.hex, receipt.hex = borsh of the Groth16 receipt; receipt.succinct.bin = bincode of the
// succinct receipt between `prove --no-wrap` on the GPU and `wrap` on a CPU box)
// ---------------------------------------------------------------------------------------------

fn print_relay_journal(bytes: &[u8]) {
    println!("journal       : {} bytes, sha256 {}", bytes.len(), hex::encode(risc0_zkvm::Journal::new(bytes.to_vec()).digest().as_bytes()));
    match relay::Journal::decode(bytes) {
        Some(j) => {
            println!("  T            : {} (daa {})", hex::encode(j.t), j.t_daa);
            println!("  B            : {} (daa {}, {} DAA before T)", hex::encode(j.b), j.b_daa, j.t_daa - j.b_daa);
            println!("  r_bits       : 0x{:08x} (median difficulty over the attesting superblocks, V4-DESIGN 2.11.3 / 2.14)", j.r_bits);
            println!("  prover       : 0x{} (the tips go here)", hex::encode(j.prover));
            println!("  headers      : {}", j.n_headers);
            for lc in &j.levels {
                println!("  level {:>3}    : {} superblocks, {} attesting", lc.level, lc.count, lc.attesting);
            }
            println!("  target       : 0x{}", hex::encode(j.target));
            println!("  token        : {}", hex::encode(j.token_cov_id));
            println!("  template     : {}", hex::encode(j.template_hash));
            println!("  burns        : {}", j.burns.len());
            for b in &j.burns {
                println!("    tx {} amount {} tip {} -> 0x{}", hex::encode(b.tx_id), b.amount, b.tip, hex::encode(b.recipient));
            }
        }
        None => println!("  (does not decode as a KZO6 relay journal)"),
    }
}

fn write_common(out: &PathBuf, image_id: &Digest, receipt: &Receipt) -> Result<()> {
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("image_id.hex"), hex::encode(image_id.as_bytes()))?;
    std::fs::write(out.join("journal.hex"), hex::encode(&receipt.journal.bytes))?;
    std::fs::write(out.join("journal_hash.hex"), hex::encode(receipt.journal.digest().as_bytes()))?;
    Ok(())
}

fn write_groth16_bundle(receipt: &Receipt, out: &PathBuf) -> Result<()> {
    let groth16 = receipt.inner.groth16().context("receipt is not Groth16")?;
    let bytes = borsh::to_vec(groth16)?;
    std::fs::write(out.join("receipt.hex"), hex::encode(&bytes))?;
    println!("receipt       : {} bytes borsh -> {}", bytes.len(), out.join("receipt.hex").display());
    println!("seal          : {} bytes", groth16.seal.len());
    Ok(())
}

fn prove_cmd(input: &PathBuf, out: &PathBuf, no_wrap: bool) -> Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let image_id = Digest::from(KASPA_RELAY_GUEST_ID);
    println!("relay image   : {}", hex::encode(image_id.as_bytes()));
    println!("input frame   : {} bytes", bytes.len());
    // The native run first: a frame the program rejects fails here in a second, not after proving.
    let expect = relay::run::<SoftKeccak>(&bytes);
    println!("native        : {} headers, {} burn(s), journal {} bytes", expect.n_headers, expect.burns.len(), expect.len());

    let dev = std::env::var("RISC0_DEV_MODE").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let opts = if dev || no_wrap { ProverOpts::succinct() } else { ProverOpts::groth16() };
    let env = ExecutorEnv::builder().write_frame(&bytes).build()?;
    let t0 = Instant::now();
    let info = default_prover().prove_with_opts(env, KASPA_RELAY_GUEST_ELF, &opts)?;
    let elapsed = t0.elapsed();
    println!("proved in     : {:.1} s", elapsed.as_secs_f64());
    println!("user cycles   : {}", info.stats.user_cycles);
    println!("total cycles  : {}", info.stats.total_cycles);
    println!("segments      : {}", info.stats.segments);
    let receipt = info.receipt;
    receipt.verify(image_id).context("receipt does not verify against the relay image id")?;
    let j = relay::Journal::decode(&receipt.journal.bytes).ok_or_else(|| anyhow!("journal does not decode"))?;
    if j != expect {
        bail!("proved journal differs from the native run");
    }
    print_relay_journal(&receipt.journal.bytes);

    write_common(out, &image_id, &receipt)?;
    std::fs::write(out.join("timing.txt"), format!("proved_in_seconds={}\nuser_cycles={}\ntotal_cycles={}\nsegments={}\n",
        elapsed.as_secs_f64(), info.stats.user_cycles, info.stats.total_cycles, info.stats.segments))?;
    if dev {
        println!("RISC0_DEV_MODE: no real receipt written.");
        return Ok(());
    }
    if no_wrap {
        let path = out.join("receipt.succinct.bin");
        std::fs::write(&path, bincode::serialize(&receipt)?)?;
        println!("--no-wrap: succinct receipt verified and saved to {} ({} bytes)", path.display(), std::fs::metadata(&path)?.len());
        println!("next: kaspa-prover wrap --receipt {} --out {}   (a box with r0vm 3.0.4 and Docker)", path.display(), out.display());
        return Ok(());
    }
    write_groth16_bundle(&receipt, out)
}

fn wrap_cmd(receipt_path: &PathBuf, out: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(receipt_path).with_context(|| format!("read {}", receipt_path.display()))?;
    let receipt: Receipt = bincode::deserialize(&bytes).context("decode succinct receipt")?;
    // The receipt is verified against the image id the GPU box recorded, not this build's: a native build
    // of the host may carry a different (unpinned) relay image, and the bundle must stay the pod's.
    let id_hex = std::fs::read_to_string(out.join("image_id.hex")).with_context(|| format!("read {}/image_id.hex (written by prove)", out.display()))?;
    let image_id = Digest::from(unhex32(id_hex.trim())?);
    receipt.verify(image_id).context("succinct receipt does not verify against image_id.hex in --out")?;
    println!("relay image   : {} (succinct receipt verified)", hex::encode(image_id.as_bytes()));
    let ours = Digest::from(KASPA_RELAY_GUEST_ID);
    if ours != image_id {
        println!("note          : this host build's relay image is {} (native build; the bundle keeps the pod's id)", hex::encode(ours.as_bytes()));
    }
    let t0 = Instant::now();
    let g = default_prover().compress(&ProverOpts::groth16(), &receipt)?;
    let elapsed = t0.elapsed();
    println!("wrapped in    : {:.1} s", elapsed.as_secs_f64());
    g.verify(image_id).context("Groth16 receipt does not verify")?;
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().append(true).create(true).open(out.join("timing.txt"))?;
    writeln!(f, "wrapped_in_seconds={}", elapsed.as_secs_f64())?;
    print_relay_journal(&g.journal.bytes);
    write_common(out, &image_id, &g)?;
    write_groth16_bundle(&g, out)
}

fn verify_cmd(bundle: &PathBuf, image_id: Option<String>) -> Result<()> {
    let rd = |name: &str| -> Result<Vec<u8>> {
        let t = std::fs::read_to_string(bundle.join(name)).with_context(|| format!("read {}/{name}", bundle.display()))?;
        unhex(t.trim())
    };
    let bundle_id = Digest::from(unhex32(std::fs::read_to_string(bundle.join("image_id.hex")).with_context(|| format!("read {}/image_id.hex", bundle.display()))?.trim())?);
    let want = match image_id {
        Some(s) => Digest::from(unhex32(&s)?),
        None => Digest::from(KASPA_RELAY_GUEST_ID),
    };
    let journal = rd("journal.hex")?;
    let groth16: risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> = borsh::from_slice(&rd("receipt.hex")?).context("receipt.hex is not a borsh Groth16 receipt")?;
    let receipt = Receipt::new(InnerReceipt::Groth16(groth16), journal.clone());
    receipt.verify(want).context("Groth16 receipt does not verify against the image id")?;
    println!("bundle        : {}", bundle.display());
    println!("image id      : {} ({})", hex::encode(want.as_bytes()), if bundle_id == want { "matches image_id.hex" } else { "DIFFERS from image_id.hex" });
    println!("journal hash  : {} ({})", hex::encode(receipt.journal.digest().as_bytes()),
        if rd("journal_hash.hex").map(|h| h == receipt.journal.digest().as_bytes()).unwrap_or(false) { "matches journal_hash.hex" } else { "journal_hash.hex missing or different" });
    print_relay_journal(&journal);
    println!("verified      : Groth16 receipt ok");

    // What the Ethereum verifier (risc0-ethereum RiscZeroGroth16Verifier) sees: verify(seal, imageId, sha256(journal)).
    // Its seal is 4 selector bytes (the head of the Groth16ReceiptVerifierParameters digest) followed by the
    // 256-byte proof; it rebuilds ReceiptClaim::ok(imageId, journalDigest) and checks the proof against
    // (control root halves, claim digest halves, bn254 control id).
    let g = receipt.inner.groth16().context("receipt is not Groth16")?;
    let params = risc0_zkvm::Groth16ReceiptVerifierParameters::default();
    let params_digest = params.digest();
    let claim = risc0_zkvm::ReceiptClaim::ok(want, journal.clone());
    let claim_digest = claim.digest();
    println!("\n== ethereum ==");
    println!("control root  : {}", hex::encode(params.control_root.as_bytes()));
    println!("bn254 ctrl id : {}", hex::encode(params.bn254_control_id.as_bytes()));
    println!("verifier prms : {} ({})", hex::encode(g.verifier_parameters.as_bytes()),
        if g.verifier_parameters == params_digest { "= risc0 3.0.4 defaults" } else { "DIFFERS from risc0 3.0.4 defaults" });
    println!("selector      : 0x{}", hex::encode(&g.verifier_parameters.as_bytes()[..4]));
    println!("claim digest  : {} ({})", hex::encode(claim_digest.as_bytes()),
        if g.claim.digest() == claim_digest { "= ReceiptClaim::ok(imageId, journal)" } else { "DIFFERS from the receipt's claim" });
    println!("image id      : 0x{}", hex::encode(want.as_bytes()));
    println!("journal digest: 0x{}", hex::encode(receipt.journal.digest().as_bytes()));
    println!("seal          : 0x{}{}", hex::encode(&g.verifier_parameters.as_bytes()[..4]), hex::encode(&g.seal));
    println!("journal       : 0x{}", hex::encode(&journal));
    std::fs::write(bundle.join("eth-seal.hex"), format!("{}{}", hex::encode(&g.verifier_parameters.as_bytes()[..4]), hex::encode(&g.seal)))?;
    Ok(())
}
