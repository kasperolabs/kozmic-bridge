//! kpow-vectors: Kaspa header PoW test vectors for the Solidity port (outbound study, E10).
//!
//! Every value is computed twice where possible: once by this file's step-by-step re-implementation
//! (so the Solidity port can be debugged stage by stage) and once by rusty-kaspa v2.1.0 itself
//! (`kaspa_pow::State`, `hashing::header::hash`). The program aborts if the two ever disagree, so a
//! vector file that exists is a vector file rusty-kaspa agrees with.
//!
//!   kpow-vectors fetch [--url ws://127.0.0.1:17110] [--count 64] [--out vectors.json]
//!       walks back `count` blocks along the selected chain from the sink of a mainnet node (wRPC Borsh)
//!   kpow-vectors synth [--count 8] [--out vectors.json]
//!       random headers, no node needed (PoW will not pass; only for checking the port offline)

use kaspa_consensus_core::{hashing, header::Header};
use kaspa_hashes::{BlockHash, Hash, HasherBase, KHeavyHash, PowHash};
use kaspa_math::Uint256;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};

const MAINNET_MAX_BLOCK_LEVEL: u8 = 225; // consensus/core/src/config/params.rs, MAINNET_PARAMS

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| default.to_string())
}

/// The exact byte string `hashing::header::hash_override_nonce_time` feeds to keyed blake2b.
fn preimage(h: &Header, nonce: u64, timestamp: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(4096);
    b.extend(h.version.to_le_bytes());
    let levels: Vec<&[Hash]> = h.parents_by_level.expanded_iter().collect();
    b.extend((levels.len() as u64).to_le_bytes());
    for level in levels {
        b.extend((level.len() as u64).to_le_bytes());
        for p in level {
            b.extend(p.as_bytes());
        }
    }
    b.extend(h.hash_merkle_root.as_bytes());
    b.extend(h.accepted_id_merkle_root.as_bytes());
    b.extend(h.utxo_commitment.as_bytes());
    b.extend(timestamp.to_le_bytes());
    b.extend(h.bits.to_le_bytes());
    b.extend(nonce.to_le_bytes());
    b.extend(h.daa_score.to_le_bytes());
    b.extend(h.blue_score.to_le_bytes());
    let bw = h.blue_work.to_be_bytes();
    let start = bw.iter().position(|&x| x != 0).unwrap_or(bw.len());
    b.extend(((bw.len() - start) as u64).to_le_bytes());
    b.extend(&bw[start..]);
    b.extend(h.pruning_point.as_bytes());
    b
}

fn blake(data: &[u8]) -> Hash {
    let mut h = BlockHash::new();
    h.update(data);
    h.finalize()
}

// ---- matrix, copied from consensus/pow/src/{xoshiro,matrix}.rs at v2.1.0 so intermediates are visible ----
struct Xo([u64; 4]);
impl Xo {
    fn next(&mut self) -> u64 {
        let s = &mut self.0;
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

fn rank(m: &[[u16; 64]; 64]) -> usize {
    const EPS: f64 = 1e-9;
    let mut f = [[0f64; 64]; 64];
    for i in 0..64 {
        for j in 0..64 {
            f[i][j] = m[i][j] as f64;
        }
    }
    let mut rank = 0;
    let mut sel = [false; 64];
    for i in 0..64 {
        let mut j = 0;
        while j < 64 {
            if !sel[j] && f[j][i].abs() > EPS {
                break;
            }
            j += 1;
        }
        if j != 64 {
            rank += 1;
            sel[j] = true;
            for p in (i + 1)..64 {
                f[j][p] /= f[j][i];
            }
            for k in 0..64 {
                if k != j && f[k][i].abs() > EPS {
                    for p in (i + 1)..64 {
                        f[k][p] -= f[j][p] * f[k][i];
                    }
                }
            }
        }
    }
    rank
}

/// Returns (matrix, packed rows, attempts). Packed row i: nibble j at bits 4j..4j+4 of a uint256,
/// i.e. exactly the four xoshiro outputs of that row laid side by side; serialized big-endian.
fn matrix(pre_pow: Hash) -> ([[u16; 64]; 64], Vec<u8>, u32) {
    let mut g = Xo(pre_pow.to_le_u64());
    let mut attempts = 0;
    loop {
        attempts += 1;
        let mut m = [[0u16; 64]; 64];
        let mut packed = Vec::with_capacity(2048);
        for row in m.iter_mut() {
            let v: [u64; 4] = [g.next(), g.next(), g.next(), g.next()];
            for (j, cell) in row.iter_mut().enumerate() {
                *cell = ((v[j / 16] >> (4 * (j % 16))) & 0xF) as u16;
            }
            for k in (0..4).rev() {
                packed.extend(v[k].to_be_bytes());
            }
        }
        if rank(&m) == 64 {
            return (m, packed, attempts);
        }
    }
}

fn heavy(m: &[[u16; 64]; 64], hash: Hash) -> Hash {
    let hb = hash.as_bytes();
    let mut v = [0u16; 64];
    for i in 0..32 {
        v[2 * i] = (hb[i] >> 4) as u16;
        v[2 * i + 1] = (hb[i] & 0xF) as u16;
    }
    let mut p = [0u8; 32];
    for i in 0..32 {
        let (mut s1, mut s2) = (0u16, 0u16);
        for j in 0..64 {
            s1 += m[2 * i][j] * v[j];
            s2 += m[2 * i + 1][j] * v[j];
        }
        p[i] = (((s1 >> 10) << 4) as u8 | (s2 >> 10) as u8) ^ hb[i];
    }
    KHeavyHash::hash(Hash::from_bytes(p))
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

struct Out {
    preimages: Vec<String>,
    hashes: Vec<String>,
    pre_pows: Vec<String>,
    pow_hashes: Vec<String>,
    matrices: Vec<String>,
    pows: Vec<String>,
    levels: Vec<u64>,
    attempts: Vec<u64>,
    passed: Vec<u64>,
    n_levels: Vec<u64>,
    n_parents: Vec<u64>,
}

fn process(h: &Header, rpc_hash: Option<Hash>, o: &mut Out) {
    let pre = preimage(h, h.nonce, h.timestamp);
    let hash = blake(&pre);
    assert_eq!(hash, hashing::header::hash(h), "preimage serialization disagrees with rusty-kaspa");
    if let Some(r) = rpc_hash {
        assert_eq!(hash, r, "recomputed hash disagrees with the node's hash");
    }
    let pre_pow = blake(&preimage(h, 0, 0));
    assert_eq!(pre_pow, hashing::header::hash_override_nonce_time(h, 0, 0));

    let pow_hash = PowHash::new(pre_pow, h.timestamp).finalize_with_nonce(h.nonce);
    let (m, packed, attempts) = matrix(pre_pow);
    let fin = heavy(&m, pow_hash);
    let pow = Uint256::from_le_bytes(fin.as_bytes());

    let state = kaspa_pow::State::new(h);
    let (passed, pow_ref) = state.check_pow(h.nonce);
    assert_eq!(pow, pow_ref, "step-by-step PoW disagrees with kaspa_pow::State");
    let level = kaspa_pow::calc_level_from_pow(pow, MAINNET_MAX_BLOCK_LEVEL);

    let levels: Vec<&[Hash]> = h.parents_by_level.expanded_iter().collect();
    o.preimages.push(hx(&pre));
    o.hashes.push(hx(&hash.as_bytes()));
    o.pre_pows.push(hx(&pre_pow.as_bytes()));
    o.pow_hashes.push(hx(&pow_hash.as_bytes()));
    o.matrices.push(hx(&packed));
    o.pows.push(hx(&pow.to_be_bytes()));
    o.levels.push(level as u64);
    o.attempts.push(attempts as u64);
    o.passed.push(passed as u64);
    o.n_levels.push(levels.len() as u64);
    o.n_parents.push(levels.iter().map(|l| l.len() as u64).sum());
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn hash(&mut self) -> Hash {
        Hash::from_le_u64([self.next(), self.next(), self.next(), self.next()])
    }
}

fn synth_header(r: &mut Rng) -> Header {
    let n_levels = 1 + (r.next() % 30) as usize;
    let parents: Vec<Vec<Hash>> = (0..n_levels).map(|_| (0..1 + (r.next() % 8)).map(|_| r.hash()).collect()).collect();
    Header::new_finalized(
        1,
        parents.try_into().unwrap(),
        r.hash(),
        r.hash(),
        r.hash(),
        r.next() >> 20,
        0x1a0fffff,
        r.next(),
        r.next() >> 16,
        kaspa_math::Uint192::from_u64(r.next()),
        r.next() >> 16,
        r.hash(),
    )
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).cloned().unwrap_or_default();
    let count: usize = arg(&args, "--count", if mode == "synth" { "8" } else { "64" }).parse().expect("--count");
    let out_path = arg(&args, "--out", "vectors.json");
    let mut o = Out {
        preimages: vec![],
        hashes: vec![],
        pre_pows: vec![],
        pow_hashes: vec![],
        matrices: vec![],
        pows: vec![],
        levels: vec![],
        attempts: vec![],
        passed: vec![],
        n_levels: vec![],
        n_parents: vec![],
    };
    let source: String;

    match mode.as_str() {
        "synth" => {
            let mut r = Rng(42);
            for _ in 0..count {
                process(&synth_header(&mut r), None, &mut o);
            }
            source = "synthetic".into();
        }
        "fetch" => {
            let url = arg(&args, "--url", "ws://127.0.0.1:17110");
            let client = KaspaRpcClient::new(
                WrpcEncoding::Borsh,
                Some(&url),
                None,
                Some(NetworkId::new(NetworkType::Mainnet)),
                None,
            )
            .expect("client");
            client
                .connect(Some(ConnectOptions {
                    block_async_connect: true,
                    connect_timeout: Some(Duration::from_millis(10_000)),
                    strategy: ConnectStrategy::Fallback,
                    ..Default::default()
                }))
                .await
                .expect("connect (is the node running with --rpclisten-borsh?)");
            let info = client.get_server_info().await.expect("server info");
            assert!(info.is_synced, "node is not synced");
            let mut cur = client.get_sink().await.expect("sink").sink;
            source = format!("{} {} sink {}", info.network_id, info.server_version, cur);
            for i in 0..count {
                let b = client.get_block(cur, false).await.expect("get_block");
                let h: Header = (&b.header).try_into().expect("header");
                process(&h, Some(b.header.hash), &mut o);
                cur = b.verbose_data.expect("verbose data").selected_parent_hash;
                if (i + 1) % 500 == 0 {
                    eprintln!("  {} headers", i + 1);
                }
            }
            client.disconnect().await.ok();
        }
        _ => {
            eprintln!("usage: kpow-vectors fetch [--url ws://127.0.0.1:17110] [--count 64] [--out vectors.json]");
            eprintln!("       kpow-vectors synth [--count 8] [--out vectors.json]");
            std::process::exit(2);
        }
    }

    let v = json!({
        "source": source,
        "preimages": o.preimages, "hashes": o.hashes, "prePows": o.pre_pows, "powHashes": o.pow_hashes,
        "matrices": o.matrices, "pows": o.pows, "levels": o.levels, "attempts": o.attempts, "passed": o.passed,
        "nLevels": o.n_levels, "nParents": o.n_parents,
    });
    std::fs::write(&out_path, serde_json::to_string(&v).unwrap()).expect("write");

    // Summary for the human.
    let n = o.levels.len();
    let sizes: Vec<usize> = o.preimages.iter().map(|s| (s.len() - 2) / 2).collect();
    let mut hist: BTreeMap<u64, usize> = BTreeMap::new();
    for l in &o.levels {
        *hist.entry(*l).or_default() += 1;
    }
    println!("source          : {source}");
    println!("headers         : {n}  (pow passed: {})", o.passed.iter().sum::<u64>());
    println!(
        "header bytes    : min {} / avg {} / max {}",
        sizes.iter().min().unwrap(),
        sizes.iter().sum::<usize>() / n,
        sizes.iter().max().unwrap()
    );
    println!(
        "parent levels   : min {} / max {}   parents total: min {} / max {}",
        o.n_levels.iter().min().unwrap(),
        o.n_levels.iter().max().unwrap(),
        o.n_parents.iter().min().unwrap(),
        o.n_parents.iter().max().unwrap()
    );
    println!("matrix attempts : max {} (1 = first matrix was full rank)", o.attempts.iter().max().unwrap());
    println!("block levels    : {}", hist.iter().map(|(l, c)| format!("{l}:{c}")).collect::<Vec<_>>().join("  "));
    println!("wrote           : {out_path}");
}
