//! dagwalk: superblocks across the whole Kaspa DAG, and whether `parents_by_level[L]` links them.
//!
//! Outbound study, weekend item 3 (DAG half) and the structural input to E3'. Reads a window of the
//! mainnet DAG from a node (wRPC Borsh), computes every block's level with rusty-kaspa's own PoW code,
//! and answers, per level L:
//!   - how many blocks of level >= L the DAG holds in the window (all, blue, red, on the selected chain);
//!   - how many of them a walk along `parents_by_level[L]` from the sink reaches: if a prover must show a
//!     closed level-L walk (every level-L parent of every shown header), this is the set it cannot
//!     silently shrink; the blocks it misses are the superblocks no honest proof can carry.
//!
//!   dagwalk [--url ws://127.0.0.1:17110] [--hours 1] [--levels 24,26,28,30,32,34] [--out dagwalk.json]
//!
//! Window = every block reachable from the sink through direct parents whose timestamp is within the
//! last `hours` (timestamps are loose, tolerance 132 s, so the edge is fuzzy by a few blocks; the
//! numbers are ratios and rates, which do not care).

use kaspa_consensus_core::header::Header;
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

const MAINNET_MAX_BLOCK_LEVEL: u8 = 225;

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| default.to_string())
}

struct Info {
    header: Header,
    level: u8,
    is_chain: bool,
    blues: Vec<Hash>,
    reds: Vec<Hash>,
}

struct Walker {
    client: KaspaRpcClient,
    blocks: HashMap<Hash, Info>,
    rpc_calls: usize,
}

impl Walker {
    async fn get(&mut self, h: Hash) -> &Info {
        if !self.blocks.contains_key(&h) {
            let b = self.client.get_block(h, false).await.expect("get_block");
            self.rpc_calls += 1;
            let header: Header = (&b.header).try_into().expect("header");
            let (level, passed) = kaspa_pow::calc_block_level_check_pow(&header, MAINNET_MAX_BLOCK_LEVEL);
            assert!(passed, "block {h} fails its own PoW");
            let v = b.verbose_data.expect("verbose data");
            self.blocks.insert(
                h,
                Info {
                    header,
                    level,
                    is_chain: v.is_chain_block,
                    blues: v.merge_set_blues_hashes,
                    reds: v.merge_set_reds_hashes,
                },
            );
            if self.rpc_calls % 2000 == 0 {
                eprintln!("  {} blocks fetched", self.rpc_calls);
            }
        }
        &self.blocks[&h]
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = arg(&args, "--url", "ws://127.0.0.1:17110");
    let hours: f64 = arg(&args, "--hours", "1").parse().expect("--hours");
    let levels: Vec<u8> = arg(&args, "--levels", "24,26,28,30,32,34").split(',').map(|s| s.trim().parse().expect("--levels")).collect();
    let out_path = arg(&args, "--out", "dagwalk.json");

    let client = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&url), None, Some(NetworkId::new(NetworkType::Mainnet)), None).expect("client");
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
    let sink = client.get_sink().await.expect("sink").sink;
    let mut w = Walker { client, blocks: HashMap::new(), rpc_calls: 0 };

    // 1. The window: BFS over direct parents from the sink, expanding only blocks inside the time window.
    let t_end = w.get(sink).await.header.timestamp;
    let t_start = t_end - (hours * 3600.0 * 1000.0) as u64;
    let mut in_window: HashSet<Hash> = HashSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::from([sink]);
    let mut seen: HashSet<Hash> = HashSet::from([sink]);
    while let Some(h) = queue.pop_front() {
        let inf = w.get(h).await;
        if inf.header.timestamp < t_start {
            continue; // boundary block: fetched, not expanded, not counted
        }
        let parents: Vec<Hash> = inf.header.parents_by_level.get(0).map(|p| p.to_vec()).unwrap_or_default();
        in_window.insert(h);
        for p in parents {
            if seen.insert(p) {
                queue.push_back(p);
            }
        }
    }
    eprintln!("window walked: {} blocks in window, {} fetched", in_window.len(), w.rpc_calls);

    // 2. Classify: chain blocks, blue set (chain blocks plus their mergeset blues), red set.
    let chain: HashSet<Hash> = in_window.iter().copied().filter(|h| w.blocks[h].is_chain).collect();
    let mut blue: HashSet<Hash> = chain.clone();
    let mut red: HashSet<Hash> = HashSet::new();
    for h in &chain {
        blue.extend(w.blocks[h].blues.iter().copied());
        red.extend(w.blocks[h].reds.iter().copied());
    }
    let span_s = (t_end - t_start) as f64 / 1000.0;
    let unclassified = in_window.iter().filter(|h| !blue.contains(h) && !red.contains(h)).count();

    // 3. Histograms.
    let mut hist_all: BTreeMap<u8, usize> = BTreeMap::new();
    let mut hist_chain: BTreeMap<u8, usize> = BTreeMap::new();
    let mut hist_red: BTreeMap<u8, usize> = BTreeMap::new();
    for h in &in_window {
        let l = w.blocks[h].level;
        *hist_all.entry(l).or_default() += 1;
        if chain.contains(h) {
            *hist_chain.entry(l).or_default() += 1;
        }
        if red.contains(h) {
            *hist_red.entry(l).or_default() += 1;
        }
    }
    let fmt_hist = |m: &BTreeMap<u8, usize>| m.iter().map(|(l, c)| format!("{l}:{c}")).collect::<Vec<_>>().join("  ");

    // Chain-work baseline: sum over in-window blue blocks of 2^256/(target+1), and the headers' blue_work delta
    // along the selected chain inside the window.
    let work_of = |h: &Hash| -> f64 { 2f64.powi(256) / (kaspa_math_target(w.blocks[h].header.bits) + 1.0) };
    let blue_work_sum: f64 = blue.iter().filter(|h| in_window.contains(h)).map(|h| work_of(h)).sum();
    let all_work_sum: f64 = in_window.iter().map(|h| work_of(h)).sum();

    println!("source        : {} {} sink {}", info.network_id, info.server_version, sink);
    println!("window        : {:.2} h ({:.0} s), timestamps {} .. {}", hours, span_s, t_start, t_end);
    println!("blocks        : {} in window ({:.2} per s); chain {} ({:.1}%), blue {} ({:.2}%), red {} ({:.3}%), unclassified {}", in_window.len(), in_window.len() as f64 / span_s, chain.len(), 100.0 * chain.len() as f64 / in_window.len() as f64, blue.iter().filter(|h| in_window.contains(h)).count(), 100.0 * blue.iter().filter(|h| in_window.contains(h)).count() as f64 / in_window.len() as f64, red.iter().filter(|h| in_window.contains(h)).count(), 100.0 * red.iter().filter(|h| in_window.contains(h)).count() as f64 / in_window.len() as f64, unclassified);
    println!("rpc calls     : {} (window plus boundary)", w.rpc_calls);
    println!("work          : all blocks {:.4e} hashes, blue blocks {:.4e} ({:.3e} per s = hashrate)", all_work_sum, blue_work_sum, blue_work_sum / span_s);
    println!("levels, all   : {}", fmt_hist(&hist_all));
    println!("levels, chain : {}", fmt_hist(&hist_chain));
    println!("levels, red   : {}", fmt_hist(&hist_red));

    // 4. Per level: superblocks in the DAG vs the closed level-L walk from the sink.
    println!();
    println!("== level-L parent walks from the sink (in-window counts) ==");
    println!("{:>5} {:>9} {:>8} {:>6} {:>9} {:>9} {:>7} {:>7} {:>8} {:>8} {:>10}", "level", "DAG >= L", "blue", "red", "walked", "missed", "m.red", "m.blue", "avg par", "max par", "est/work");
    let mut per_level = Vec::new();
    for &lv in &levels {
        let a: HashSet<Hash> = in_window.iter().copied().filter(|h| w.blocks[h].level >= lv).collect();
        let a_blue = a.iter().filter(|h| blue.contains(h)).count();
        let a_red = a.iter().filter(|h| red.contains(h)).count();
        // closed walk along level-L parents
        let mut walked: HashSet<Hash> = HashSet::new();
        let mut q: VecDeque<Hash> = VecDeque::from([sink]);
        let mut vis: HashSet<Hash> = HashSet::from([sink]);
        let mut par_counts: Vec<usize> = Vec::new();
        while let Some(h) = q.pop_front() {
            let inf = w.get(h).await;
            if inf.header.timestamp < t_start {
                continue;
            }
            let parents: Vec<Hash> = inf.header.parents_by_level.get(lv as usize).map(|p| p.to_vec()).unwrap_or_default();
            if inf.level >= lv && in_window.contains(&h) {
                walked.insert(h);
                par_counts.push(parents.len());
            }
            for p in parents {
                if vis.insert(p) {
                    q.push_back(p);
                }
            }
        }
        let missed: Vec<Hash> = a.iter().copied().filter(|h| !walked.contains(h)).collect();
        let m_red = missed.iter().filter(|h| red.contains(h)).count();
        let m_blue = missed.iter().filter(|h| blue.contains(h)).count();
        let extra = walked.iter().filter(|h| !a.contains(h)).count();
        assert_eq!(extra, 0, "level-{lv} walk reached blocks below level {lv}");
        let avg_par = if par_counts.is_empty() { 0.0 } else { par_counts.iter().sum::<usize>() as f64 / par_counts.len() as f64 };
        let max_par = par_counts.iter().copied().max().unwrap_or(0);
        let est = a.len() as f64 * 2f64.powi(31 + lv as i32);
        println!("{:>5} {:>9} {:>8} {:>6} {:>9} {:>9} {:>7} {:>7} {:>8.2} {:>8} {:>10.3}", lv, a.len(), a_blue, a_red, walked.len(), missed.len(), m_red, m_blue, avg_par, max_par, est / blue_work_sum);
        per_level.push(json!({
            "level": lv, "dag_at_or_above": a.len(), "blue": a_blue, "red": a_red, "walked": walked.len(),
            "missed": missed.len(), "missed_red": m_red, "missed_blue": m_blue, "avg_level_parents": avg_par,
            "max_level_parents": max_par, "estimate_over_blue_work": est / blue_work_sum,
            "missed_hashes": missed.iter().take(20).map(|h| h.to_string()).collect::<Vec<_>>(),
        }));
    }
    println!("(DAG >= L: blocks in the window at level >= L; walked: reached from the sink by following parents_by_level[L];");
    println!(" missed: superblocks the walk never reaches, split by red/blue; est/work: count x 2^(31+L) over the blue work)");

    let doc = json!({
        "source": format!("{} {} sink {}", info.network_id, info.server_version, sink),
        "hours": hours, "t_start": t_start, "t_end": t_end,
        "blocks": in_window.len(), "chain": chain.len(), "blue": blue.iter().filter(|h| in_window.contains(h)).count(),
        "red": red.iter().filter(|h| in_window.contains(h)).count(), "rpc_calls": w.rpc_calls,
        "work_all": all_work_sum, "work_blue": blue_work_sum, "hashrate": blue_work_sum / span_s,
        "levels_all": hist_all, "levels_chain": hist_chain, "levels_red": hist_red,
        "per_level": per_level,
    });
    std::fs::write(&out_path, serde_json::to_string_pretty(&doc).unwrap()).expect("write");
    println!("wrote         : {out_path}");
    w.client.disconnect().await.ok();
}

/// Uint256::from_compact_target_bits as an f64 (kaspa_math is not a dependency here; the exact value does
/// not matter for ratios, only for the order of magnitude).
fn kaspa_math_target(bits: u32) -> f64 {
    let (mant, expt) = {
        let unshifted = bits >> 24;
        if unshifted <= 3 { ((bits & 0xFFFFFF) >> (8 * (3 - unshifted)), 0) } else { (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3)) }
    };
    if mant > 0x7FFFFF { 0.0 } else { mant as f64 * 2f64.powi(expt as i32) }
}
