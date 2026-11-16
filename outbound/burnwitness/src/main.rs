//! burnwitness: the outbound relay witness (O1) for one burned-KAS transaction, from a rusty-kaspa
//! U4 (2026-10-16): relay guest v2. Burns are KCC-20 reference-cell burns of one token (--token <covenant id>;
//! cells.rs reads the amounts from the spender's transfer and checks each by its P2SH hash), the attestation follows
//! the guest's three-step first-parent rule (hop-4 joins recorded separately), and the witness is format 3.
//! v2.1.0 node over wRPC. Everything the relay guest needs, with every intermediate hash recorded
//! from the node's own crates (`kaspa_seq_commit`, `kaspa_smt`, `kaspa_pow`) so a port that drifts
//! is caught field by field before anything is proven.
//!
//!   burnwitness --url ws://127.0.0.1:17110 --txid <id>[,<id>...] --start <chain block before the burns>
//!               [--levels 28,30,32] [--hours 1 | --k <checkpoint hash>] [--b <attested block>] [--t <tip>]
//!               [--depth-daa 6000] [--cmp-level 30 --min-attest 50 --min-count 300] [--out witness.json]
//!               [--extra-nonchain N]   # O5: also record N real non-chain blocks (fake-B material for the
//!                                      # adversarial tests in kaspa-prover/host/src/adversarial.rs)
//!   burnwitness --url ws://127.0.0.1:17110 --pick-k [--levels 28,30,32] [--hours 0]
//!               # O3: print a fresh checkpoint for the relay contract (a block at level >= max(levels) along the
//!               # sink's level parents, --hours older than the sink) and exit
//!   burnwitness --url ws://127.0.0.1:17110 --check-first-parent [--count 5000] [--levels 28,30,32]
//!               [--margin-min 2] [--out first-parent-check.json]
//!               # v1 step 1: walk --count chain blocks back from the sink (skipping the newest --margin-min
//!               # minutes), check parents_by_level[0][0] == the node's selected parent on every one, then for
//!               # every superblock at each level in that span report whether its first parent is a chain
//!               # block, whether it equals its own selected parent, and the DAA lag between them
//!
//! What it does:
//!   1. finds, for each burn, the chain block C that accepted it (getVirtualChainFromBlock from --start);
//!   2. picks B = the latest C (or --b), T = the first chain block at level >= max(levels) at least --depth-daa
//!      past B (or --t), and K = --k (the relay contract's checkpoint) or else the first block along T's
//!      level-max parents whose timestamp is at least --hours older than T;
//!   3. for each level L walks parents_by_level[L] from T (closed walk; stops at K and at blocks whose
//!      daa_score <= K's), serializes every visited header (preimage checked against its hash), and for every
//!      counted superblock checks whether its first parent is a chain block in [B, T] (v1 attestation);
//!      those first parents' headers go into the witness too (hash-checked only in the guest);
//!   4. per burn: rebuilds C's native-lane activity (merge order from the node's accepted ids), recomputes
//!      the lane tip, SMT leaf, lanes root and seq_commit(C) with kaspa_seq_commit / kaspa_smt, checks
//!      them against the node, then chains the state roots of the chain blocks after C through B; and
//!      records the state roots of the chain blocks after B through T (the attestation chain).

use kaspa_consensus_core::hashing::HasherExtensions;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::tx::Transaction;
use kaspa_hashes::{Hash, HasherBase, SeqCommitActiveNode};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::model::{GetSeqCommitLaneProofResponse, RpcTransaction};
use kaspa_seq_commit::hashing::{
    activity_digest_lane, activity_leaf, activity_root_hash, lane_key, lane_tip_next, mergeset_context_hash, seq_commit,
    seq_state_root, smt_leaf_hash,
};
use kaspa_seq_commit::types::{LaneTipInput, MergesetContext, SeqCommitInput, SeqState, SmtLeafInput};
use kaspa_smt::proof::OwnedSmtProof;
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::time::Duration;

mod cells;

const MAINNET_MAX_BLOCK_LEVEL: u8 = 225;
/// U4: first-parent hops the relay guest v2 accepts (primitives/src/relay.rs MAX_FP_STEPS).
const RULE_FP_STEPS: usize = 3;
const NATIVE_LANE: [u8; 20] = [0u8; 20];
/// O5 measurement: first-parent steps followed from a superblock until a chain block (1 = its first parent).
const MAX_FP_STEPS: usize = 5;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn h(s: &str) -> Hash {
    Hash::from_str(s.strip_prefix("0x").unwrap_or(s)).unwrap_or_else(|e| panic!("bad hash {s}: {e}"))
}

struct Info {
    header: Header,
    level: u8,
    is_chain: bool,
    selected_parent: Hash,
    blues: Vec<Hash>,
    reds: Vec<Hash>,
}

struct Node {
    client: KaspaRpcClient,
    cache: HashMap<Hash, Info>,
    calls: usize,
}

impl Node {
    async fn get(&mut self, hash: Hash) -> &Info {
        if !self.cache.contains_key(&hash) {
            let b = self.client.get_block(hash, false).await.unwrap_or_else(|e| panic!("get_block {hash}: {e}"));
            self.calls += 1;
            let header: Header = (&b.header).try_into().expect("header");
            let (level, passed) = kaspa_pow::calc_block_level_check_pow(&header, MAINNET_MAX_BLOCK_LEVEL);
            assert!(passed, "block {hash} fails its own PoW");
            let v = b.verbose_data.expect("verbose data");
            self.cache.insert(
                hash,
                Info {
                    header,
                    level,
                    is_chain: v.is_chain_block,
                    selected_parent: v.selected_parent_hash,
                    blues: v.merge_set_blues_hashes,
                    reds: v.merge_set_reds_hashes,
                },
            );
            if self.calls % 1000 == 0 {
                eprintln!("  {} blocks fetched", self.calls);
            }
        }
        &self.cache[&hash]
    }

    async fn txs(&mut self, hash: Hash) -> Vec<RpcTransaction> {
        self.calls += 1;
        self.client.get_block(hash, true).await.unwrap_or_else(|e| panic!("get_block(txs) {hash}: {e}")).transactions
    }

    async fn lane_proof(&mut self, hash: Hash, lk: Hash) -> GetSeqCommitLaneProofResponse {
        self.calls += 1;
        self.client.get_seq_commit_lane_proof(hash, lk).await.unwrap_or_else(|e| panic!("get_seq_commit_lane_proof {hash}: {e}"))
    }
}

/// The exact bytes `hash_override_nonce_time` feeds to blake2b (consensus/core/src/hashing/header.rs),
/// checked against the header's hash.
fn header_preimage(hd: &Header) -> Vec<u8> {
    #[derive(Default)]
    struct Buf(Vec<u8>);
    impl HasherBase for Buf {
        fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
            self.0.extend_from_slice(data.as_ref());
            self
        }
    }
    let mut b = Buf::default();
    b.update(hd.version.to_le_bytes()).write_len(hd.parents_by_level.expanded_len());
    hd.parents_by_level.expanded_iter().for_each(|level| {
        b.write_var_array(level);
    });
    b.update(hd.hash_merkle_root)
        .update(hd.accepted_id_merkle_root)
        .update(hd.utxo_commitment)
        .update(hd.timestamp.to_le_bytes())
        .update(hd.bits.to_le_bytes())
        .update(hd.nonce.to_le_bytes())
        .update(hd.daa_score.to_le_bytes())
        .update(hd.blue_score.to_le_bytes())
        .write_blue_work(hd.blue_work)
        .update(hd.pruning_point);
    let mut check = kaspa_hashes::BlockHash::new();
    check.update(&b.0);
    let got = kaspa_hashes::Hasher::finalize(check);
    assert_eq!(got, hd.hash, "serialized preimage does not hash to the header's hash");
    b.0
}

/// state root of a chain block from its lane witness (any lane; the SMT root is what matters).
fn state_root_of(resp: &GetSeqCommitLaneProofResponse, lk: Hash) -> (Hash, Hash) {
    let proof = OwnedSmtProof::from_bytes(&resp.smt_proof).expect("smt proof wire format");
    let leaf = resp.lane.as_ref().map(|l| smt_leaf_hash(&SmtLeafInput { lane_tip: &l.tip, blue_score: l.blue_score }));
    let lanes_root = proof.compute_root::<SeqCommitActiveNode>(&lk, leaf).expect("smt compute_root");
    let ar = activity_root_hash(&resp.inactivity_shortcut, &lanes_root);
    let sr = seq_state_root(&SeqState { activity_root: &ar, payload_and_ctx_digest: &resp.payload_and_ctx_digest });
    (sr, lanes_root)
}

/// Follows parents_by_level[lmax][0] from `from` until a block whose timestamp is <= `cutoff` (ms). With
/// `skip_from`, `from` itself is never returned (the sink is rarely at level lmax; the first level parent is).
async fn walk_back(node: &mut Node, from: Hash, lmax: u8, cutoff: u64, skip_from: bool) -> Hash {
    let mut cur = from;
    let mut first = true;
    loop {
        let (ts, level, ps): (u64, u8, Vec<Hash>) = {
            let i = node.get(cur).await;
            (i.header.timestamp, i.level, i.header.parents_by_level.get(lmax as usize).map(|p| p.to_vec()).unwrap_or_default())
        };
        if ts <= cutoff && level >= lmax && !(first && skip_from) {
            return cur;
        }
        first = false;
        assert!(!ps.is_empty(), "block {cur} has no level-{lmax} parents");
        cur = ps[0];
    }
}

/// One more page of the selected chain after its current last block (no accepted ids: the batch is then
/// ~1,800 chain blocks, about 22 minutes). Returns false when the node has nothing newer.
async fn extend_chain(node: &mut Node, chain: &mut Vec<Hash>) -> bool {
    let last = *chain.last().expect("empty chain");
    let vc = node.client.get_virtual_chain_from_block(last, false, None).await.expect("get_virtual_chain_from_block");
    node.calls += 1;
    let before = chain.len();
    for x in vc.added_chain_block_hashes {
        if !chain.contains(&x) {
            chain.push(x);
        }
    }
    chain.len() > before
}

fn quantile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

/// v1 step 1. The chain-qualification fix (Michael Sutton, 2026-10-15) rests on two facts:
///   (a) every chain block's first parent (parents_by_level[0][0]) is its selected parent; v2.1.0 enforces this as a
///       chain-qualification rule (utxo_validation.rs, WrongSelectedParentOrder), so a first-parent walk from a
///       chain block follows the selected chain;
///   (b) honest miners put the qualified sink first, so a superblock's first parent attests that block's
///       qualification. How often a counted superblock's first parent is a chain block, and how far behind it the
///       first parent sits, decides what the guest may require of the attesting superblocks.
/// is_chain is the node's current view; the newest --margin-min minutes are skipped so tip reorgs do not count.
async fn check_first_parent(node: &mut Node, count: usize, levels: &[u8], margin_ms: u64, out: &str, source: &str) {
    let t0 = std::time::Instant::now();
    let dag = node.client.get_block_dag_info().await.expect("get_block_dag_info");
    let sink = dag.sink;
    let sink_ts = node.get(sink).await.header.timestamp;

    // the newest chain block at least margin_ms older than the sink
    let mut cur = sink;
    loop {
        let (ts, sp) = {
            let i = node.get(cur).await;
            (i.header.timestamp, i.selected_parent)
        };
        if ts + margin_ms <= sink_ts {
            break;
        }
        cur = sp;
    }
    let top = cur;

    // (a) the chain, by the node's selected parents
    let mut chain: Vec<Hash> = Vec::with_capacity(count);
    let mut chain_set: HashSet<Hash> = HashSet::new();
    let mut mismatches = Vec::new();
    let mut not_chain = Vec::new();
    let mut nparents: BTreeMap<usize, u32> = BTreeMap::new();
    for _ in 0..count {
        let (is_chain, sp, fp, np) = {
            let i = node.get(cur).await;
            let p0 = i.header.parents_by_level.get(0).map(|p| p.to_vec()).unwrap_or_default();
            (i.is_chain, i.selected_parent, p0.first().copied(), p0.len())
        };
        *nparents.entry(np).or_default() += 1;
        if !is_chain {
            not_chain.push(cur.to_string());
        }
        if fp != Some(sp) {
            mismatches.push(json!({ "block": cur.to_string(), "first_parent": fp.map(|x| x.to_string()), "selected_parent": sp.to_string() }));
        }
        chain.push(cur);
        chain_set.insert(cur);
        cur = sp;
    }
    let bottom = *chain.last().unwrap();
    let (top_daa, top_ts) = {
        let i = node.get(top).await;
        (i.header.daa_score, i.header.timestamp)
    };
    let (floor_daa, bottom_ts) = {
        let i = node.get(bottom).await;
        (i.header.daa_score, i.header.timestamp)
    };
    // the same chain again, this time by first parents only (what the guest will do), from the top down
    let mut fp_walk_ok = true;
    let mut x = top;
    for (n, &expect) in chain.iter().enumerate() {
        if x != expect {
            println!("first-parent walk leaves the selected chain at step {n}: {x} vs {expect}");
            fp_walk_ok = false;
            break;
        }
        if n + 1 < chain.len() {
            x = node.get(x).await.header.parents_by_level.get(0).and_then(|p| p.first().copied()).expect("no direct parents");
        }
    }
    let span_h = (top_ts - bottom_ts) as f64 / 3.6e6;
    println!("span          : {count} chain blocks, top {top} (daa {top_daa}) .. bottom {bottom} (daa {floor_daa}), {span_h:.2} h, {:.2} chain blocks/s", count as f64 / (span_h * 3600.0));
    println!("chain check   : first parent == selected parent on {}/{} chain blocks; not chain per node: {}; first-parent walk == selected chain: {}", count - mismatches.len(), count, not_chain.len(), fp_walk_ok);
    println!("direct parents: {:?} (count -> chain blocks)", nparents);
    for m in mismatches.iter().take(10) {
        println!("  MISMATCH {m}");
    }

    // (b) every superblock per level in (floor_daa, top_daa], by a closed walk from the sink
    println!();
    println!(
        "{:>5} {:>7} {:>7} {:>9} {:>9} {:>9} {:>8} {:>8} {:>8} {:>8}",
        "level", "blocks", "chain", "fp chain", "fp==sp", "fp in sp", "lag p50", "lag p90", "lag p99", "lag max"
    );
    let mut per_level = Vec::new();
    for &lv in levels {
        let mut seen: HashSet<Hash> = HashSet::from([sink]);
        let mut q: VecDeque<Hash> = VecDeque::from([sink]);
        let (mut total, mut x_chain, mut fp_chain, mut fp_is_sp, mut fp_in_span) = (0u32, 0u32, 0u32, 0u32, 0u32);
        let mut lags: Vec<u64> = Vec::new();
        let mut exceptions = Vec::new();
        let mut steps_hist = [0u32; MAX_FP_STEPS + 1]; // [0] = no chain block within MAX_FP_STEPS
        while let Some(x) = q.pop_front() {
            let (daa, level, ps, fp, sp, xc) = {
                let i = node.get(x).await;
                (
                    i.header.daa_score,
                    i.level,
                    i.header.parents_by_level.get(lv as usize).map(|p| p.to_vec()).unwrap_or_default(),
                    i.header.parents_by_level.get(0).and_then(|p| p.first().copied()),
                    i.selected_parent,
                    i.is_chain,
                )
            };
            if daa <= floor_daa {
                continue;
            }
            if x != sink {
                assert!(level >= lv, "level {lv}: block {x} (level {level}) reached through level-{lv} parents");
            }
            for p in ps {
                if seen.insert(p) {
                    q.push_back(p);
                }
            }
            if level < lv || daa > top_daa {
                continue;
            }
            total += 1;
            if xc {
                x_chain += 1;
            }
            let fp = fp.expect("no direct parents");
            let (fpc, fp_daa) = {
                let i = node.get(fp).await;
                (i.is_chain, i.header.daa_score)
            };
            if fpc {
                fp_chain += 1;
            }
            if fp == sp {
                fp_is_sp += 1;
            }
            if chain_set.contains(&fp) {
                fp_in_span += 1;
            }
            let lag = daa.saturating_sub(fp_daa);
            lags.push(lag);
            // O5: how many first-parent steps until a chain block (1 = the first parent itself). Sizes the
            // non-direct-attesters extension (docs/RELAY-V1-DESIGN.md, 8.1).
            let mut reach: Option<usize> = if fpc { Some(1) } else { None };
            let mut cur = fp;
            let mut s = 1usize;
            while reach.is_none() && s < MAX_FP_STEPS {
                let next = node.get(cur).await.header.parents_by_level.get(0).and_then(|p| p.first().copied()).expect("no direct parents");
                s += 1;
                if node.get(next).await.is_chain {
                    reach = Some(s);
                }
                cur = next;
            }
            match reach {
                Some(k) => steps_hist[k] += 1,
                None => steps_hist[0] += 1,
            }
            if (!fpc || fp != sp) && exceptions.len() < 20 {
                exceptions.push(json!({ "block": x.to_string(), "daa": daa, "is_chain": xc, "first_parent": fp.to_string(), "first_parent_is_chain": fpc, "selected_parent": sp.to_string(), "lag_daa": lag }));
            }
        }
        lags.sort_unstable();
        let (p50, p90, p99, pmax) = (quantile(&lags, 0.5), quantile(&lags, 0.9), quantile(&lags, 0.99), lags.last().copied().unwrap_or(0));
        println!("{:>5} {:>7} {:>7} {:>9} {:>9} {:>9} {:>8} {:>8} {:>8} {:>8}", lv, total, x_chain, fp_chain, fp_is_sp, fp_in_span, p50, p90, p99, pmax);
        {
            let non_direct = total.saturating_sub(steps_hist[1]);
            let within2 = steps_hist[2];
            let within3 = steps_hist[2] + steps_hist[3];
            println!(
                "        first-parent steps to a chain block: 1: {}  2: {}  3: {}  4: {}  5: {}  none within {}: {}   non-direct {}: {} join within 2 steps, {} within 3",
                steps_hist[1], steps_hist[2], steps_hist[3], steps_hist[4], steps_hist[5], MAX_FP_STEPS, steps_hist[0], non_direct, within2, within3
            );
        }
        for e in exceptions.iter().take(5) {
            println!("        exception {e}");
        }
        per_level.push(json!({
            "level": lv, "blocks": total, "chain": x_chain, "first_parent_chain": fp_chain, "first_parent_is_selected_parent": fp_is_sp,
            "first_parent_in_span": fp_in_span,
            "first_parent_steps_hist": steps_hist.iter().enumerate().map(|(k, v)| json!([if k == 0 { "none".to_string() } else { k.to_string() }, v])).collect::<Vec<_>>(),
            "lag_daa": { "p50": p50, "p90": p90, "p99": p99, "max": pmax }, "exceptions": exceptions,
        }));
    }
    println!("(lag = superblock daa_score minus its first parent's; ~10 DAA per second)");
    println!();
    println!("rpc calls     : {} in {:.1} s", node.calls, t0.elapsed().as_secs_f64());

    let doc = json!({
        "source": source,
        "sink": sink.to_string(),
        "top": top.to_string(), "top_daa": top_daa,
        "bottom": bottom.to_string(), "bottom_daa": floor_daa,
        "count": count, "span_hours": span_h,
        "first_parent_eq_selected_parent": count - mismatches.len(),
        "mismatches": mismatches,
        "not_chain": not_chain,
        "first_parent_walk_equals_selected_chain": fp_walk_ok,
        "direct_parents_hist": nparents.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "levels": per_level,
    });
    std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap()).expect("write");
    println!("wrote         : {out}");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = arg(&args, "--url").unwrap_or_else(|| "ws://127.0.0.1:17110".into());
    let start_arg = arg(&args, "--start");
    let levels: Vec<u8> = arg(&args, "--levels").unwrap_or_else(|| "28,30,32".into()).split(',').map(|s| s.trim().parse().expect("--levels")).collect();
    let hours: f64 = arg(&args, "--hours").unwrap_or_else(|| "1".into()).parse().expect("--hours");
    let b_arg = arg(&args, "--b").map(|s| h(&s));
    let t_arg = arg(&args, "--t").map(|s| h(&s));
    let k_arg = arg(&args, "--k").map(|s| h(&s));
    let token_arg = arg(&args, "--token").map(|s| h(&s));
    let depth_daa: u64 = arg(&args, "--depth-daa").unwrap_or_else(|| "6000".into()).parse().expect("--depth-daa");
    let cmp_level: u8 = arg(&args, "--cmp-level").unwrap_or_else(|| "30".into()).parse().expect("--cmp-level");
    let min_attest: u32 = arg(&args, "--min-attest").unwrap_or_else(|| "100".into()).parse().expect("--min-attest");
    let min_count: u32 = arg(&args, "--min-count").unwrap_or_else(|| "100".into()).parse().expect("--min-count");
    let pick_k = args.iter().any(|a| a == "--pick-k");
    let check_fp = args.iter().any(|a| a == "--check-first-parent");
    let out_path = arg(&args, "--out").unwrap_or_else(|| "witness.json".into());
    assert!(!levels.is_empty() && levels.windows(2).all(|p| p[0] < p[1]), "--levels must be ascending");
    let lmax = *levels.last().unwrap();

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
    let source = format!("{} {}", info.network_id, info.server_version);
    let mut node = Node { client, cache: HashMap::new(), calls: 0 };

    if check_fp {
        let count: usize = arg(&args, "--count").unwrap_or_else(|| "5000".into()).parse().expect("--count");
        let margin_min: f64 = arg(&args, "--margin-min").unwrap_or_else(|| "2".into()).parse().expect("--margin-min");
        let out = arg(&args, "--out").unwrap_or_else(|| "first-parent-check.json".into());
        check_first_parent(&mut node, count, &levels, (margin_min * 60_000.0) as u64, &out, &source).await;
        node.client.disconnect().await.ok();
        return;
    }

    if pick_k {
        let dag = node.client.get_block_dag_info().await.expect("get_block_dag_info");
        let sink = dag.sink;
        let (sink_ts, sink_daa) = {
            let i = node.get(sink).await;
            (i.header.timestamp, i.header.daa_score)
        };
        let k = walk_back(&mut node, sink, lmax, sink_ts.saturating_sub((hours * 3600.0 * 1000.0) as u64), true).await;
        let i = node.get(k).await;
        println!("sink          : {sink} (daa {sink_daa})");
        println!("checkpoint K  : {k} (level {}, daa {}, chain block {}, {:.1} min before the sink)", i.level, i.header.daa_score, i.is_chain, (sink_ts - i.header.timestamp) as f64 / 60_000.0);
        println!("\nCHECKPOINT=0x{k} CHECKPOINT_DAA={}", i.header.daa_score);
        println!("GENESIS_BITS=0x{:08x}  (the relay's first difficulty reading, V4-DESIGN 2.11.4; the block above)", i.header.bits);
        return;
    }

    // 1. per burn: the chain block C that accepted it; the chain after --start
    let start = h(&start_arg.expect("--start <chain block hash from before the burn, e.g. the sink burn.mjs printed>"));
    let txids: Vec<Hash> = arg(&args, "--txid").expect("--txid <id>[,<id>...]").split(',').map(|t| h(t.trim())).collect();
    assert!(!txids.is_empty() && txids.len() <= 16, "1 to 16 burns");
    let token = token_arg.expect("--token <covenant id of the KCC-20 token whose burn cells to read>");
    println!("token         : {token}");
    // getVirtualChainFromBlock returns one batch (about 1,800 merged blocks with accepted ids, ~3 min of chain on
    // mainnet; 1,800 chain blocks without), so the chain is paged: with accepted ids until every burn's accepting
    // block is found, then without them as far as T needs (see `extend_chain`).
    let lk = lane_key(&NATIVE_LANE);
    let mut chain: Vec<Hash> = Vec::new();
    let mut accepted_entries = Vec::new();
    let mut cursor = start;
    loop {
        let vc = node.client.get_virtual_chain_from_block(cursor, true, None).await.expect("get_virtual_chain_from_block");
        node.calls += 1;
        if vc.added_chain_block_hashes.is_empty() {
            break;
        }
        chain.extend(vc.added_chain_block_hashes.iter().copied());
        accepted_entries.extend(vc.accepted_transaction_ids.into_iter());
        cursor = *chain.last().unwrap();
        let all_found = txids.iter().all(|t| accepted_entries.iter().any(|e: &kaspa_rpc_core::RpcAcceptedTransactionIds| e.accepted_transaction_ids.iter().any(|x| x == t)));
        if all_found {
            break;
        }
    }
    println!("chain         : {} chain blocks after start in {} page(s)", chain.len(), node.calls);

    struct BurnRec {
        txid: Hash,
        c: Hash,
        idx_c: usize,
        sp: Hash,
        sp_ts: u64,
        c_daa: u64,
        c_blue: u64,
        c_aimr: Hash,
        tx: Transaction,
        version: u16,
        native_leaves: Vec<(Hash, u16, u32)>,
        leaf_index: u32,
        resp: GetSeqCommitLaneProofResponse,
        lane_tip: Hash,
        lane_bs: u64,
        parent_ref: Hash,
        ad: Hash,
        ctx: Hash,
        lanes_root: Hash,
        sc_c: Hash,
        cells: Vec<(u32, u64)>,
    }
    let mut recs: Vec<BurnRec> = Vec::new();
    for &txid in &txids {
        let entry = accepted_entries
            .iter()
            .find(|e| e.accepted_transaction_ids.iter().any(|t| *t == txid))
            .unwrap_or_else(|| panic!("tx {txid} is not accepted by any chain block after {start} (not mined yet, or --start is too late)"));
        let c = entry.accepting_block_hash;
        let accepted: Vec<Hash> = entry.accepted_transaction_ids.clone();
        let idx_c = chain.iter().position(|x| *x == c).expect("C is not in the added chain list");
        let (c_daa, c_blue, c_aimr, sp, c_blues, c_reds) = {
            let i = node.get(c).await;
            assert!(i.is_chain, "C {c} is not a chain block");
            (i.header.daa_score, i.header.blue_score, i.header.accepted_id_merkle_root, i.selected_parent, i.blues.clone(), i.reds.clone())
        };
        let (sp_ts, sp_aimr) = {
            let i = node.get(sp).await;
            (i.header.timestamp, i.header.accepted_id_merkle_root)
        };
        println!("burn          : tx {txid}");
        println!("accepted in C : {c} (daa {c_daa}, blue score {c_blue}), selected parent {sp}");

        // 2. the activity of C: every accepted tx in global merge order, with version and lane
        let mut merged: Vec<Hash> = vec![sp];
        for x in c_blues.iter().chain(c_reds.iter()) {
            if !merged.contains(x) {
                merged.push(*x);
            }
        }
        let mut txmap: HashMap<Hash, (u16, [u8; 20], RpcTransaction)> = HashMap::new();
        for m in &merged {
            for t in node.txs(*m).await {
                let id = t.verbose_data.as_ref().expect("tx verbose data").transaction_id;
                txmap.insert(id, (t.version, *t.subnetwork_id.as_bytes(), t));
            }
        }
        let mut lane_leaves: BTreeMap<[u8; 20], Vec<Hash>> = BTreeMap::new();
        let mut native_leaves: Vec<(Hash, u16, u32)> = Vec::new();
        let mut leaf_index: Option<u32> = None;
        for (gi, id) in accepted.iter().enumerate() {
            let (ver, lane, _) = txmap.get(id).unwrap_or_else(|| panic!("accepted tx {id} not found in the mergeset blocks of C"));
            lane_leaves.entry(*lane).or_default().push(activity_leaf(id, *ver, gi as u32));
            if *lane == NATIVE_LANE {
                if *id == txid {
                    leaf_index = Some(native_leaves.len() as u32);
                }
                native_leaves.push((*id, *ver, gi as u32));
            }
        }
        let leaf_index = leaf_index.expect("burn tx is not in the native lane");
        let (version, _, burn_rpc) = txmap.get(&txid).unwrap().clone();
        let tx: Transaction = burn_rpc.clone().try_into().expect("rpc tx -> consensus tx");
        assert_eq!(tx.id(), txid, "consensus id of the burn body differs from the accepted id");
        println!("activity      : {} accepted txs in C over {} lanes; native lane {} txs, burn at index {}", accepted.len(), lane_leaves.len(), native_leaves.len(), leaf_index);

        // 3. the lane witness at C and the parent reference at the selected parent
        let resp = node.lane_proof(c, lk).await;
        let lane_c = resp.lane.clone().expect("native lane has no entry at C");
        let resp_sp = node.lane_proof(sp, lk).await;
        let parent_ref = resp_sp.lane.as_ref().map(|l| l.tip).unwrap_or(sp_aimr);
        assert_eq!(resp.parent_seq_commit, sp_aimr, "parent_seq_commit at C is not the selected parent's accepted_id_merkle_root");
        let ad = activity_digest_lane(lane_leaves[&NATIVE_LANE].iter().copied());
        let ctx = mergeset_context_hash(&MergesetContext { timestamp: sp_ts, daa_score: c_daa, blue_score: c_blue });
        let tip = lane_tip_next(&LaneTipInput { parent_ref: &parent_ref, lane_key: &lk, activity_digest: &ad, context_hash: &ctx });
        println!("lane tip      : {} {}", if tip == lane_c.tip { "ok  " } else { "DIFF" }, tip);
        if tip != lane_c.tip {
            println!("                node says {}", lane_c.tip);
        }
        if lane_c.blue_score != c_blue {
            println!("warning       : lane entry blue score {} differs from C's blue score {}", lane_c.blue_score, c_blue);
        }
        let (state_root_c, lanes_root) = state_root_of(&resp, lk);
        let sc_c = seq_commit(&SeqCommitInput { parent_seq_commit: &resp.parent_seq_commit, state_root: &state_root_c });
        println!("seq_commit(C) : {} {}", if sc_c == c_aimr { "ok  " } else { "DIFF" }, sc_c);
        if sc_c != c_aimr {
            println!("                header says {c_aimr}");
        }
        // U4: the token's burn cells. Their amounts are inside the P2SH hashes; the spender's transfer names them
        // (cells.rs), and each is checked by rebuilding its redeem and hashing it.
        let burn_cells: Vec<(u32, u64)> = {
            let outs: Vec<cells::Out> = tx
                .outputs
                .iter()
                .map(|o| cells::Out { spk_version: o.script_public_key.version(), script: o.script_public_key.script(), covenant_id: o.covenant.as_ref().map(|c| c.covenant_id.as_bytes()) })
                .collect();
            let sigs: Vec<&[u8]> = tx.inputs.iter().map(|i| i.signature_script.as_slice()).collect();
            cells::burn_cells(&outs, &sigs, &token.as_bytes())
        };
        assert!(!burn_cells.is_empty(), "tx {txid} creates no burn cell of token {token} (a holder's transfer to the burn owner, scheme 3)");
        let foreign = tx.outputs.iter().filter(|o| o.covenant.as_ref().is_some_and(|c| c.covenant_id != token)).count();
        assert!(foreign == 0, "tx {txid} has {foreign} covenant output(s) outside the token's family; the guest refuses it");
        let amount: u64 = burn_cells.iter().map(|(_, a)| a).sum();
        let pl = &tx.payload;
        if pl.len() == 53 && &pl[..4] == b"KZB1" && pl[4] == 2 {
            let tip = u64::from_be_bytes(pl[25..33].try_into().unwrap());
            println!("burn cells    : {:?} (output, units), {} units; payload v2 target 0x{} tip {} recipient 0x{}", burn_cells, amount, hex::encode(&pl[5..25]), tip, hex::encode(&pl[33..53]));
            assert!(tip <= amount, "tip {tip} exceeds the burned amount {amount}; the guest refuses it");
        } else if pl.len() == 93 && &pl[..4] == b"KZB1" && pl[4] == 3 {
            // S3b: payload v3, read by guest v3 (KZO4) only
            let tip = u64::from_be_bytes(pl[25..33].try_into().unwrap());
            let bn = u64::from_be_bytes(pl[53..61].try_into().unwrap());
            println!("burn cells    : {:?} (output, units), {} units; payload v3 target 0x{} tip {} recipient 0x{} beacon block {} 0x{}", burn_cells, amount, hex::encode(&pl[5..25]), tip, hex::encode(&pl[33..53]), bn, hex::encode(&pl[61..93]));
            assert!(tip < amount, "tip {tip} is not below the burned amount {amount}; guest v3 refuses it");
            assert!((bn == 0) == pl[61..93].iter().all(|b| *b == 0), "payload v3 beacon is half empty; guest v3 refuses it");
        } else {
            println!("burn cells    : {:?}, {} units; payload 0x{} (not a v2 payload, nor v3: the guests will refuse it)", burn_cells, amount, hex::encode(pl));
        }
        recs.push(BurnRec { txid, c, idx_c, sp, sp_ts, c_daa, c_blue, c_aimr, tx, version, native_leaves, leaf_index, resp, lane_tip: lane_c.tip, lane_bs: lane_c.blue_score, parent_ref, ad, ctx, lanes_root, sc_c, cells: burn_cells });
        println!();
    }

    // 4. B = the chain block that accepted the latest burn (or --b, a chain block at or after it): every burn's
    //    commitment chain ends at B.aimr. v1 no longer needs B to be a superblock: its commitment is pinned by the
    //    chain blocks after it (step 7), not by its own PoW.
    let idx_last = recs.iter().map(|r| r.idx_c).max().unwrap();
    let b = b_arg.unwrap_or(chain[idx_last]);
    let idx_b = chain.iter().position(|x| *x == b).expect("B is not in the added chain list");
    assert!(idx_b >= idx_last, "B comes before a burn's C");
    let (b_daa, b_aimr, b_level) = {
        let i = node.get(b).await;
        assert!(i.is_chain, "B must be a chain block");
        (i.header.daa_score, i.header.accepted_id_merkle_root, i.level)
    };

    // 5. T = the proof tip: --t, or the first chain block at level >= lmax with daa_score >= B.daa + --depth-daa.
    //    The ladders are walked from T; T becomes the relay's next checkpoint.
    let t = match t_arg {
        Some(th) => {
            while !chain.contains(&th) {
                assert!(extend_chain(&mut node, &mut chain).await, "--t {th} is not on the selected chain after --start");
            }
            th
        }
        None => {
            let mut found = None;
            let mut from = idx_b;
            loop {
                for &x in chain.iter().skip(from) {
                    let i = node.get(x).await;
                    if i.level >= lmax && i.header.daa_score >= b_daa + depth_daa {
                        found = Some(x);
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
                from = chain.len();
                if !extend_chain(&mut node, &mut chain).await {
                    let tip_daa = node.get(*chain.last().unwrap()).await.header.daa_score;
                    panic!("no chain block at level >= {lmax} with daa >= B.daa + {depth_daa} yet (chain tip daa {tip_daa}, {} DAA to go before a level-{lmax} chain block can qualify); wait and rerun (or pass --t)", (b_daa + depth_daa).saturating_sub(tip_daa));
                }
            }
            found.unwrap()
        }
    };
    let idx_t = chain.iter().position(|x| *x == t).expect("T is not in the added chain list");
    assert!(idx_t >= idx_b, "T comes before B");
    let (t_daa, t_ts, t_level) = {
        let i = node.get(t).await;
        assert!(i.is_chain, "T must be a chain block");
        assert!(i.level >= lmax, "T is at level {} < {lmax}", i.level);
        (i.header.daa_score, i.header.timestamp, i.level)
    };

    // 6. state roots of every chain block after the earliest C through T, computed once and checked against
    //    each header's accepted_id_merkle_root; per burn (C, B], and the attestation chain (B, T]
    let idx_first = recs.iter().map(|r| r.idx_c).min().unwrap();
    let mut roots: HashMap<Hash, Hash> = HashMap::new();
    for &x in &chain[idx_first + 1..=idx_t] {
        let r = node.lane_proof(x, lk).await;
        let (sr, _) = state_root_of(&r, lk);
        let aimr = node.get(x).await.header.accepted_id_merkle_root;
        let sc = seq_commit(&SeqCommitInput { parent_seq_commit: &r.parent_seq_commit, state_root: &sr });
        assert_eq!(sc, aimr, "chain block {x}: recomputed seq_commit differs from its header");
        roots.insert(x, sr);
    }
    let mut chain_roots_per_burn: Vec<Vec<Hash>> = Vec::new();
    for r in &recs {
        let mut sc = r.sc_c;
        let mut v = Vec::new();
        for &x in &chain[r.idx_c + 1..=idx_b] {
            let sr = roots[&x];
            sc = seq_commit(&SeqCommitInput { parent_seq_commit: &sc, state_root: &sr });
            v.push(sr);
        }
        assert_eq!(sc, b_aimr, "burn {}: seq_commit chain from C does not end at B's accepted_id_merkle_root", r.txid);
        chain_roots_per_burn.push(v);
    }
    let attest_roots: Vec<Hash> = chain[idx_b + 1..=idx_t].iter().map(|x| roots[x]).collect();
    {
        let mut sc = b_aimr;
        for &x in &chain[idx_b + 1..=idx_t] {
            sc = seq_commit(&SeqCommitInput { parent_seq_commit: &sc, state_root: &roots[&x] });
            assert_eq!(sc, node.get(x).await.header.accepted_id_merkle_root, "attestation chain: commitment at {x} differs from its header");
        }
    }
    // chain position of every chain block in [B, T], for the attestation check below
    let chain_pos: HashMap<Hash, usize> = chain[idx_b..=idx_t].iter().enumerate().map(|(i, x)| (*x, i)).collect();
    println!("attested B    : {b} (level {b_level}, daa {b_daa}), {} chain blocks after the last C, seq_commit chains ok", idx_b - idx_last);
    println!("tip T         : {t} (level {t_level}, daa {t_daa}), {} chain blocks after B ({} DAA, {:.1} min)", idx_t - idx_b, t_daa - b_daa, (t_daa - b_daa) as f64 / 600.0);

    // 7. (v4, V4-DESIGN 2.11) no checkpoint: the ladders end at B. --k and --hours are accepted and ignored.
    if k_arg.is_some() {
        println!("note          : --k is ignored since v4 (the ladder is anchored at B, no checkpoint)");
    }
    let _ = (hours, t_ts);
    assert!(t_daa > b_daa, "T (daa {t_daa}) is not past B (daa {b_daa})");

    // 8. ladders from T down to B, and per counted superblock the attestation check: first parent Y on the chain [B, T]
    let mut all: HashSet<Hash> = HashSet::from([t, b]);
    let mut ys: HashSet<Hash> = HashSet::new();
    let mut ys_late: HashSet<Hash> = HashSet::new();
    let mut per_level = Vec::new();
    println!();
    println!("{:>5} {:>8} {:>9} {:>8} {:>8} {:>8}", "level", "counted", "attesting", "leaves", "visited", "max par");
    for &lv in &levels {
        let mut seen: HashSet<Hash> = HashSet::from([t]);
        let mut q: VecDeque<Hash> = VecDeque::from([t]);
        let mut count = 0u32;
        let mut attesting = 0u32;
        let mut leaves = 0u32;
        let mut max_par = 0usize;
        let mut visited: Vec<Hash> = Vec::new();
        let mut level_ys: HashSet<Hash> = HashSet::new();
        let mut by_steps = [0u32; RULE_FP_STEPS + 1];
        let mut joins_late = 0u32;
        let mut deep_paths: Vec<Vec<String>> = Vec::new();
        let mut late_paths: Vec<Vec<String>> = Vec::new();
        while let Some(x) = q.pop_front() {
            visited.push(x);
            let (daa, level, ps, fp): (u64, u8, Vec<Hash>, Hash) = {
                let i = node.get(x).await;
                (
                    i.header.daa_score,
                    i.level,
                    i.header.parents_by_level.get(lv as usize).map(|p| p.to_vec()).unwrap_or_default(),
                    i.header.parents_by_level.get(0).and_then(|p| p.first().copied()).expect("no direct parents"),
                )
            };
            if daa <= b_daa {
                leaves += 1;
                continue;
            }
            assert!(level >= lv, "level {lv}: block {x} (level {level}) reached through level-{lv} parents");
            count += 1;
            // U4: the guest's three-step first-parent rule. Follow first parents from the superblock until a chain
            // block in [B, T]; a join within RULE_FP_STEPS hops attests and every header on the path goes into the
            // witness; a join at hop RULE_FP_STEPS + 1 is recorded for the adversarial suite (it must not attest).
            let mut path = vec![fp];
            let mut steps = None;
            loop {
                let y = *path.last().unwrap();
                if chain_pos.contains_key(&y) {
                    steps = Some(path.len());
                    break;
                }
                if path.len() > RULE_FP_STEPS {
                    break;
                }
                let next = node.get(y).await.header.parents_by_level.get(0).and_then(|p| p.first().copied()).expect("no direct parents");
                path.push(next);
            }
            match steps {
                Some(s) if s <= RULE_FP_STEPS => {
                    attesting += 1;
                    by_steps[s] += 1;
                    for y in &path {
                        ys.insert(*y);
                        level_ys.insert(*y);
                    }
                    if s > 1 {
                        deep_paths.push(path.iter().map(|x| x.to_string()).collect());
                    }
                }
                Some(_) => {
                    joins_late += 1;
                    ys_late.extend(path.iter().copied());
                    late_paths.push(path.iter().map(|x| x.to_string()).collect());
                }
                None => {}
            }
            max_par = max_par.max(ps.len());
            for p in ps {
                if seen.insert(p) {
                    q.push_back(p);
                }
            }
        }
        println!("{:>5} {:>8} {:>9} {:>8} {:>8} {:>8}", lv, count, attesting, leaves, visited.len(), max_par);
        println!("      attesting by first-parent hop 1/2/3: {}/{}/{}; joins at hop {} (not counted): {}", by_steps[1], by_steps[2], by_steps[3], RULE_FP_STEPS + 1, joins_late);
        all.extend(visited.iter().copied());
        per_level.push(json!({
            "level": lv, "count": count, "attesting": attesting, "leaves": leaves,
            "visited": visited.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
            "first_parents": level_ys.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
            "attesting_by_steps": by_steps[1..].to_vec(), "joins_late": joins_late, "deep_paths": deep_paths, "late_paths": late_paths,
        }));
    }

    // the relay contract requires MIN_ATTEST attesting superblocks at its comparison level; a witness below it would
    // be a wasted proof, so stop here and let the caller retry with a later T (more chain after B, more attesters)
    if let Some(p) = per_level.iter().find(|p| p["level"] == cmp_level) {
        let (c, a) = (p["count"].as_u64().unwrap_or(0), p["attesting"].as_u64().unwrap_or(0));
        assert!(
            c >= min_count as u64,
            "only {c} superblocks at level {cmp_level} after B (relay floor {min_count}, ~{:.0} more minutes of chain needed); wait and rerun with a larger --depth-daa or --t",
            (min_count as f64 - c as f64) / 9.0
        );
        assert!(
            a >= min_attest as u64,
            "only {a} attesting superblocks at level {cmp_level} after B (relay needs {min_attest}); wait and rerun with a larger --depth-daa or --t"
        );
    }

    // O5: real blocks that are NOT chain blocks (from the mergesets of chain blocks in (B, T]), recorded with their
    // headers so the adversarial tests can present one as B. The node's data cannot make a burn's commitment chain
    // end at such a block; only its miner's state root could, which is the forged-B case in the tests.
    let extra_n: usize = arg(&args, "--extra-nonchain").map(|s| s.parse().expect("--extra-nonchain")).unwrap_or(0);
    let mut extra_headers = Vec::new();
    if extra_n > 0 {
        let chain_all: HashSet<Hash> = chain.iter().copied().collect();
        'extra: for &x in &chain[idx_b + 1..=idx_t] {
            let cands: Vec<Hash> = {
                let i = node.get(x).await;
                i.blues.iter().chain(i.reds.iter()).copied().filter(|p| !chain_all.contains(p)).collect()
            };
            for p in cands {
                let (is_chain, sp, daa, level) = {
                    let i = node.get(p).await;
                    (i.is_chain, i.selected_parent, i.header.daa_score, i.level)
                };
                if is_chain || all.contains(&p) || ys.contains(&p) {
                    continue;
                }
                let pre = header_preimage(&node.get(p).await.header);
                extra_headers.push(json!({
                    "hash": p.to_string(), "preimage": format!("0x{}", hex::encode(&pre)), "is_chain": false,
                    "selected_parent": sp.to_string(), "selected_parent_is_chain": chain_all.contains(&sp),
                    "daa_score": daa, "level": level,
                }));
                if extra_headers.len() >= extra_n {
                    break 'extra;
                }
            }
        }
        println!("extra headers : {} real non-chain block(s) from the mergesets of chain blocks in (B, T] (O5 adversarial tests)", extra_headers.len());
    }

    // 9. serialize every header once: the PoW-verified set, then the first-parent headers not already in it
    let mut headers = Vec::with_capacity(all.len());
    let mut bytes = 0usize;
    for x in &all {
        let pre = header_preimage(&node.get(*x).await.header);
        bytes += pre.len();
        headers.push(json!({ "hash": x.to_string(), "preimage": format!("0x{}", hex::encode(&pre)) }));
    }
    let mut y_headers = Vec::new();
    let mut y_bytes = 0usize;
    let mut y_in_ladder = 0usize;
    for y in &ys {
        // every first parent is listed, ladder members included: the host drops the ones already among the
        // PoW-verified headers for the levels it proves (a subset of levels has a smaller ladder)
        if all.contains(y) {
            y_in_ladder += 1;
        }
        let pre = header_preimage(&node.get(*y).await.header);
        y_bytes += pre.len();
        y_headers.push(json!({ "hash": y.to_string(), "preimage": format!("0x{}", hex::encode(&pre)) }));
    }
    println!();
    let mut y_late_headers = Vec::new();
    for y in &ys_late {
        if all.contains(y) || ys.contains(y) {
            continue;
        }
        let pre = header_preimage(&node.get(*y).await.header);
        y_late_headers.push(json!({ "hash": y.to_string(), "preimage": format!("0x{}", hex::encode(&pre)) }));
    }
    println!("late joins    : {} header(s) on hop-{} paths, recorded for the adversarial suite (not in the proof)", y_late_headers.len(), RULE_FP_STEPS + 1);
    println!("headers       : {} unique PoW-verified ({} bytes, avg {}); first parents: {} distinct ({} bytes, avg {}), {} of them already in the ladder; attestation chain {} roots; rpc calls {}",
        all.len(), bytes, bytes / all.len().max(1), ys.len(), y_bytes, y_bytes / y_headers.len().max(1), y_in_ladder, attest_roots.len(), node.calls);

    // 10. the burn bodies in the guest's field layout
    let mut burns_json = Vec::new();
    for (r, croots) in recs.iter().zip(chain_roots_per_burn.iter()) {
        let tx = &r.tx;
        let body = json!({
            "version": tx.version,
            "inputs": tx.inputs.iter().map(|i| json!({ "txid": i.previous_outpoint.transaction_id.to_string(), "index": i.previous_outpoint.index, "sequence": i.sequence })).collect::<Vec<_>>(),
            "outputs": tx.outputs.iter().map(|o| json!({
                "value": o.value,
                "spk_version": o.script_public_key.version(),
                "script": format!("0x{}", hex::encode(o.script_public_key.script())),
                "covenant": o.covenant.as_ref().map(|cv| json!({ "authorizing_input": cv.authorizing_input, "covenant_id": cv.covenant_id.to_string() })),
            })).collect::<Vec<_>>(),
            "lock_time": tx.lock_time,
            "subnetwork_id": format!("0x{}", hex::encode(tx.subnetwork_id.as_bytes())),
            "gas": tx.gas,
            "payload": format!("0x{}", hex::encode(&tx.payload)),
        });
        burns_json.push(json!({
            "txid": r.txid.to_string(),
            "version": r.version,
            "cells": r.cells.iter().map(|(i, a)| json!({ "index": i, "amount": a })).collect::<Vec<_>>(),
            "body": body,
            "c": r.c.to_string(),
            "sp": r.sp.to_string(),
            "b": b.to_string(),
            "sp_timestamp": r.sp_ts,
            "c_daa_score": r.c_daa,
            "c_blue_score": r.c_blue,
            "leaves": r.native_leaves.iter().map(|(id, v, i)| json!({ "txid": id.to_string(), "version": v, "merge_idx": i })).collect::<Vec<_>>(),
            "leaf_index": r.leaf_index,
            "parent_ref": r.parent_ref.to_string(),
            "lane_blue_score": r.lane_bs,
            "inactivity_shortcut": r.resp.inactivity_shortcut.to_string(),
            "payload_and_ctx_digest": r.resp.payload_and_ctx_digest.to_string(),
            "parent_seq_commit": r.resp.parent_seq_commit.to_string(),
            "smt_proof": format!("0x{}", hex::encode(&r.resp.smt_proof)),
            "chain_state_roots": croots.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
            "expected": {
                "activity_digest": r.ad.to_string(),
                "context_hash": r.ctx.to_string(),
                "lane_tip": r.lane_tip.to_string(),
                "lanes_root": r.lanes_root.to_string(),
                "seq_commit_c": r.c_aimr.to_string(),
                "b_accepted_id_merkle_root": b_aimr.to_string(),
            },
        }));
    }

    let doc = json!({
        "source": format!("{source} start {start}"),
        "format": 4,
        "token_cov_id": token.to_string(),
        "rule_fp_steps": RULE_FP_STEPS,
        "levels": levels,
        "t": t.to_string(),
        "b": b.to_string(),
        "t_daa_score": t_daa,
        "b_daa_score": b_daa,
        "depth_daa": depth_daa,
        "hours": hours,
        "headers": headers,
        "y_headers": y_headers,
        "y_late_headers": y_late_headers,
        "attest_roots": attest_roots.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "per_level": per_level,
        "burns": burns_json,
        "extra_headers": extra_headers,
    });
    std::fs::write(&out_path, serde_json::to_string(&doc).unwrap()).expect("write");
    println!("wrote         : {out_path}");
    node.client.disconnect().await.ok();
}

