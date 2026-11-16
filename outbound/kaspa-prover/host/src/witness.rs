//! witness.json (burnwitness) -> the relay guest's `Witness`. Moved out of main.rs for O5 so the adversarial tests
//! (`adversarial.rs`) build the same witness the `relay` subcommand proves.
//!
//! Format 3 (U4, relay guest v2, `KZO3`): token burns. The file names the token's covenant id and, per burn, the
//! burn cells `(output index, amount)` burnwitness read from the spender's transfer; per level, how many attesters
//! joined the chain at each first-parent hop (1 to 3, the guest's rule) and the paths that join only at hop 4
//! (`y_late_headers`, adversarial material that must not attest). Format 2 (v1, KAS burns) is refused: the KAS
//! instance keeps the v1 tools at their git revision.
#![allow(dead_code)]

use crate::{unhex, unhex32};
use anyhow::{anyhow, Result};
use kaspa_prover_primitives::relay;
use serde::Deserialize;
use std::collections::HashSet;

/// 3 = burnwitness with K (v2/v3 guests); 4 = without K (v4, KZO5/KZO6). Both load; K is ignored. The prover's
/// address is not witness data (it is whoever proves): `relay --prover`.
pub(crate) const WITNESS_FORMATS: [u32; 2] = [3, 4];

#[derive(Deserialize)]
pub(crate) struct WFile {
    pub(crate) source: Option<String>,
    /// 3 = relay guest v2 (token burns, three-step attestation); anything else is refused
    pub(crate) format: Option<u32>,
    pub(crate) levels: Vec<u8>,
    /// format 3 only; ignored (v4 anchors the ladder at B)
    #[serde(default)]
    pub(crate) k: Option<String>,
    pub(crate) t: String,
    pub(crate) b: String,
    pub(crate) k_daa_score: Option<u64>,
    pub(crate) t_daa_score: Option<u64>,
    pub(crate) b_daa_score: Option<u64>,
    /// covenant id of the KCC-20 token whose burn cells the burns are
    #[serde(default)]
    pub(crate) token_cov_id: Option<String>,
    pub(crate) headers: Vec<WHeader>,
    #[serde(default)]
    pub(crate) y_headers: Vec<WHeader>,
    /// headers on first-parent paths that reach the chain only at hop 4 (not in the proof)
    #[serde(default)]
    pub(crate) y_late_headers: Vec<WHeader>,
    #[serde(default)]
    pub(crate) attest_roots: Vec<String>,
    pub(crate) per_level: Vec<WLevel>,
    pub(crate) burns: Vec<WBurn>,
    /// O5: real blocks that are NOT on the selected chain (from the mergesets of chain blocks in (B, T]),
    /// written by `burnwitness --extra-nonchain N`; the adversarial tests use them as a fake B.
    #[serde(default)]
    pub(crate) extra_headers: Vec<WExtra>,
}
#[derive(Deserialize)]
pub(crate) struct WHeader {
    pub(crate) hash: String,
    pub(crate) preimage: String,
}
#[derive(Deserialize)]
pub(crate) struct WExtra {
    pub(crate) hash: String,
    pub(crate) preimage: String,
    #[serde(default)]
    pub(crate) is_chain: bool,
    #[serde(default)]
    pub(crate) selected_parent: String,
    #[serde(default)]
    pub(crate) selected_parent_is_chain: bool,
    #[serde(default)]
    pub(crate) daa_score: u64,
    #[serde(default)]
    pub(crate) level: u8,
}
#[derive(Deserialize)]
pub(crate) struct WLevel {
    pub(crate) level: u8,
    pub(crate) count: u32,
    #[serde(default)]
    pub(crate) attesting: u32,
    pub(crate) visited: Vec<String>,
    /// every header on the first-parent paths of this level's attesting superblocks (hops 1 to 3)
    #[serde(default)]
    pub(crate) first_parents: Vec<String>,
    /// attesters by hop: [joined at hop 1, at hop 2, at hop 3]
    #[serde(default)]
    pub(crate) attesting_by_steps: Vec<u32>,
    /// superblocks whose path reaches the chain only at hop 4
    #[serde(default)]
    pub(crate) joins_late: u32,
    /// the paths of the attesters that joined at hop 2 or 3 (first parent first, the chain block last)
    #[serde(default)]
    pub(crate) deep_paths: Vec<Vec<String>>,
    /// the hop-4 paths
    #[serde(default)]
    pub(crate) late_paths: Vec<Vec<String>>,
}
#[derive(Deserialize)]
pub(crate) struct WBurn {
    pub(crate) txid: String,
    pub(crate) body: WTx,
    /// the burn cells of the tx: (output index, amount in token base units)
    #[serde(default)]
    pub(crate) cells: Vec<WCell>,
    pub(crate) c: String,
    pub(crate) b: String,
    pub(crate) sp_timestamp: u64,
    pub(crate) c_daa_score: u64,
    pub(crate) c_blue_score: u64,
    pub(crate) leaves: Vec<WLeaf>,
    pub(crate) leaf_index: u32,
    pub(crate) parent_ref: String,
    pub(crate) lane_blue_score: u64,
    pub(crate) inactivity_shortcut: String,
    pub(crate) payload_and_ctx_digest: String,
    pub(crate) parent_seq_commit: String,
    pub(crate) smt_proof: String,
    pub(crate) chain_state_roots: Vec<String>,
    pub(crate) expected: WExpected,
}
#[derive(Deserialize)]
pub(crate) struct WCell {
    pub(crate) index: u32,
    pub(crate) amount: u64,
}
#[derive(Deserialize)]
pub(crate) struct WTx {
    pub(crate) version: u16,
    pub(crate) inputs: Vec<WIn>,
    pub(crate) outputs: Vec<WOut>,
    pub(crate) lock_time: u64,
    pub(crate) subnetwork_id: String,
    pub(crate) gas: u64,
    pub(crate) payload: String,
}
#[derive(Deserialize)]
pub(crate) struct WIn {
    pub(crate) txid: String,
    pub(crate) index: u32,
    pub(crate) sequence: u64,
}
#[derive(Deserialize)]
pub(crate) struct WOut {
    pub(crate) value: u64,
    pub(crate) spk_version: u16,
    pub(crate) script: String,
    pub(crate) covenant: Option<WCov>,
}
#[derive(Deserialize)]
pub(crate) struct WCov {
    pub(crate) authorizing_input: u16,
    pub(crate) covenant_id: String,
}
#[derive(Deserialize)]
pub(crate) struct WLeaf {
    pub(crate) txid: String,
    pub(crate) version: u16,
    pub(crate) merge_idx: u32,
}
#[derive(Deserialize)]
pub(crate) struct WExpected {
    pub(crate) activity_digest: String,
    pub(crate) context_hash: String,
    pub(crate) lane_tip: String,
    pub(crate) lanes_root: String,
    pub(crate) seq_commit_c: String,
    pub(crate) b_accepted_id_merkle_root: String,
}

pub(crate) fn check_format(f: &WFile) -> Result<()> {
    if !f.format.map(|v| WITNESS_FORMATS.contains(&v)).unwrap_or(false) {
        return Err(anyhow!(
            "witness format {:?}, this host needs format {WITNESS_FORMATS:?} (token burns): rerun burnwitness with --token",
            f.format
        ));
    }
    Ok(())
}

pub(crate) fn build_witness(f: &WFile, want_levels: &[u8], soft_keccak: bool, attest: bool, prover: [u8; 20]) -> Result<relay::Witness> {
    check_format(f)?;
    let token_cov_id = unhex32(f.token_cov_id.as_deref().ok_or_else(|| anyhow!("witness has no token_cov_id"))?)?;
    // headers: the union of the walks at the chosen levels, plus T and B (v4: no K)
    let mut keep: HashSet<String> = HashSet::new();
    keep.insert(f.t.clone());
    keep.insert(f.b.clone());
    let mut ys: HashSet<String> = HashSet::new();
    for l in want_levels {
        let pl = f.per_level.iter().find(|p| p.level == *l).ok_or_else(|| anyhow!("level {l} is not in the witness (has {:?})", f.levels))?;
        keep.extend(pl.visited.iter().cloned());
        ys.extend(pl.first_parents.iter().cloned());
    }
    let headers: Vec<Vec<u8>> = f.headers.iter().filter(|h| keep.contains(&h.hash)).map(|h| unhex(&h.preimage)).collect::<Result<_>>()?;
    // first-parent path headers: only those of the attesting superblocks at the proved levels (each costs a hash,
    // ~514k cycles for a 7.9 KB header), and not the ones already among the PoW-verified headers, which the guest
    // serves from that set.
    let (y_headers, attest_roots) = if attest {
        (
            f.y_headers.iter().filter(|h| ys.contains(&h.hash) && !keep.contains(&h.hash)).map(|h| unhex(&h.preimage)).collect::<Result<Vec<_>>>()?,
            f.attest_roots.iter().map(|s| unhex32(s)).collect::<Result<Vec<_>>>()?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let mut burns = Vec::with_capacity(f.burns.len());
    for b in &f.burns {
        let t = &b.body;
        let tx = relay::TxBody {
            version: t.version,
            inputs: t
                .inputs
                .iter()
                .map(|i| -> Result<relay::TxInput> { Ok(relay::TxInput { prev_tx_id: unhex32(&i.txid)?, prev_index: i.index, sequence: i.sequence }) })
                .collect::<Result<_>>()?,
            outputs: t
                .outputs
                .iter()
                .map(|o| -> Result<relay::TxOutput> {
                    Ok(relay::TxOutput {
                        value: o.value,
                        spk_version: o.spk_version,
                        script: unhex(&o.script)?,
                        covenant: match &o.covenant {
                            None => None,
                            Some(c) => Some((c.authorizing_input, unhex32(&c.covenant_id)?)),
                        },
                    })
                })
                .collect::<Result<_>>()?,
            lock_time: t.lock_time,
            subnetwork: unhex(&t.subnetwork_id)?.as_slice().try_into().map_err(|_| anyhow!("subnetwork id must be 20 bytes"))?,
            gas: t.gas,
            payload: unhex(&t.payload)?,
        };
        if b.cells.is_empty() {
            return Err(anyhow!("burn {} names no burn cells (burnwitness found none for this token)", b.txid));
        }
        burns.push(relay::Burn {
            tx,
            cells: b.cells.iter().map(|c| relay::BurnCell { index: c.index, amount: c.amount }).collect(),
            leaves: b
                .leaves
                .iter()
                .map(|l| -> Result<([u8; 32], u16, u32)> { Ok((unhex32(&l.txid)?, l.version, l.merge_idx)) })
                .collect::<Result<_>>()?,
            leaf_index: b.leaf_index,
            sp_timestamp: b.sp_timestamp,
            c_daa_score: b.c_daa_score,
            c_blue_score: b.c_blue_score,
            parent_ref: unhex32(&b.parent_ref)?,
            lane_blue_score: b.lane_blue_score,
            inactivity_shortcut: unhex32(&b.inactivity_shortcut)?,
            payload_and_ctx_digest: unhex32(&b.payload_and_ctx_digest)?,
            parent_seq_commit: unhex32(&b.parent_seq_commit)?,
            smt_proof: unhex(&b.smt_proof)?,
            chain_state_roots: b.chain_state_roots.iter().map(|s| unhex32(s)).collect::<Result<_>>()?,
        });
    }
    Ok(relay::Witness {
        soft_keccak,
        levels: want_levels.to_vec(),
        t: unhex32(&f.t)?,
        b: unhex32(&f.b)?,
        token_cov_id,
        prover,
        headers,
        y_headers,
        attest_roots,
        burns,
    })
}
