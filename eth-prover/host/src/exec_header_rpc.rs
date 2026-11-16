//! The Gloas execution-header witness, fetched from an execution RPC (Gloas pack, 2026-11-02).
//!
//! First `debug_getRawHeader` (geth, reth, nethermind and others serve it). If the provider does
//! not, the header is rebuilt from `eth_getBlockByHash` in canonical field order. Either way the
//! bytes are accepted only if they hash to the beacon header's `execution_block_hash`, so a wrong
//! guess or a lying provider can stall a fetch but never produce a witness.
//!
//! The rebuild knows the field order through Amsterdam as alloy-consensus 2.5 encodes it (23
//! fields). If the final spec renames or reorders the new fields, the hex fields this list does not
//! know are tried in every order after the known ones; the keccak check picks the one that is the
//! header.

use alloy_primitives::{keccak256, B256};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

#[derive(Clone, Copy)]
enum Kind {
    /// raw bytes (hashes, addresses, bloom, extraData, nonce)
    Bytes,
    /// an integer, minimal big-endian (zero is the empty string)
    Quantity,
}

/// Header fields in RLP order. The first 15 exist in every header; the rest appear from London on,
/// in this order, each present only if every earlier one is.
const FIELDS: &[(&str, Kind)] = &[
    ("parentHash", Kind::Bytes),
    ("sha3Uncles", Kind::Bytes),
    ("miner", Kind::Bytes),
    ("stateRoot", Kind::Bytes),
    ("transactionsRoot", Kind::Bytes),
    ("receiptsRoot", Kind::Bytes),
    ("logsBloom", Kind::Bytes),
    ("difficulty", Kind::Quantity),
    ("number", Kind::Quantity),
    ("gasLimit", Kind::Quantity),
    ("gasUsed", Kind::Quantity),
    ("timestamp", Kind::Quantity),
    ("extraData", Kind::Bytes),
    ("mixHash", Kind::Bytes),
    ("nonce", Kind::Bytes),
    ("baseFeePerGas", Kind::Quantity),         // London
    ("withdrawalsRoot", Kind::Bytes),          // Shanghai
    ("blobGasUsed", Kind::Quantity),           // Cancun
    ("excessBlobGas", Kind::Quantity),         // Cancun
    ("parentBeaconBlockRoot", Kind::Bytes),    // Cancun
    ("requestsHash", Kind::Bytes),             // Prague
    ("blockAccessListHash", Kind::Bytes),      // Amsterdam, EIP-7928 (order as in alloy-consensus 2.5)
    ("slotNumber", Kind::Quantity),            // Amsterdam, EIP-7843 (order as in alloy-consensus 2.5)
];
const ALWAYS: usize = 15;

/// Block-object keys that are not header fields.
const NOT_HEADER: &[&str] = &[
    "hash", "size", "totalDifficulty", "transactions", "uncles", "withdrawals", "blockAccessList",
    "author", "sealFields", "l1BlockNumber", "transactionCount",
];

pub async fn fetch_exec_header_rlp(rpc_url: &str, hash: B256) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    if let Ok(v) = call(&client, rpc_url, "debug_getRawHeader", json!([hash])).await {
        if let Some(b) = v.as_str().and_then(|s| hex::decode(s.trim_start_matches("0x")).ok()) {
            if keccak256(&b) == hash {
                println!("exec header   : debug_getRawHeader, {} bytes", b.len());
                return Ok(b);
            }
        }
    }
    let block = call(&client, rpc_url, "eth_getBlockByHash", json!([hash, false])).await?;
    if block.is_null() {
        bail!("execution RPC does not know block {hash} (not synced that far, or another chain)");
    }
    let rlp = header_rlp_from_json(&block, hash)?;
    println!("exec header   : rebuilt from eth_getBlockByHash, {} bytes", rlp.len());
    Ok(rlp)
}

async fn call(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: Value = client.post(url).json(&body).send().await?.json().await?;
    if let Some(e) = resp.get("error") {
        bail!("{method}: {e}");
    }
    resp.get("result").cloned().ok_or_else(|| anyhow!("{method}: no result"))
}

/// Rebuild the RLP header from an `eth_getBlockByHash` object and accept it only if it hashes to `hash`.
pub fn header_rlp_from_json(block: &Value, hash: B256) -> Result<Vec<u8>> {
    let obj = block.as_object().ok_or_else(|| anyhow!("block is not an object"))?;
    let mut known: Vec<Vec<u8>> = Vec::new();
    for (i, (key, kind)) in FIELDS.iter().enumerate() {
        match obj.get(*key).and_then(Value::as_str) {
            Some(v) => known.push(encode_field(v, *kind)?),
            None if i < ALWAYS => bail!("block object lacks {key}"),
            None => break,
        }
    }
    let extras: Vec<&str> = obj
        .iter()
        .filter(|(k, v)| {
            !FIELDS.iter().any(|(f, _)| f == k) && !NOT_HEADER.contains(&k.as_str()) && v.as_str().map_or(false, |s| s.starts_with("0x"))
        })
        .map(|(k, _)| k.as_str())
        .collect();
    if extras.len() > 5 {
        bail!("block object has {} unknown hex fields ({extras:?}); refusing to guess", extras.len());
    }
    // the known prefix alone first, then every ordering of the unknown fields after it
    let mut orders: Vec<Vec<&str>> = vec![vec![]];
    orders.extend(permutations(&extras));
    for order in &orders {
        let mut fields = known.clone();
        for key in order {
            let v = obj[*key].as_str().unwrap();
            let hex_len = v.len() - 2;
            let kind = if hex_len == 64 || hex_len == 40 { Kind::Bytes } else { Kind::Quantity };
            fields.push(encode_field(v, kind)?);
        }
        let rlp = rlp_list(&fields);
        if keccak256(&rlp) == hash {
            if !order.is_empty() {
                println!("exec header   : appended fields {order:?} after the Prague layout");
            }
            return Ok(rlp);
        }
    }
    bail!(
        "no field order of this block object hashes to {hash} ({} known fields, unknown hex fields {extras:?}); \
         the provider needs debug_getRawHeader or this list needs the new fork's fields",
        known.len()
    )
}

fn permutations<'a>(items: &[&'a str]) -> Vec<Vec<&'a str>> {
    if items.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let x = rest.remove(i);
        out.push(vec![x]);
        for mut p in permutations(&rest) {
            p.insert(0, x);
            out.push(p);
        }
    }
    out
}

fn encode_field(v: &str, kind: Kind) -> Result<Vec<u8>> {
    let h = v.strip_prefix("0x").ok_or_else(|| anyhow!("not a hex string: {v}"))?;
    let raw = match kind {
        Kind::Bytes => hex::decode(h)?,
        Kind::Quantity => {
            let padded = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
            let b = hex::decode(padded)?;
            b.into_iter().skip_while(|x| *x == 0).collect()
        }
    };
    Ok(rlp_string(&raw))
}

pub fn rlp_string(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_prefix(0x80, b.len());
    out.extend_from_slice(b);
    out
}

pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = rlp_prefix(0xc0, payload.len());
    out.extend(payload);
    out
}

fn rlp_prefix(base: u8, len: usize) -> Vec<u8> {
    if len < 56 {
        return vec![base + len as u8];
    }
    let l: Vec<u8> = (len as u64).to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    let mut v = vec![base + 55 + l.len() as u8];
    v.extend(l);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet genesis as eth_getBlockByHash returns it (header fields only matter).
    #[test]
    fn rebuilds_mainnet_genesis() {
        let block = json!({
            "hash": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "miner": "0x0000000000000000000000000000000000000000",
            "stateRoot": "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
            "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "difficulty": "0x400000000",
            "number": "0x0",
            "gasLimit": "0x1388",
            "gasUsed": "0x0",
            "timestamp": "0x0",
            "extraData": "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000042",
            "size": "0x21c",
            "totalDifficulty": "0x400000000",
            "transactions": [],
            "uncles": []
        });
        let hash: B256 = "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3".parse().unwrap();
        let rlp = header_rlp_from_json(&block, hash).expect("rebuilds");
        let (sr, n) = eth_bridge_primitives::exec_header::state_root_and_number(&rlp).unwrap();
        assert_eq!(n, 0);
        assert_eq!(format!("{sr}"), "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544");
        // a wrong hash is refused, never "best effort"
        assert!(header_rlp_from_json(&block, B256::repeat_byte(1)).is_err());
    }
}
