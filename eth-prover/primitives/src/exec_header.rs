//! The execution block a finalized light-client header points at, for the journal's
//! `exec_state_root` and `exec_block_number` (Gloas pack, 2026-11-02).
//!
//! Before Gloas the light-client header carries the execution payload header, and helios has
//! already checked its Merkle branch against the beacon block's `body_root`.
//!
//! From Gloas on (EIP-7732) the header carries only `execution_block_hash`, which the spec fills
//! with `signed_execution_payload_bid.message.parent_block_hash`: the payload this block builds on,
//! one the chain has processed (the state transition requires the bid's parent to equal the
//! state's latest block hash). helios checks that hash's branch against `body_root` too. The
//! execution header itself therefore arrives as a witness: its RLP must hash to that value, and
//! the state root and number are read from it by position (fields 3 and 8, unchanged since
//! Frontier). Nothing after field 8 is interpreted, so header fields that later forks append do
//! not change this program.
//!
//! `exec_point` is called by the guest and by the host's dry run, so a bad witness fails on the
//! host in a second and the guest makes exactly the same decision.

use alloy_primitives::{keccak256, B256};
use helios_consensus_core::types::LightClientHeader;

/// RLP position of the state root in an execution block header.
pub const FIELD_STATE_ROOT: usize = 3;
/// RLP position of the block number in an execution block header.
pub const FIELD_NUMBER: usize = 8;
/// Every execution header since Frontier has at least 15 fields.
pub const MIN_FIELDS: usize = 15;

/// One RLP item at the start of `b`: (is_list, payload offset, payload length).
/// `None` if the prefix is malformed or the item runs past the end of `b`.
fn item(b: &[u8]) -> Option<(bool, usize, usize)> {
    let p = *b.first()?;
    let (list, off, len) = match p {
        0x00..=0x7f => return Some((false, 0, 1)),
        0x80..=0xb7 => (false, 1, (p - 0x80) as usize),
        0xb8..=0xbf => {
            let n = (p - 0xb7) as usize;
            (false, 1 + n, be_len(b.get(1..1 + n)?)?)
        }
        0xc0..=0xf7 => (true, 1, (p - 0xc0) as usize),
        0xf8..=0xff => {
            let n = (p - 0xf7) as usize;
            (true, 1 + n, be_len(b.get(1..1 + n)?)?)
        }
    };
    if off.checked_add(len)? > b.len() {
        return None;
    }
    Some((list, off, len))
}

/// Big-endian length of a long RLP prefix: 1 to 4 bytes, no leading zero.
fn be_len(x: &[u8]) -> Option<usize> {
    if x.is_empty() || x.len() > 4 || x[0] == 0 {
        return None;
    }
    Some(x.iter().fold(0usize, |v, &c| (v << 8) | c as usize))
}

/// (state root, block number) of an RLP-encoded execution block header, read by position.
/// The whole input must be exactly one RLP list; fields 0 to 8 must be strings; the state root
/// must be 32 bytes and the number a canonical integer of at most 8 bytes.
pub fn state_root_and_number(rlp: &[u8]) -> Option<(B256, u64)> {
    let (list, off, len) = item(rlp)?;
    if !list || off + len != rlp.len() {
        return None;
    }
    let mut rest = &rlp[off..];
    let (mut state_root, mut number) = (None, None);
    let mut i = 0usize;
    while !rest.is_empty() {
        let (is_list, o, n) = item(rest)?;
        if i <= FIELD_NUMBER && is_list {
            return None;
        }
        let v = &rest[o..o + n];
        if i == FIELD_STATE_ROOT {
            if v.len() != 32 {
                return None;
            }
            state_root = Some(B256::from_slice(v));
        }
        if i == FIELD_NUMBER {
            // canonical: zero is the empty string, no leading zero byte, at most 8 bytes
            if v.len() > 8 || v.first() == Some(&0) {
                return None;
            }
            let mut x = [0u8; 8];
            x[8 - v.len()..].copy_from_slice(v);
            number = Some(u64::from_be_bytes(x));
        }
        rest = &rest[o + n..];
        i += 1;
    }
    if i < MIN_FIELDS {
        return None;
    }
    Some((state_root?, number?))
}

/// (exec_state_root, exec_block_number) for a finalized light-client header that helios has
/// already validated. `rlp` is the Gloas witness: required for a Gloas header, refused otherwise,
/// so the inputs for a given step are canonical.
pub fn exec_point(header: &LightClientHeader, rlp: Option<&[u8]>) -> Result<(B256, u64), &'static str> {
    match header {
        LightClientHeader::Gloas(h) => {
            let rlp = rlp.ok_or("Gloas header: the execution header RLP witness is required")?;
            if h.execution_block_hash.is_zero() {
                return Err("Gloas header without an execution block hash");
            }
            if keccak256(rlp) != h.execution_block_hash {
                return Err("execution header RLP does not hash to the header's execution_block_hash");
            }
            state_root_and_number(rlp).ok_or("execution header RLP does not decode as a block header")
        }
        other => {
            if rlp.is_some() {
                return Err("execution header witness given for a pre-Gloas header");
            }
            let exec = other
                .execution()
                .map_err(|_| "finalized header has no execution payload (pre-Capella header)")?;
            Ok((*exec.state_root(), *exec.block_number()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethereum mainnet's genesis header, RLP-encoded by hand from its published fields; its hash is
    /// the well-known 0xd4e56740…cb8fa3 and its state root 0xd7f8974f…0f0544.
    pub fn mainnet_genesis_rlp() -> Vec<u8> {
        fn s(b: &[u8]) -> Vec<u8> {
            if b.len() == 1 && b[0] < 0x80 {
                return b.to_vec();
            }
            let mut out = if b.len() < 56 {
                vec![0x80 + b.len() as u8]
            } else {
                let l = (b.len() as u64).to_be_bytes();
                let l: Vec<u8> = l.iter().copied().skip_while(|x| *x == 0).collect();
                let mut v = vec![0xb7 + l.len() as u8];
                v.extend(l);
                v
            };
            out.extend_from_slice(b);
            out
        }
        let h = |x: &str| hex_decode(x);
        let fields: Vec<Vec<u8>> = vec![
            vec![0u8; 32],                                                                  // parentHash
            h("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),         // ommersHash
            vec![0u8; 20],                                                                  // coinbase
            h("d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),         // stateRoot
            h("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),         // transactionsRoot
            h("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),         // receiptsRoot
            vec![0u8; 256],                                                                 // logsBloom
            h("0400000000"),                                                                // difficulty 2^34
            vec![],                                                                         // number 0
            h("1388"),                                                                      // gasLimit 5000
            vec![],                                                                         // gasUsed
            vec![],                                                                         // timestamp
            h("11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),         // extraData
            vec![0u8; 32],                                                                  // mixHash
            h("0000000000000042"),                                                          // nonce
        ];
        let payload: Vec<u8> = fields.iter().flat_map(|f| s(f)).collect();
        let mut out = if payload.len() < 56 {
            vec![0xc0 + payload.len() as u8]
        } else {
            let l: Vec<u8> = (payload.len() as u64).to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
            let mut v = vec![0xf7 + l.len() as u8];
            v.extend(l);
            v
        };
        out.extend(payload);
        out
    }

    fn hex_decode(x: &str) -> Vec<u8> {
        (0..x.len()).step_by(2).map(|i| u8::from_str_radix(&x[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn genesis_vector() {
        let rlp = mainnet_genesis_rlp();
        assert_eq!(
            format!("{}", keccak256(&rlp)),
            "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        );
        let (sr, n) = state_root_and_number(&rlp).expect("decodes");
        assert_eq!(format!("{sr}"), "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544");
        assert_eq!(n, 0);
    }

    #[test]
    fn refuses_malformed() {
        let rlp = mainnet_genesis_rlp();
        // trailing byte after the list
        let mut t = rlp.clone();
        t.push(0);
        assert!(state_root_and_number(&t).is_none());
        // truncated
        assert!(state_root_and_number(&rlp[..rlp.len() - 1]).is_none());
        // not a list
        assert!(state_root_and_number(&[0x82, 0x01, 0x02]).is_none());
        // empty
        assert!(state_root_and_number(&[]).is_none());
        // too few fields: a list of 9 empty strings
        assert!(state_root_and_number(&[0xc9, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]).is_none());
        // a long-length prefix with a leading zero byte
        assert!(state_root_and_number(&[0xf9, 0x00, 0x05]).is_none());
        // a length claiming more than 4 bytes of length
        assert!(state_root_and_number(&[0xfc, 1, 1, 1, 1, 1]).is_none());
    }

    #[test]
    fn number_must_be_canonical() {
        // 15 fields, state root at 3, number at 8 encoded as a single 0x00 byte (non-canonical zero)
        let mut payload = Vec::new();
        for i in 0..15 {
            match i {
                3 => {
                    payload.push(0xa0);
                    payload.extend([7u8; 32]);
                }
                8 => payload.push(0x00),
                _ => payload.push(0x80),
            }
        }
        let mut rlp = vec![0xc0 + payload.len() as u8];
        rlp.extend(&payload);
        assert!(state_root_and_number(&rlp).is_none());
        // the canonical form (0x80) decodes as 0
        let i8 = rlp.iter().rposition(|b| *b == 0x00).unwrap();
        rlp[i8] = 0x80;
        assert_eq!(state_root_and_number(&rlp), Some((B256::repeat_byte(7), 0)));
    }
}
