// KIP-20 covenant id genesis hashing (consensus/core/src/hashing/covenant_id.rs), transcribed so a reader with no
// Rust toolchain (bin/verify-token.mjs) can recompute a token family's id from the node's own transaction data:
//
//   covenant_id(O, auth_outputs) = BLAKE2b-256[key = "CovenantID"](
//       O.tx_id || le_u32(O.index) || le_u64(len(auth_outputs))
//       || for each (out_idx, out): le_u32(out_idx) || le_u64(out.value) || le_u16(spk.version) || le_u64(len(spk.script)) || spk.script )
//
// The binding itself (covenant field of the output) is not hashed. Transaction ids are the 32 bytes as the node
// prints them (no byte reversal). Checked in test/covenant-id.test.js against a Python hashlib vector and, live,
// by bin/bridge.mjs init (tool id == SDK id == this == the node's UTXO entry).
import { blake2b, hex, unhex } from './blake2b.js';

const le = (n, bytes) => { const o = new Uint8Array(bytes); let v = BigInt(n); for (let i = 0; i < bytes; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0); const o = new Uint8Array(n); let k = 0; for (const p of parts) { o.set(p, k); k += p.length; } return o; };

/**
 * @param {{ txid: string, index: number }} outpoint   the authorizing input's previous outpoint
 * @param {{ index: number, value: bigint|string|number, version: number, script: string }[]} outputs   the authorized outputs, increasing index
 * @returns {string} 64-hex covenant id
 */
export function covenantId(outpoint, outputs) {
  const txid = unhex(outpoint.txid);
  if (txid.length !== 32) throw new Error('covenantId: txid must be 32 bytes');
  const sorted = [...outputs].sort((a, b) => a.index - b.index);
  const parts = [txid, le(outpoint.index, 4), le(sorted.length, 8)];
  for (const o of sorted) {
    const script = unhex(o.script);
    parts.push(le(o.index, 4), le(o.value, 8), le(o.version ?? 0, 2), le(script.length, 8), script);
  }
  return hex(blake2b(cat(...parts), { key: new TextEncoder().encode('CovenantID'), outLen: 32 }));
}

/** The P2SH script public key of a redeem script: aa20 <BLAKE2b-256(redeem)> 87 (unkeyed; txscript's pay_to_script_hash_script). */
export function p2shScript(redeemHex) {
  return 'aa20' + hex(blake2b(unhex(redeemHex), { outLen: 32 })) + '87';
}

/** The P2PK script of a 32-byte x-only key: 20 <key> ac. */
export function p2pkScript(xonlyHex) {
  return '20' + String(xonlyHex).replace(/^0x/, '').toLowerCase() + 'ac';
}
