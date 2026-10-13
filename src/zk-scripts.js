// Builds the exact script shapes rusty-kaspa's own ZK tests use
// (crypto/txscript/src/zk_precompiles/tests/helpers.rs), via the SDK's
// native ScriptBuilder with covenantsEnabled (post-Toccata push limits).
//
// Stack contract of OpZkPrecompile (top of stack first):
//   tag byte, then per tag:
//   0x20 Groth16:        vk, proof, n_inputs (i64), inputs[0..n) (Fr, 32 bytes LE)
//   0x21 R0 Succinct:    hashfn, control_id, image_id, journal, seal,
//                        control_digests, control_index, claim
//
// P2SH split: the redeem script pins what the covenant *trusts* (vk, or
// image/control id); the unlock (signature) script carries what the spender
// *supplies* (proof, inputs). A proof for the wrong program cannot match.
import {
  ScriptBuilder,
  Opcodes,
  payToScriptHashScript,
  payToScriptHashSignatureScript,
  addressFromScriptPublicKey,
  NetworkType,
} from './sdk.js';

export const ZK_TAG = Object.freeze({ GROTH16: 0x20, R0_SUCCINCT: 0x21 });
export const OP_ZK_PRECOMPILE = 0xa6;

export const FLAGS = Object.freeze({ flags: { covenantsEnabled: true } });

export function builder() {
  return new ScriptBuilder(FLAGS);
}

export function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function flipByte(hex, index = 0, xor = 0xff) {
  const b = Buffer.from(hex, 'hex');
  if (index < 0 || index >= b.length) throw new RangeError(`flipByte index ${index} out of range`);
  b[index] ^= xor;
  return b.toString('hex');
}

// ---------- Groth16 ----------

/** redeem = push(vk) push(0x20) OpZkPrecompile */
export function groth16RedeemScript(vkHex) {
  return builder().addData(vkHex).addData('20').addOp(Opcodes.OpZkPrecompile).drain();
}

/** unlock = push(input[n-1]) ... push(input[0]) push_i64(n) push(proof) */
export function groth16UnlockScript(proofHex, inputsHex) {
  const b = builder();
  for (let i = inputsHex.length - 1; i >= 0; i--) b.addData(inputsHex[i]);
  b.addI64(BigInt(inputsHex.length)).addData(proofHex);
  return b.drain();
}

/** Full P2SH signature script: unlock followed by push(redeem). */
export function groth16SignatureScript({ vk, proof, inputs }) {
  const redeem = groth16RedeemScript(vk);
  return payToScriptHashSignatureScript(redeem, groth16UnlockScript(proof, inputs));
}

/** Stand-alone script (no P2SH), identical to helpers.rs build_groth_script_from_fields. */
export function groth16StandaloneScript({ vk, proof, inputs }) {
  const b = builder();
  for (let i = inputs.length - 1; i >= 0; i--) b.addData(inputs[i]);
  return b.addI64(BigInt(inputs.length)).addData(proof).addData(vk).addData('20').addOp(Opcodes.OpZkPrecompile).drain();
}

// ---------- RISC Zero Succinct ----------

/** redeem = push(image_id) push(control_id) push(hashfn) push(0x21) OpZkPrecompile */
export function succinctRedeemScript({ imageId, controlId, hashfn }) {
  return builder().addData(imageId).addData(controlId).addData(hashfn).addData('21').addOp(Opcodes.OpZkPrecompile).drain();
}

/** unlock = push(claim) push(control_index) push(control_digests) push(seal) push(journal) */
export function succinctUnlockScript({ claim, controlIndex, controlDigests, seal, journal }) {
  return builder().addData(claim).addData(controlIndex).addData(controlDigests).addData(seal).addData(journal).drain();
}

export function succinctSignatureScript(f) {
  return payToScriptHashSignatureScript(succinctRedeemScript(f), succinctUnlockScript(f));
}

/** Stand-alone script, identical to helpers.rs R0Fields::script(). */
export function succinctStandaloneScript(f) {
  return builder()
    .addData(f.claim)
    .addData(f.controlIndex)
    .addData(f.controlDigests)
    .addData(f.seal)
    .addData(f.journal)
    .addData(f.imageId)
    .addData(f.controlId)
    .addData(f.hashfn)
    .addData('21')
    .addOp(Opcodes.OpZkPrecompile)
    .drain();
}

// ---------- P2SH helpers ----------

export function p2shScriptPublicKey(redeemHex) {
  return payToScriptHashScript(redeemHex);
}

export function networkTypeFor(network) {
  const n = String(network).toLowerCase();
  if (n.startsWith('mainnet')) return NetworkType.Mainnet;
  if (n.startsWith('testnet')) return NetworkType.Testnet;
  if (n.startsWith('devnet')) return NetworkType.Devnet;
  if (n.startsWith('simnet')) return NetworkType.Simnet;
  throw new Error(`unknown network ${network}`);
}

export function p2shAddress(redeemHex, network = 'testnet-10') {
  return addressFromScriptPublicKey(p2shScriptPublicKey(redeemHex), networkTypeFor(network)).toString();
}

/** Decode a script hex into [{op, dataLen}] using the canonical push encodings. */
export function decodeScript(hex) {
  const b = Buffer.from(hex, 'hex');
  const out = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i++];
    let len = 0;
    if (op >= 1 && op <= 75) len = op;
    else if (op === 0x4c) { len = b[i]; i += 1; }
    else if (op === 0x4d) { len = b.readUInt16LE(i); i += 2; }
    else if (op === 0x4e) { len = b.readUInt32LE(i); i += 4; }
    let data = len ? b.subarray(i, i + len).toString('hex') : null;
    // canonical small-int pushes: Op0 -> empty, Op1..Op16 -> 01..10, Op1Negate -> 81
    if (op === 0x00) data = '';
    else if (op >= 0x51 && op <= 0x60) data = (op - 0x50).toString(16).padStart(2, '0');
    else if (op === 0x4f) data = '81';
    out.push({ op, dataLen: len || (data !== null ? data.length / 2 : 0), data, smallInt: op === 0x00 || op === 0x4f || (op >= 0x51 && op <= 0x60) });
    i += len;
  }
  return out;
}
