// What a byte flip changes, and what it does not. Verification itself happens
// in the node's script engine (bin/live.mjs); here we pin the structural
// consequences so the live rejection is attributable to the precompile and
// not to a malformed script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadGroth16, loadSuccinct } from '../src/fixtures.js';
import {
  groth16RedeemScript,
  groth16SignatureScript,
  groth16UnlockScript,
  succinctRedeemScript,
  succinctSignatureScript,
  p2shAddress,
  decodeScript,
  flipByte,
} from '../src/zk-scripts.js';

const g = loadGroth16();
const s = loadSuccinct();

test('flipping a proof byte keeps the script well-formed and the address unchanged (failure must come from verification)', () => {
  const redeem = groth16RedeemScript(g.vk);
  const good = groth16SignatureScript(g);
  const bad = groth16SignatureScript({ ...g, proof: flipByte(g.proof, 0) });
  assert.notEqual(good, bad);
  assert.equal(good.length, bad.length);
  const dg = decodeScript(good), db = decodeScript(bad);
  assert.equal(dg.length, db.length);
  assert.equal(db[6].dataLen, 128, 'proof still 128 bytes');
  assert.equal(db.at(-1).data, redeem, 'redeem script untouched, so P2SH hash still matches');
  assert.equal(p2shAddress(redeem), p2shAddress(decodeScript(bad).at(-1).data));
});

test('flipping a public input keeps arity (5) so the engine reaches the pairing check, not an arity error', () => {
  const inputs = [...g.inputs];
  inputs[2] = flipByte(inputs[2], 3);
  const unlock = decodeScript(groth16UnlockScript(g.proof, inputs));
  assert.equal(unlock[5].op, 0x55, 'count still 5');
  assert.equal(unlock.filter((o) => o.dataLen === 32).length, 5);
});

test('dropping a public input changes arity: engine must reject with ArityMismatch (vk has 6 gamma_abc elements)', () => {
  const unlock = decodeScript(groth16UnlockScript(g.proof, g.inputs.slice(0, 4)));
  assert.equal(unlock[4].op, 0x54, 'count 4');
});

test('flipping a VK byte moves the covenant to a different address: the old UTXO cannot be unlocked with it', () => {
  const redeemGood = groth16RedeemScript(g.vk);
  const redeemBad = groth16RedeemScript(flipByte(g.vk, 7));
  assert.notEqual(p2shAddress(redeemGood), p2shAddress(redeemBad));
  // and the P2SH signature script built from the bad redeem fails the hash check before any ZK work
  const sigBad = groth16SignatureScript({ ...g, vk: flipByte(g.vk, 7) });
  assert.equal(decodeScript(sigBad).at(-1).data, redeemBad);
});

test('Succinct: flipping a seal word keeps the 4-byte alignment the parser requires', () => {
  const sealBad = flipByte(s.seal, 1000);
  assert.equal(sealBad.length, s.seal.length);
  assert.equal((sealBad.length / 2) % 4, 0);
  const sig = succinctSignatureScript({ ...s, seal: sealBad });
  assert.equal(sig.length, succinctSignatureScript(s).length);
});

test('Succinct: image id lives in the redeem script, so a different program is a different address', () => {
  const a = p2shAddress(succinctRedeemScript(s));
  const b = p2shAddress(succinctRedeemScript({ ...s, imageId: flipByte(s.imageId, 0) }));
  assert.notEqual(a, b);
});

test('mutation vectors for the live test are distinct and well-formed', () => {
  const variants = {
    proof: groth16SignatureScript({ ...g, proof: flipByte(g.proof, 0) }),
    input: groth16SignatureScript({ ...g, inputs: g.inputs.map((x, i) => (i === 4 ? flipByte(x, 0) : x)) }),
    good: groth16SignatureScript(g),
  };
  const set = new Set(Object.values(variants));
  assert.equal(set.size, 3);
  for (const v of Object.values(variants)) assert.doesNotThrow(() => decodeScript(v));
});
