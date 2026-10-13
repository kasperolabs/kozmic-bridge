import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadGroth16, loadSuccinct } from '../src/fixtures.js';
import { groth16RedeemScript, groth16SignatureScript, succinctRedeemScript, succinctSignatureScript, flipByte } from '../src/zk-scripts.js';
import { buildZkSpend, planZkSpend, TX_VERSION_TOCCATA } from '../src/tx.js';

const g = loadGroth16();
const s = loadSuccinct();
const TO = '20' + 'ab'.repeat(32) + 'ac'; // dummy P2PK destination
const PREV = '11'.repeat(32);

test('plan: Groth16 spend budget, masses, min fee', () => {
  const redeem = groth16RedeemScript(g.vk);
  const sig = groth16SignatureScript(g);
  const plan = planZkSpend({ tag: 0x20, nInputs: 5, redeemHex: redeem, signatureScriptHex: sig, toScriptHex: TO });
  assert.ok(plan.computeBudget >= 1550 && plan.computeBudget <= 1700);
  assert.ok(plan.masses.compute > plan.masses.transient);
  assert.ok(plan.minFeeSompi > 0n);
});

test('build: v1 transaction carries computeBudget and the proof as signature script', () => {
  const redeem = groth16RedeemScript(g.vk);
  const sig = groth16SignatureScript(g);
  const plan = planZkSpend({ tag: 0x20, nInputs: 5, redeemHex: redeem, signatureScriptHex: sig, toScriptHex: TO });
  const tx = buildZkSpend({ prevTxId: PREV, prevIndex: 0, prevAmount: 100_000_000n, redeemHex: redeem, signatureScript: sig, computeBudget: plan.computeBudget, toScriptHex: TO, fee: plan.minFeeSompi * 2n });
  assert.equal(tx.version, TX_VERSION_TOCCATA);
  assert.equal(tx.inputs.length, 1);
  assert.equal(tx.inputs[0].computeBudget, plan.computeBudget);
  assert.equal(tx.inputs[0].signatureScript, sig);
  assert.equal(tx.outputs.length, 1);
  assert.equal(tx.outputs[0].value, 100_000_000n - plan.minFeeSompi * 2n);
  assert.match(tx.id, /^[0-9a-f]{64}$/);
});

test('KIP-24: v1 txid excludes signature script and compute budget', () => {
  const redeem = groth16RedeemScript(g.vk);
  const sig = groth16SignatureScript(g);
  const common = { prevTxId: PREV, prevIndex: 0, prevAmount: 100_000_000n, redeemHex: redeem, toScriptHex: TO, fee: 5_000_000n };
  const a = buildZkSpend({ ...common, signatureScript: sig, computeBudget: 1627 });
  const b = buildZkSpend({ ...common, signatureScript: flipByte(sig, 10), computeBudget: 1627 });
  const c = buildZkSpend({ ...common, signatureScript: sig, computeBudget: 9 });
  assert.equal(a.id, b.id, 'malleating the proof does not change the txid');
  assert.equal(a.id, c.id, 'changing the budget does not change the txid');
  const d = buildZkSpend({ ...common, signatureScript: sig, computeBudget: 1627, fee: 5_000_001n });
  assert.notEqual(a.id, d.id, 'outputs are covered');
});

test('build: Succinct spend with 222 KB signature script constructs and round-trips', () => {
  const redeem = succinctRedeemScript(s);
  const sig = succinctSignatureScript(s);
  const plan = planZkSpend({ tag: 0x21, redeemHex: redeem, signatureScriptHex: sig, toScriptHex: TO });
  assert.ok(plan.computeBudget >= 2500);
  const tx = buildZkSpend({ prevTxId: PREV, prevIndex: 0, prevAmount: 500_000_000n, redeemHex: redeem, signatureScript: sig, computeBudget: plan.computeBudget, toScriptHex: TO, fee: plan.minFeeSompi * 2n });
  assert.equal(tx.inputs[0].signatureScript.length, sig.length);
  const json = tx.serializeToSafeJSON();
  assert.ok(json.includes('"computeBudget"'), 'safe JSON carries the v1 field');
});

test('build: rejects out-of-range budget and overspend', () => {
  const redeem = groth16RedeemScript(g.vk);
  const sig = groth16SignatureScript(g);
  assert.throws(() => buildZkSpend({ prevTxId: PREV, prevIndex: 0, prevAmount: 10n, redeemHex: redeem, signatureScript: sig, computeBudget: 70000, toScriptHex: TO, fee: 1n }), RangeError);
  assert.throws(() => buildZkSpend({ prevTxId: PREV, prevIndex: 0, prevAmount: 10n, redeemHex: redeem, signatureScript: sig, computeBudget: 1, toScriptHex: TO, fee: 10n }), RangeError);
});
