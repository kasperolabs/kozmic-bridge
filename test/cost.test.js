import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT,
  ZK_TAG_COST_GRAMS,
  ZK_TAG_MAX_COST_GRAMS,
  zkTagCostUnits,
  groth16VkUnits,
  coveringComputeBudget,
  allowedScriptUnits,
  estimateSpendScriptUnits,
  suggestedComputeBudget,
  verifiesPerBlock,
  spendMasses,
  minimumRelayFeeSompi,
  feeMassGrams,
  BLOCK_COMPUTE_MASS_LIMIT,
  BLOCK_TRANSIENT_MASS_LIMIT_POST_TOCCATA,
} from '../src/cost.js';
import { loadGroth16, loadSuccinct } from '../src/fixtures.js';
import { groth16RedeemScript, groth16SignatureScript, succinctRedeemScript, succinctSignatureScript } from '../src/zk-scripts.js';

const P2PK_SCRIPT_LEN = 34; // 0x20 <32-byte pubkey> OpCheckSig

// --- constants pinned by rusty-kaspa's own unit tests ---

test('tags.rs: max_cost_matches_hardcoded_value', () => {
  assert.equal(ZK_TAG_MAX_COST_GRAMS, 250_000n);
  assert.equal(ZK_TAG_COST_GRAMS[0x20], 140_000n);
  assert.equal(ZK_TAG_COST_GRAMS[0x21], 250_000n);
});

test('tags.rs: groth16_cost_block_capacity == 3, r0_succinct_cost_block_capacity == 2', () => {
  assert.equal(verifiesPerBlock(0x20), 3n);
  assert.equal(verifiesPerBlock(0x21), 2n);
});

test('units.rs: checked_covering_script_units_respects_free_allowance_boundaries', () => {
  assert.equal(coveringComputeBudget(0n), 0n);
  assert.equal(coveringComputeBudget(9_999n), 0n);
  assert.equal(coveringComputeBudget(10_000n), 1n);
  assert.equal(coveringComputeBudget(19_999n), 1n);
  assert.equal(coveringComputeBudget(20_000n), 2n);
});

test('units.rs: budget overflow returns none past u16::MAX', () => {
  const max = allowedScriptUnits(65535);
  assert.equal(coveringComputeBudget(max), 65535n);
  assert.equal(coveringComputeBudget(max + 1n), null);
});

test('lib.rs: test_used_script_units_can_drive_compute_budget_selection (10_000 units -> budget 1)', () => {
  assert.equal(coveringComputeBudget(SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT), 1n);
  assert.equal(allowedScriptUnits(1), 19_999n);
  assert.equal(allowedScriptUnits(0), 9_999n);
});

// --- derived numbers for the two fixtures ---

test('Groth16 fixture spend needs ~1550 budget before margin; precompile dominates', () => {
  const g = loadGroth16();
  const redeemLen = groth16RedeemScript(g.vk).length / 2;
  const units = estimateSpendScriptUnits({ tag: 0x20, nInputs: g.inputs.length, redeemLen });
  assert.equal(zkTagCostUnits(0x20), 14_000_000n);
  assert.equal(groth16VkUnits(5), 1_500_000n);
  assert.equal(units, 14_000_000n + 1_500_000n + 2n * BigInt(redeemLen));
  assert.equal(coveringComputeBudget(units), 1550n);
  const budget = suggestedComputeBudget({ tag: 0x20, nInputs: 5, redeemLen });
  assert.ok(budget >= 1550n && budget <= 1600n, `budget ${budget}`);
});

test('Succinct fixture spend needs ~2500 budget; transient mass is the binding constraint', () => {
  const s = loadSuccinct();
  const redeemLen = succinctRedeemScript(s).length / 2;
  const units = estimateSpendScriptUnits({ tag: 0x21, redeemLen });
  assert.equal(coveringComputeBudget(units), 2500n);
  const sig = succinctSignatureScript(s);
  const m = spendMasses({ version: 1, inputs: [{ signatureScriptLen: sig.length / 2, computeBudget: 2625 }], outputs: [{ scriptLen: P2PK_SCRIPT_LEN }] });
  assert.ok(m.compute < BLOCK_COMPUTE_MASS_LIMIT, `compute ${m.compute} < 500k`);
  assert.ok(m.transient < BLOCK_TRANSIENT_MASS_LIMIT_POST_TOCCATA, `transient ${m.transient} < 1M`);
  assert.ok(m.transient > 850_000n, `a Succinct spend eats most of a block's transient budget: ${m.transient}`);
  assert.ok(m.transient > m.compute);
  // mempool fee basis normalizes transient by 0.5, so compute still sets the Succinct fee
  assert.equal(feeMassGrams(m), m.compute);
  assert.ok(minimumRelayFeeSompi(feeMassGrams(m)) < 50_000_000n, 'Succinct min fee < 0.5 KAS');
});

test('Groth16 fixture spend masses fit a block with room for 2 more', () => {
  const g = loadGroth16();
  const sig = groth16SignatureScript(g);
  const m = spendMasses({ version: 1, inputs: [{ signatureScriptLen: sig.length / 2, computeBudget: 1627 }], outputs: [{ scriptLen: P2PK_SCRIPT_LEN }] });
  assert.ok(m.compute > 160_000n && m.compute < 170_000n, `compute ${m.compute}`);
  assert.ok(m.transient < 5_000n, `transient ${m.transient}`);
  assert.ok(m.compute * 3n < BLOCK_COMPUTE_MASS_LIMIT);
  // min relay fee at 100 sompi/gram: ~0.164 KAS per Groth16 verify
  const fee = minimumRelayFeeSompi(m.compute);
  assert.ok(fee > 16_000_000n && fee < 17_000_000n, `fee ${fee} sompi`);
});

test('mainnet measurement: used=15,500,893 covers to budget 1550, and the model predicts it', async () => {
  const { MEASURED_GROTH16_5IN_P2SH_UNITS } = await import('../src/cost.js');
  assert.equal(coveringComputeBudget(MEASURED_GROTH16_5IN_P2SH_UNITS), 1550n);
  const g = loadGroth16();
  const redeemLen = groth16RedeemScript(g.vk).length / 2;
  const predicted = estimateSpendScriptUnits({ tag: 0x20, nInputs: 5, redeemLen });
  assert.ok(MEASURED_GROTH16_5IN_P2SH_UNITS - predicted < 100n, `model within 100 units of measurement (${MEASURED_GROTH16_5IN_P2SH_UNITS - predicted})`);
});
