#!/usr/bin/env node
// Prints the P2SH covenant addresses for both fixtures plus the spend plan.
// Fund the Groth16 address on testnet-10 to run bin/live.mjs.
//
//   node bin/address.mjs [network]      (default testnet-10)
import { loadGroth16, loadSuccinct } from '../src/fixtures.js';
import { groth16RedeemScript, groth16SignatureScript, succinctRedeemScript, succinctSignatureScript, p2shAddress } from '../src/zk-scripts.js';
import { planZkSpend } from '../src/tx.js';

const network = process.argv[2] ?? 'testnet-10';
// Placeholder recipient used only to size the spend (mass depends on script length, not the key).
// All-zero key: never a valid recipient; nothing here is ever submitted.
const SIZING_P2PK = '20' + '00'.repeat(32) + 'ac';

const g = loadGroth16();
const gRedeem = groth16RedeemScript(g.vk);
const gPlan = planZkSpend({ tag: 0x20, nInputs: g.inputs.length, redeemHex: gRedeem, signatureScriptHex: groth16SignatureScript(g), toScriptHex: SIZING_P2PK });

const s = loadSuccinct();
const sRedeem = succinctRedeemScript(s);
const sPlan = planZkSpend({ tag: 0x21, redeemHex: sRedeem, signatureScriptHex: succinctSignatureScript(s), toScriptHex: SIZING_P2PK });

const kas = (sompi) => (Number(sompi) / 1e8).toFixed(8);

console.log(`network: ${network}\n`);
console.log('Groth16 covenant (tag 0x20)');
console.log(`  address        : ${p2shAddress(gRedeem, network)}`);
console.log(`  redeem bytes   : ${gRedeem.length / 2}`);
console.log(`  compute budget : ${gPlan.computeBudget}  (allows ${(gPlan.computeBudget * 10_000 + 9_999).toLocaleString()} script units)`);
console.log(`  compute mass   : ${gPlan.masses.compute} grams   transient: ${gPlan.masses.transient}`);
console.log(`  min relay fee  : ${gPlan.minFeeSompi} sompi (${kas(gPlan.minFeeSompi)} KAS)`);
console.log(`  fund with      : >= ${kas(gPlan.minFeeSompi * 3n + 100_000_000n)} KAS (fee x3 headroom + 1 KAS to spend back)\n`);

console.log('RISC Zero Succinct covenant (tag 0x21)');
console.log(`  address        : ${p2shAddress(sRedeem, network)}`);
console.log(`  redeem bytes   : ${sRedeem.length / 2}`);
console.log(`  compute budget : ${sPlan.computeBudget}`);
console.log(`  compute mass   : ${sPlan.masses.compute} grams   transient: ${sPlan.masses.transient} (block limit 1,000,000)`);
console.log(`  min relay fee  : ${sPlan.minFeeSompi} sompi (${kas(sPlan.minFeeSompi)} KAS)`);
