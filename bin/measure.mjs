#!/usr/bin/env node
// Measures the exact compute budget a Groth16 P2SH spend needs, on the live node.
//
// Under-budget submissions are rejected at the mempool for free (the UTXO is not consumed),
// and the rejection names the units: "used=N, limit=M". N is cumulative up to the charge that
// overflowed, so we walk: budget 0 -> rejection -> set budget to cover N -> rejection or accept.
// Converges in 2-3 free rounds; only the final accepted spend costs a fee.
//
//   node bin/measure.mjs --to kaspa:qq... --url ws://127.0.0.1:17110 [--network mainnet]
import { createRequire } from 'node:module';
if (typeof globalThis.WebSocket === 'undefined') {
  globalThis.WebSocket = createRequire(import.meta.url)('websocket').w3cwebsocket;
}
import { kaspa } from '../src/sdk.js';
import { loadGroth16 } from '../src/fixtures.js';
import { groth16RedeemScript, groth16SignatureScript, p2shAddress } from '../src/zk-scripts.js';
import { buildZkSpend, planZkSpend } from '../src/tx.js';
import { coveringComputeBudget, allowedScriptUnits } from '../src/cost.js';

const { RpcClient, Encoding, payToAddressScript } = kaspa;
const args = Object.fromEntries(process.argv.slice(2).map((a, i, v) => (a.startsWith('--') ? [a.slice(2), v[i + 1]?.startsWith('--') || v[i + 1] === undefined ? true : v[i + 1]] : null)).filter(Boolean));
if (!args.to || !args.url) { console.error('usage: --to <address> --url ws://host:port [--network mainnet]'); process.exit(2); }
const network = args.network ?? 'mainnet';

const g = loadGroth16();
const redeem = groth16RedeemScript(g.vk);
const sig = groth16SignatureScript(g);
const covenant = p2shAddress(redeem, network);
const toScriptHex = payToAddressScript(args.to).script;
const plan = planZkSpend({ tag: 0x20, nInputs: 5, redeemHex: redeem, signatureScriptHex: sig, toScriptHex });
const fee = plan.minFeeSompi * 2n;

const rpc = new RpcClient({ url: args.url, encoding: Encoding.Borsh, networkId: network });
await rpc.connect();
const { entries } = await rpc.getUtxosByAddresses([covenant]);
const u = entries.find((e) => e.amount >= fee + 100_000n);
if (!u) { console.log(`fund ${covenant} with >= ${(Number(fee) / 1e8 + 0.01).toFixed(3)} KAS and rerun`); await rpc.disconnect(); process.exit(1); }
console.log(`UTXO ${u.outpoint.transactionId}:${u.outpoint.index}  (${u.amount} sompi)   estimate was budget ${plan.computeBudget}\n`);

let budget = 0;
for (let round = 1; round <= 8; round++) {
  const tx = buildZkSpend({ prevTxId: u.outpoint.transactionId, prevIndex: u.outpoint.index, prevAmount: u.amount, redeemHex: redeem, signatureScript: sig, computeBudget: budget, toScriptHex, fee });
  process.stdout.write(`round ${round}: budget ${budget} (limit ${allowedScriptUnits(budget).toLocaleString()} units) ... `);
  try {
    const r = await rpc.submitTransaction({ transaction: tx, allowOrphan: false });
    console.log(`ACCEPTED  txid ${r.transactionId}`);
    console.log(`\nexact minimum compute budget for this spend: ${budget}`);
    console.log(`(= ${budget * 100} grams of compute mass; estimate ${plan.computeBudget} was ${plan.computeBudget - budget >= 0 ? 'over' : 'UNDER'} by ${Math.abs(plan.computeBudget - budget)})`);
    break;
  } catch (e) {
    const msg = String(e.message ?? e);
    const m = msg.match(/used=(\d+), limit=(\d+)/);
    if (!m) { console.log(`rejected for another reason:\n  ${msg.split('\n')[0]}`); break; }
    const used = BigInt(m[1]);
    console.log(`rejected: used=${used.toLocaleString()} limit=${m[2]}`);
    const next = coveringComputeBudget(used);
    budget = Number(next) + (Number(next) === budget ? 1 : 0);
  }
}
await rpc.disconnect();
