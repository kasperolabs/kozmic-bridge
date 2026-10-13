#!/usr/bin/env node
// Live acceptance test against a Toccata node (testnet-10 by default).
//
// Flow, on ONE funded covenant UTXO:
//   1. submit a spend whose proof has one flipped byte  -> node must REJECT (ZkIntegrity)
//   2. submit the spend with the genuine fixture proof   -> node must ACCEPT (txid returned, mined ~1s later)
// Nothing is signed with a key. The only thing that opens the UTXO is a valid proof
// for the verifying key pinned in the redeem script.
//
// Usage:
//   node bin/live.mjs --to kaspatest:qq... [--url ws://127.0.0.1:17210] [--network testnet-10]
//                     [--fixture groth16|succinct] [--fee-mult 2] [--skip-bad] [--dry-run]
//
// Fund the covenant address first (node bin/address.mjs). testnet-10 faucet: https://faucet-tn10.kaspanet.io
//
// Default RPC: the public resolver. Prefer your own node (--url) for a stable wRPC Borsh endpoint
// (kaspad --testnet --netsuffix=10 --rpclisten-borsh=0.0.0.0:17210 --utxoindex).
import { createRequire } from 'node:module';
if (typeof globalThis.WebSocket === 'undefined') { try { globalThis.WebSocket = createRequire(import.meta.url)('websocket').w3cwebsocket; } catch {} }
import { kaspa } from '../src/sdk.js';
import { loadGroth16, loadSuccinct } from '../src/fixtures.js';
import {
  groth16RedeemScript,
  groth16SignatureScript,
  succinctRedeemScript,
  succinctSignatureScript,
  p2shAddress,
  flipByte,
} from '../src/zk-scripts.js';
import { buildZkSpend, planZkSpend } from '../src/tx.js';

const { RpcClient, Resolver, Encoding, payToAddressScript } = kaspa;

const TOCCATA_ACTIVATION_DAA = { 'testnet-10': 467_579_632n, mainnet: 474_165_565n };
const COINBASE_MATURITY = 100n;

const args = parseArgs(process.argv.slice(2));
if (!args.to) {
  console.error('missing --to <your address on the same network>');
  process.exit(2);
}
const network = args.network ?? 'testnet-10';
const fixtureName = args.fixture ?? 'groth16';
const feeMult = BigInt(args['fee-mult'] ?? 2);

const fx = fixtureName === 'succinct'
  ? (() => { const s = loadSuccinct(); return { tag: 0x21, nInputs: 0, redeem: succinctRedeemScript(s), good: succinctSignatureScript(s), bad: succinctSignatureScript({ ...s, seal: flipByte(s.seal, 1000) }), badWhat: 'seal word at byte 1000' }; })()
  : (() => { const g = loadGroth16(); return { tag: 0x20, nInputs: g.inputs.length, redeem: groth16RedeemScript(g.vk), good: groth16SignatureScript(g), bad: groth16SignatureScript({ ...g, proof: flipByte(g.proof, 0) }), badWhat: 'proof byte 0' }; })();

const covenantAddress = p2shAddress(fx.redeem, network);
const toSpk = payToAddressScript(args.to);
const toScriptHex = toSpk.script;
const plan = planZkSpend({ tag: fx.tag, nInputs: fx.nInputs, redeemHex: fx.redeem, signatureScriptHex: fx.good, toScriptHex });
const fee = plan.minFeeSompi * feeMult;

console.log(`fixture         : ${fixtureName} (tag 0x${fx.tag.toString(16)})`);
console.log(`covenant address: ${covenantAddress}`);
console.log(`destination     : ${args.to}`);
console.log(`compute budget  : ${plan.computeBudget}   compute mass ${plan.masses.compute}   transient ${plan.masses.transient}`);
console.log(`fee             : ${fee} sompi (${(Number(fee) / 1e8).toFixed(8)} KAS)`);

if (args['dry-run']) {
  const tx = buildZkSpend({ prevTxId: '00'.repeat(32), prevIndex: 0, prevAmount: fee + 100_000_000n, redeemHex: fx.redeem, signatureScript: fx.good, computeBudget: plan.computeBudget, toScriptHex, fee });
  console.log(`dry-run txid    : ${tx.id}`);
  process.exit(0);
}

const rpc = new RpcClient(args.url ? { url: args.url, encoding: Encoding.Borsh, networkId: network } : { resolver: new Resolver(), networkId: network });
const connectTimeoutMs = Number(args['connect-timeout'] ?? 30_000);
await Promise.race([
  rpc.connect(),
  new Promise((_, rej) => setTimeout(() => rej(new Error(`could not connect within ${connectTimeoutMs} ms (try --url ws://<your-node>:17210)`)), connectTimeoutMs)),
]).catch((e) => { console.error(String(e.message ?? e)); process.exit(4); });
console.log(`connected       : ${rpc.url}`);

try {
  const dag = await rpc.getBlockDagInfo();
  const activation = TOCCATA_ACTIVATION_DAA[network];
  if (activation !== undefined && dag.virtualDaaScore < activation) {
    throw new Error(`Toccata not active yet on ${network}: DAA ${dag.virtualDaaScore} < ${activation}`);
  }
  console.log(`virtual DAA     : ${dag.virtualDaaScore} (Toccata active)`);

  const { entries } = await rpc.getUtxosByAddresses([covenantAddress]);
  const need = fee + 100_000n;
  const spendable = entries.filter((e) => e.amount >= need && (!e.entry.isCoinbase || dag.virtualDaaScore - e.entry.blockDaaScore >= COINBASE_MATURITY));
  if (spendable.length === 0) {
    console.log(`\nNo spendable UTXO (>= ${need} sompi) at the covenant address. Fund it and rerun:\n  ${covenantAddress}`);
    process.exit(1);
  }
  const u = spendable[0];
  const prev = { prevTxId: u.outpoint.transactionId, prevIndex: u.outpoint.index, prevAmount: u.amount };
  console.log(`spending UTXO   : ${prev.prevTxId}:${prev.prevIndex} (${prev.prevAmount} sompi)`);

  const common = { ...prev, redeemHex: fx.redeem, computeBudget: plan.computeBudget, toScriptHex, fee };

  if (!args['skip-bad']) {
    console.log(`\n[1/2] submitting spend with corrupted ${fx.badWhat} ...`);
    const badTx = buildZkSpend({ ...common, signatureScript: fx.bad });
    try {
      const r = await rpc.submitTransaction({ transaction: badTx, allowOrphan: false });
      console.log(`  !! ACCEPTED (${r.transactionId}) - this should not happen. Stopping.`);
      process.exit(3);
    } catch (e) {
      console.log(`  rejected as expected:\n    ${String(e.message ?? e).split('\n')[0]}`);
    }
  }

  console.log(`\n[2/2] submitting spend with the genuine proof ...`);
  const goodTx = buildZkSpend({ ...common, signatureScript: fx.good });
  const r = await rpc.submitTransaction({ transaction: goodTx, allowOrphan: false });
  console.log(`  accepted: txid ${r.transactionId}`);

  // confirm it left the mempool / landed in the UTXO set of the destination
  const t0 = Date.now();
  let seen = false;
  while (Date.now() - t0 < 20_000) {
    await new Promise((res) => setTimeout(res, 1500));
    const { entries: dest } = await rpc.getUtxosByAddresses([args.to]);
    if (dest.some((e) => e.outpoint.transactionId === r.transactionId)) { seen = true; break; }
  }
  console.log(seen ? `  confirmed: output now in UTXO set of ${args.to}` : '  (not yet visible at destination after 20s; check an explorer)');
  console.log(`\nA UTXO on ${network} was opened by a ZK proof and nothing else.`);
} finally {
  await rpc.disconnect();
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    out[k] = v;
  }
  return out;
}
