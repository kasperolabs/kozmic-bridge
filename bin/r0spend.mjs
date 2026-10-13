#!/usr/bin/env node
// Lock to / spend from a covenant pinned to a RISC Zero program (image id), using the
// SDK's ZkScriptBuilder (v2.1.0). Works with any "bundle" directory containing:
//   image_id.hex      32 bytes  hash of the guest program
//   journal_hash.hex  32 bytes  sha256 of the journal the receipt commits to
//   receipt.hex       borsh-encoded Groth16Receipt<ReceiptClaim> (risc0-zkvm 3.0.4)
//   journal.hex       (optional) raw journal bytes, shown decoded if --decode is given
// The prover in prover/ writes exactly this bundle. fixtures/r0-example/ is the SDK's own.
//
//   node bin/r0spend.mjs address --bundle prover/out [--network mainnet]
//   node bin/r0spend.mjs spend   --bundle prover/out --to kaspa:q... --url ws://127.0.0.1:17110
//                                [--network mainnet] [--budget 1550] [--skip-bad] [--fee-mult 2]
import { createRequire } from 'node:module';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
if (typeof globalThis.WebSocket === 'undefined') {
  try { globalThis.WebSocket = createRequire(import.meta.url)('websocket').w3cwebsocket; } catch { /* only needed for spend on Node < 22 */ }
}
import { kaspa } from '../src/sdk.js';
import { buildZkSpend, planZkSpend } from '../src/tx.js';
import { coveringComputeBudget, allowedScriptUnits } from '../src/cost.js';
import { flipByte, networkTypeFor } from '../src/zk-scripts.js';

const { ZkScriptBuilder, RpcClient, Encoding, payToAddressScript, payToScriptHashScript, addressFromScriptPublicKey } = kaspa;
const FLAGS = { flags: { covenantsEnabled: true } };
const TOCCATA_DAA = { mainnet: 474_165_565n, 'testnet-10': 467_579_632n };

const [cmd, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.map((a, i, v) => (a.startsWith('--') ? [a.slice(2), v[i + 1] === undefined || v[i + 1].startsWith('--') ? true : v[i + 1]] : null)).filter(Boolean));
if (!['address', 'spend'].includes(cmd) || !args.bundle) {
  console.error('usage: r0spend.mjs address|spend --bundle <dir> [--to addr --url ws://...] [--network mainnet]');
  process.exit(2);
}
const network = args.network ?? 'mainnet';
const hexFile = (name, required = true) => {
  const p = join(args.bundle, name);
  if (!existsSync(p)) { if (required) throw new Error(`missing ${p}`); return null; }
  return readFileSync(p, 'utf8').trim().toLowerCase();
};

const imageId = hexFile('image_id.hex');
const journalHash = hexFile('journal_hash.hex');
const journal = hexFile('journal.hex', false);
if (journal && createHash('sha256').update(Buffer.from(journal, 'hex')).digest('hex') !== journalHash) {
  throw new Error('journal.hex does not hash to journal_hash.hex');
}

// Redeem script exists before any proof: the covenant is defined by the program alone.
const commit = ZkScriptBuilder.newR0(FLAGS);
commit.commitToGroth16(imageId);
const redeem = commit.script();
const spk = payToScriptHashScript(redeem);
const covenant = addressFromScriptPublicKey(spk, networkTypeFor(network)).toString();

console.log(`program (image id) : ${imageId}`);
console.log(`journal hash       : ${journalHash}`);
if (journal) console.log(`journal            : ${journal}${args.decode ? '\n' + decodeMelodyJournal(journal) : ''}`);
console.log(`redeem script      : ${redeem.length / 2} bytes (image id + RISC Zero Groth16 VK + claim reconstruction + OpZkPrecompile)`);
console.log(`covenant address   : ${covenant}`);
if (cmd === 'address') process.exit(0);

// ---- spend ----
if (!args.to || !args.url) { console.error('spend needs --to and --url'); process.exit(2); }
const receipt = hexFile('receipt.hex');
const good = finalize(receipt, journalHash);
const bad = finalize(receipt, flipByte(journalHash, 0)); // valid proof, wrong public input -> pairing check fails
if (good.redeemScript !== redeem) throw new Error('finalized redeem differs from committed redeem');

const toScriptHex = payToAddressScript(args.to).script;
const plan = planZkSpend({ tag: 0x20, nInputs: 5, redeemHex: redeem, signatureScriptHex: good.sigScript, toScriptHex });
const fee = plan.minFeeSompi * BigInt(args['fee-mult'] ?? 2);
console.log(`signature script   : ${good.sigScript.length / 2} bytes   fee ${fee} sompi`);

const rpc = new RpcClient({ url: args.url, encoding: Encoding.Borsh, networkId: network });
await Promise.race([
  rpc.connect(),
  new Promise((_, rej) => setTimeout(() => rej(new Error(`could not connect to ${args.url} within 30 s`)), 30_000)),
]).catch((e) => { console.error(String(e.message ?? e)); process.exit(4); });
try {
  const dag = await rpc.getBlockDagInfo();
  if (TOCCATA_DAA[network] && dag.virtualDaaScore < TOCCATA_DAA[network]) throw new Error('Toccata not active on this node');
  const { entries } = await rpc.getUtxosByAddresses([covenant]);
  const u = entries.find((e) => e.amount >= fee + 100_000n && (!e.entry.isCoinbase || dag.virtualDaaScore - e.entry.blockDaaScore >= 100n));
  if (!u) { console.log(`\nno spendable UTXO at ${covenant}; fund it with >= ${(Number(fee) / 1e8 + 0.01).toFixed(3)} KAS and rerun`); process.exit(1); }
  console.log(`spending UTXO      : ${u.outpoint.transactionId}:${u.outpoint.index} (${u.amount} sompi)\n`);
  const common = { prevTxId: u.outpoint.transactionId, prevIndex: u.outpoint.index, prevAmount: u.amount, redeemHex: redeem, toScriptHex, fee };

  let budget = args.budget ? Number(args.budget) : 1550;
  if (!args['skip-bad']) {
    process.stdout.write(`[bad]  valid proof, journal hash with byte 0 flipped, budget ${budget} ... `);
    try {
      const r = await rpc.submitTransaction({ transaction: buildZkSpend({ ...common, signatureScript: bad.sigScript, computeBudget: budget }), allowOrphan: false });
      console.log(`ACCEPTED (${r.transactionId}) - this must not happen; stopping`); process.exit(3);
    } catch (e) {
      const msg = String(e.message ?? e).split('\n')[0];
      console.log(`rejected\n       ${msg.slice(msg.indexOf('failed'))}`);
      const m = msg.match(/used=(\d+)/);
      if (m) budget = Number(coveringComputeBudget(BigInt(m[1]))); // bad spend was under budget: learn the number
    }
  }
  for (let round = 1; round <= 6; round++) {
    process.stdout.write(`[good] genuine proof, budget ${budget} (limit ${allowedScriptUnits(budget).toLocaleString()} units) ... `);
    try {
      const r = await rpc.submitTransaction({ transaction: buildZkSpend({ ...common, signatureScript: good.sigScript, computeBudget: budget }), allowOrphan: false });
      console.log(`ACCEPTED  txid ${r.transactionId}`);
      console.log(`\nA covenant pinned to program ${imageId.slice(0, 16)}… was opened on ${network} by a proof that this program ran. Budget used: ${budget}.`);
      break;
    } catch (e) {
      const msg = String(e.message ?? e).split('\n')[0];
      const m = msg.match(/used=(\d+), limit=(\d+)/);
      if (!m) { console.log(`rejected:\n       ${msg}`); break; }
      console.log(`under budget (used=${Number(m[1]).toLocaleString()})`);
      const next = Number(coveringComputeBudget(BigInt(m[1])));
      budget = next > budget ? next : budget + 1;
    }
  }
} finally {
  await rpc.disconnect();
}

function finalize(receiptHex, journalHashHex) {
  const b = ZkScriptBuilder.newR0(FLAGS);
  b.commitToGroth16(imageId);
  return b.finalizeWithGroth16Proof(receiptHex, journalHashHex);
}

// Journal layout written by prover/methods/guest: [root u8][mode u8][n u16 LE][sha256(melody) 32]
function decodeMelodyJournal(hex) {
  const b = Buffer.from(hex, 'hex');
  if (b.length !== 36) return '  (not a melody journal)';
  const names = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B'];
  return `  key ${names[b[0] % 12]} ${b[1] === 0 ? 'major' : 'minor'}, ${b.readUInt16LE(2)} notes, melody sha256 ${b.subarray(4).toString('hex')}`;
}
