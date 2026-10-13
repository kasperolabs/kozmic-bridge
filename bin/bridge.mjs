#!/usr/bin/env node
// BRIDGE covenant driver (CP-4 .. CP-6): deploy the Silverscript covenant in bridge/bridge.sil on
// Kaspa, bind it to its KCC-20 token, advance its Ethereum light-client state with eth-prover
// bundles (minting the deposits they carry), and move minted tokens wallet-side.
//
//   node bin/bridge.mjs key      [--key bridge-key.json]
//   node bin/bridge.mjs genesis  --bundle <dir> | --header H --committee H     --url ws://127.0.0.1:17110
//                                [--vault 0x3DD8...] [--amount 10] [--max-fee 2] [--key bridge-key.json] [--dry-run]
//   node bin/bridge.mjs init     --url ws://...   [--token-kas 1]             # creates the KCC-20 genesis
//   node bin/bridge.mjs advance  --bundle <dir> --url ws://... [--fee-mult 2] [--token-kas 1] [--budget N] [--no-measure]
//   node bin/bridge.mjs replay   --bundle <dir> --url ws://...                # must be REJECTED; recorded as evidence
//   node bin/bridge.mjs transfer --from-key bridge-key.json --to kaspa:... --amount 0.4 --url ws://...  [--utxo TXID:IDX]
//   node bin/bridge.mjs show
//
// State lives in bridge-cp6-state.json (--state to override): covenant id, token id, current
// (header, committee, cursor, token), the live covenant UTXO, the token's minter-branch UTXO,
// every minted token UTXO, and every txid / rejection. All scripts and transactions come from
// the Rust tool bridge/target/release/bridge-covenant (BRIDGE_COVENANT_BIN to override), which
// compiles bridge.sil and kcc20.sil with silverscript at a pinned commit, assembles the complete
// v1 transaction and runs every input through the 2.1.0 engine before we submit. This file only
// fetches UTXO entries, sets compute budgets, computes fees and talks to the node.
//
// Genesis is the only covenant step that uses a key: a throwaway Schnorr key funds the covenant's
// genesis output (KIP-20 covenant id derived from that input). After that nothing on the bridge
// side is signed by anyone; `transfer` signs with a token holder's key, as a wallet would.
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
if (typeof globalThis.WebSocket === 'undefined') {
  try { globalThis.WebSocket = createRequire(import.meta.url)('websocket').w3cwebsocket; } catch { /* Node >= 22 has WebSocket */ }
}
import { kaspa } from '../src/sdk.js';
import { spendMasses, feeMassGrams, minimumRelayFeeSompi, coveringComputeBudget, allowedScriptUnits, storageMassGrams, utxoPlurality } from '../src/cost.js';

const { RpcClient, Encoding, Transaction, PrivateKey, Keypair, Address, payToAddressScript, payToScriptHashScript, addressFromScriptPublicKey, signTransaction, kaspaToSompi, ScriptPublicKey } = kaspa;

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TOOL = process.env.BRIDGE_COVENANT_BIN ?? join(ROOT, 'bridge', 'target', 'release', 'bridge-covenant');
const SUBNET = '0000000000000000000000000000000000000000';
const TOCCATA_DAA = { mainnet: 474_165_565n, 'testnet-10': 467_579_632n };
const P2SH_SCRIPT_LEN = 35; // OpBlake2b OpData32 <hash> OpEqual
const ZERO32 = '0'.repeat(64);
const DEFAULT_VAULT = '3dd8cd71c3efe664d4db96d30fbfecbeea06d529';

const [cmd, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);
const network = args.network ?? 'mainnet';
const statePath = resolve(args.state ?? 'bridge-cp6-state.json');
const keyPath = resolve(args.key ?? 'bridge-key.json');
const feeMult = BigInt(args['fee-mult'] ?? 2);
const tokenKas = kaspaToSompi(String(args['token-kas'] ?? '1'));

const jsonBig = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
const loadState = () => {
  if (!existsSync(statePath)) die(`no ${statePath}; run genesis first`);
  return JSON.parse(readFileSync(statePath, 'utf8'));
};
const saveState = (s) => writeFileSync(statePath, jsonBig(s) + '\n');
const p2shAddr = (redeemHex) => addressFromScriptPublicKey(payToScriptHashScript(redeemHex), network).toString();
const spkAddr = (scriptHex) => addressFromScriptPublicKey(new ScriptPublicKey(0, scriptHex), network).toString();
const now = () => new Date().toISOString();

switch (cmd) {
  case 'key': await cmdKey(); break;
  case 'genesis': await cmdGenesis(); break;
  case 'init': await cmdInit(); break;
  case 'advance': await cmdAdvance({ replay: false }); break;
  case 'replay': await cmdAdvance({ replay: true }); break;
  case 'transfer': await cmdTransfer(); break;
  case 'show': cmdShow(); break;
  default:
    console.error('usage: bridge.mjs key | genesis | init | advance --bundle DIR | replay --bundle DIR | transfer --from-key F --to ADDR --amount N | show   (all but key/show need --url WS)');
    process.exit(2);
}

// ---------------------------------------------------------------------------

function covenantArgs(p) {
  return ['--image-id', p.imageId, '--chain-commitment', p.chainCommitment, '--vault', p.vault, '--max-fee', String(p.maxFee),
    '--header', p.header, '--committee', p.committee, '--cursor', String(p.cursor ?? 0), '--token', p.token ?? ZERO32];
}

function tool(sub, a) {
  try {
    return JSON.parse(execFileSync(TOOL, [sub, ...a], { encoding: 'utf8', maxBuffer: 64 << 20 }));
  } catch (e) {
    die(`bridge-covenant ${sub} failed: ${e.stderr || e.message}\n(build it: cd bridge && cargo build --release)`);
  }
}

function readBundleJournal(dir) {
  return tool('journal', ['--bundle', dir]);
}

async function connect() {
  if (!args.url) die('--url ws://<your node>:17110 (wRPC Borsh) is required');
  const rpc = new RpcClient({ url: args.url, encoding: Encoding.Borsh, networkId: network });
  await Promise.race([
    rpc.connect(),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`could not connect to ${args.url} within 30 s`)), 30_000)),
  ]).catch((e) => die(String(e.message ?? e), 4));
  const dag = await rpc.getBlockDagInfo();
  if (TOCCATA_DAA[network] && dag.virtualDaaScore < TOCCATA_DAA[network]) die('Toccata not active on this node');
  return { rpc, dag };
}

function firstLine(e) { return String(e?.message ?? e).split('\n')[0]; }
function usedUnits(msg) { const m = msg.match(/used=(\d+)/); return m ? BigInt(m[1]) : null; }
function failingInput(msg) { const m = msg.match(/input(?: index)?[ #:]*(\d+)/i); return m ? Number(m[1]) : null; }

async function waitForUtxo(rpc, address, txid, index = 0, timeoutMs = 60_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const { entries } = await rpc.getUtxosByAddresses([address]);
    const e = entries.find((x) => x.outpoint.transactionId === txid && x.outpoint.index === index);
    if (e) return e;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}

/** The node's UTXO entry for each input of a tool-built tx (by P2SH address of its spk). */
async function fetchEntries(rpc, txJson) {
  const out = [];
  for (const i of txJson.inputs) {
    const addr = spkAddr(i.scriptPublicKey);
    const { entries } = await rpc.getUtxosByAddresses([addr]);
    const e = entries.find((x) => x.outpoint.transactionId === i.transactionId && x.outpoint.index === i.index);
    if (!e) die(`input ${i.transactionId}:${i.index} not found at ${addr} (spent already, or not yet in the UTXO index)`, 1);
    if (BigInt(e.amount) !== BigInt(i.amount)) die(`input ${i.transactionId}:${i.index} holds ${e.amount} sompi, the state file says ${i.amount}`, 3);
    const cid = e.entry?.covenantId?.toString();
    if (i.covenantId && cid && cid !== i.covenantId) die(`input ${i.transactionId}:${i.index} carries covenant id ${cid}, expected ${i.covenantId}`, 3);
    out.push(e);
  }
  return out;
}

/** Build the SDK Transaction from the tool's JSON with the given per-input compute budgets. */
function sdkTx(txJson, budgets, entries, genesisGroups = []) {
  const tx = new Transaction({
    version: 1,
    inputs: txJson.inputs.map((i, k) => ({
      previousOutpoint: { transactionId: i.transactionId, index: i.index }, signatureScript: i.signatureScript, sequence: 0n, sigOpCount: 0, computeBudget: budgets[k],
      utxo: { outpoint: { transactionId: i.transactionId, index: i.index }, amount: BigInt(i.amount), scriptPublicKey: { version: i.scriptVersion, script: i.scriptPublicKey }, blockDaaScore: entries[k].entry.blockDaaScore, isCoinbase: entries[k].entry.isCoinbase },
    })),
    outputs: txJson.outputs.map((o, idx) => ({
      value: BigInt(o.value), scriptPublicKey: { version: o.scriptVersion, script: o.scriptPublicKey },
      // genesis-group outputs get their binding from populateGenesisCovenants below
      ...(o.covenant && !genesisGroups.some((g) => g.outputs.includes(idx)) ? { covenant: { authorizingInput: o.covenant.authorizingInput, covenantId: o.covenant.covenantId } } : {}),
    })),
    lockTime: 0n, subnetworkId: SUBNET, gas: 0n, payload: '',
  });
  if (genesisGroups.length) tx.populateGenesisCovenants(genesisGroups);
  return tx;
}

/** Fee for a tool-built tx shape at these budgets: max(compute, storage, transient/2) * feeMult. */
function feeFor(txJson, budgets) {
  const masses = spendMasses({ version: 1,
    inputs: txJson.inputs.map((i, k) => ({ signatureScriptLen: i.signatureScript.length / 2, computeBudget: budgets[k] })),
    outputs: txJson.outputs.map((o) => ({ scriptLen: o.scriptPublicKey.length / 2, covenant: !!o.covenant })) });
  const storage = storageMassGrams(
    txJson.inputs.map((i) => ({ amount: BigInt(i.amount), plurality: utxoPlurality(i.scriptPublicKey.length / 2, !!i.covenantId) })),
    txJson.outputs.map((o) => ({ amount: BigInt(o.value), plurality: utxoPlurality(o.scriptPublicKey.length / 2, !!o.covenant) })));
  const mass = [feeMassGrams(masses), storage].reduce((a, b) => (a > b ? a : b));
  return { fee: minimumRelayFeeSompi(mass) * feeMult, mass, storage };
}

/**
 * Submit a tool-built tx with budget walk-up. `build(fee)` returns the tool JSON for that fee
 * (the tool rebuilds the tx so the fee comes out of the bridge successor). Starts input 0 one
 * under the local engine's count so the node reports its own (an under-budget spend is a free
 * rejection with used=N), the other inputs at their local count + 1.
 */
async function submitWalkup(rpc, build, { label, replay = false, genesisGroups = [] }) {
  let r = build(0n);
  const local = r.simulate.ok ? r.simulate.budgets.map(Number) : r.tx.inputs.map(() => 1560);
  let budgets = local.map((b, k) => (k === 0 ? (args.budget ? Number(args.budget) : (args['no-measure'] || replay ? b : b - 1)) : b + 1));
  for (let round = 1; round <= 8; round++) {
    // fee fixed point: the fee changes the output values, which change the storage mass
    let { fee, mass, storage } = feeFor(r.tx, budgets);
    for (let k = 0; k < 6; k++) {
      r = build(fee);
      const again = feeFor(r.tx, budgets);
      if (again.fee <= fee) break;
      ({ fee, mass, storage } = again);
    }
    const entries = await fetchEntries(rpc, r.tx);
    const tx = sdkTx(r.tx, budgets, entries, genesisGroups);
    process.stdout.write(`${label} budgets [${budgets.join(', ')}] (limits ${budgets.map((b) => allowedScriptUnits(b)).join('/')} units), mass ${mass} g (storage ${storage}), fee ${fee} sompi ... `);
    try {
      const res = await rpc.submitTransaction({ transaction: tx, allowOrphan: false });
      console.log(`ACCEPTED  txid ${res.transactionId}`);
      return { txid: res.transactionId, budgets, fee, r, tx };
    } catch (e) {
      const msg = firstLine(e);
      const used = usedUnits(msg);
      if (used === null) {
        console.log(replay ? 'REJECTED (expected)' : 'rejected');
        console.log(`  ${msg}`);
        return { rejected: msg, budgets, r };
      }
      const which = failingInput(msg) ?? 0;
      console.log(`under budget (node: input ${which} used=${used})`);
      const next = Number(coveringComputeBudget(used));
      budgets[which] = next > budgets[which] ? next : budgets[which] + 1;
    }
  }
  die('budget walk-up did not converge in 8 rounds', 1);
}

function recipientInfo(spk) {
  // 33-byte kaspa_spk hex -> address
  const version = parseInt(spk.slice(0, 2), 16);
  const payload = spk.slice(2);
  const script = version === 0 ? `20${payload}ac` : `aa20${payload}87`;
  return { version, payload, address: spkAddr(script) };
}

// ---------------------------------------------------------------------------

async function cmdKey() {
  if (existsSync(keyPath)) die(`${keyPath} exists; refusing to overwrite`);
  const kp = Keypair.random();
  writeFileSync(keyPath, JSON.stringify({ privateKey: kp.privateKey, note: 'throwaway key that funds the BRIDGE covenant genesis output' }, null, 2) + '\n');
  chmodSync(keyPath, 0o600);
  console.log(`key file     : ${keyPath} (chmod 600)`);
  console.log(`fund address : ${kp.toAddress(network).toString()}`);
  console.log(`send it the genesis amount + 0.3 KAS`);
}

async function cmdGenesis() {
  if (existsSync(statePath)) die(`${statePath} exists: a covenant is already deployed from this directory (use --state for another instance)`);
  let header = args.header, committee = args.committee, cc = args['chain-commitment'], imageId = args['image-id'];
  if (args.bundle) {
    const b = readBundleJournal(args.bundle);
    header ??= b.journal.prevHeader; committee ??= b.journal.prevCommittee; cc ??= b.journal.chainCommitment; imageId ??= b.imageId;
  }
  if (!header || !committee || !cc || !imageId) die('--bundle <dir> or all of --header --committee --chain-commitment --image-id');
  const p = { imageId, chainCommitment: cc, vault: (args.vault ?? DEFAULT_VAULT).replace(/^0x/, '').toLowerCase(), maxFee: kaspaToSompi(String(args['max-fee'] ?? '2')), header, committee, cursor: 0, token: ZERO32 };
  const amount = kaspaToSompi(String(args.amount ?? '10'));
  const s = tool('script', covenantArgs(p));
  const covAddr = p2shAddr(s.redeem);
  console.log(`program (image id)  : ${p.imageId}`);
  console.log(`chain commitment    : ${p.chainCommitment}`);
  console.log(`vault               : 0x${p.vault}`);
  console.log(`initial header      : ${p.header}`);
  console.log(`initial committee   : ${p.committee}`);
  console.log(`cursor / token      : 0 / (none yet)`);
  console.log(`max fee per spend   : ${p.maxFee} sompi`);
  console.log(`token template      : hash ${s.tokenTemplateHash}, prefix ${s.tokenPrefixLen} B, suffix ${s.tokenSuffixLen} B, maxCovIns ${s.tokenMaxCovIns}, maxCovOuts ${s.tokenMaxCovOuts}`);
  console.log(`redeem script       : ${s.redeemLen} bytes, state at [${s.stateSpan}]`);
  console.log(`covenant address    : ${covAddr}`);
  if (!existsSync(keyPath)) die(`no ${keyPath}; run: node bin/bridge.mjs key`);
  const key = new PrivateKey(JSON.parse(readFileSync(keyPath, 'utf8')).privateKey);
  const keyAddr = key.toAddress(network).toString();
  const keySpk = payToAddressScript(keyAddr);
  const covSpk = payToScriptHashScript(s.redeem);

  const { rpc, dag } = await connect();
  try {
    const { entries } = await rpc.getUtxosByAddresses([keyAddr]);
    const mature = entries.filter((e) => !e.entry.isCoinbase || dag.virtualDaaScore - e.entry.blockDaaScore >= 100n).sort((a, b) => (b.amount > a.amount ? 1 : -1));
    const u = mature[0];
    if (!u || u.amount < amount + 20_000_000n) die(`fund ${keyAddr} with >= ${(Number(amount) / 1e8 + 0.3).toFixed(2)} KAS (one UTXO) and rerun`, 1);
    console.log(`funding UTXO        : ${u.outpoint.transactionId}:${u.outpoint.index} (${u.amount} sompi)`);

    let budget = Number(args['key-budget'] ?? 10);
    for (let round = 1; round <= 6; round++) {
      const masses = spendMasses({ version: 1, inputs: [{ signatureScriptLen: 66, computeBudget: budget }],
        outputs: [{ scriptLen: P2SH_SCRIPT_LEN, covenant: true }, { scriptLen: keySpk.script.length / 2 }] });
      const fee = minimumRelayFeeSompi(feeMassGrams(masses)) * feeMult;
      const change = u.amount - amount - fee;
      const tx = new Transaction({
        version: 1,
        inputs: [{ previousOutpoint: { transactionId: u.outpoint.transactionId, index: u.outpoint.index }, signatureScript: '', sequence: 0n, sigOpCount: 0, computeBudget: budget,
          utxo: { outpoint: { transactionId: u.outpoint.transactionId, index: u.outpoint.index }, amount: u.amount, scriptPublicKey: { version: keySpk.version, script: keySpk.script }, blockDaaScore: u.entry.blockDaaScore, isCoinbase: u.entry.isCoinbase } }],
        outputs: [
          { value: amount, scriptPublicKey: { version: covSpk.version, script: covSpk.script } },
          { value: change, scriptPublicKey: { version: keySpk.version, script: keySpk.script } },
        ],
        lockTime: 0n, subnetworkId: SUBNET, gas: 0n, payload: '',
      });
      tx.populateGenesisCovenants([{ authorizingInput: 0, outputs: [0] }]);
      const covenantId = tx.outputs[0].covenant.toJSON().covenantId;
      const signed = signTransaction(tx, [key], true);
      if (args['dry-run']) { console.log(`dry-run: covenant id ${covenantId}, txid ${signed.id}, fee ${fee}`); return; }
      process.stdout.write(`[genesis] budget ${budget}, fee ${fee} sompi ... `);
      try {
        const r = await rpc.submitTransaction({ transaction: signed, allowOrphan: false });
        console.log(`ACCEPTED  txid ${r.transactionId}`);
        console.log(`covenant id         : ${covenantId}`);
        const st = {
          network, contract: 'bridge/bridge.sil', token: 'bridge/kcc20.sil', silverscript: 'kaspanet/silverscript@a0dd7448ccc7bad5b99140f2c8edbbd0b2a874f1',
          params: { imageId: p.imageId, chainCommitment: p.chainCommitment, vault: p.vault, maxFee: p.maxFee.toString(),
            tokenTemplateHash: s.tokenTemplateHash, tokenPrefixLen: s.tokenPrefixLen, tokenSuffixLen: s.tokenSuffixLen, tokenMaxCovIns: s.tokenMaxCovIns, tokenMaxCovOuts: s.tokenMaxCovOuts },
          covenantId, genesisTxid: r.transactionId, tokenId: null,
          state: { header: p.header, committee: p.committee, cursor: 0, token: ZERO32 },
          utxo: { txid: r.transactionId, index: 0, amount: amount.toString() }, address: covAddr,
          minter: null, tokens: [],
          history: [{ kind: 'genesis', txid: r.transactionId, header: p.header, committee: p.committee, at: now() }],
        };
        saveState(st);
        const seen = await waitForUtxo(rpc, covAddr, r.transactionId);
        const cid = seen?.entry?.covenantId?.toString();
        console.log(seen ? `covenant UTXO live   : ${covAddr} (node reports covenant id ${cid ?? 'n/a'})` : 'not visible in the UTXO index after 60 s; check before init');
        if (cid && cid !== covenantId) die(`node reports covenant id ${cid}, expected ${covenantId}`, 3);
        return;
      } catch (e) {
        const msg = firstLine(e);
        const used = usedUnits(msg);
        if (used === null) die(`rejected: ${msg}`, 1);
        const next = Number(coveringComputeBudget(used));
        console.log(`under budget (used=${used})`);
        budget = next > budget ? next : budget + 1;
      }
    }
  } finally {
    await rpc.disconnect();
  }
}

async function cmdInit() {
  const st = loadState();
  if (st.tokenId) die(`token already initialized: ${st.tokenId}`);
  const p = { ...st.params, maxFee: BigInt(st.params.maxFee), ...st.state };
  const amount = BigInt(st.utxo.amount);
  const build = (fee) => tool('init', [...covenantArgs(p), '--covenant-id', st.covenantId, '--utxo', `${st.utxo.txid}:${st.utxo.index}`, '--value', amount.toString(), '--fee', fee.toString(), '--token-out', tokenKas.toString()]);
  const r0 = build(0n);
  if (p2shAddr(r0.redeem) !== st.address) die(`redeem for the recorded state hashes to ${p2shAddr(r0.redeem)}, state file says ${st.address}`, 3);
  console.log(`covenant            : ${st.covenantId}`);
  console.log(`token id (expected) : ${r0.tokenId}`);
  console.log(`minter branch       : ${p2shAddr(r0.minterRedeem)} (${tokenKas} sompi)`);
  console.log(`local engine        : ${r0.simulate.ok ? `accepts, ${r0.simulate.scriptUnits} script units` : `rejects (${r0.simulate.error})`}`);
  if (!r0.simulate.ok) die('the local engine rejects init; not submitting', 1);
  const { rpc } = await connect();
  try {
    const res = await submitWalkup(rpc, build, { label: '[init]', genesisGroups: [{ authorizingInput: 0, outputs: [1] }] });
    if (res.rejected) { st.history.push({ kind: 'init-rejected', error: res.rejected, at: now() }); saveState(st); process.exit(1); }
    const sdkTokenId = res.tx.outputs[1].covenant.toJSON().covenantId;
    if (sdkTokenId !== res.r.tokenId) die(`SDK derived token id ${sdkTokenId}, the tool ${res.r.tokenId}`, 3);
    st.tokenId = res.r.tokenId;
    st.state = res.r.nextState;
    st.utxo = { txid: res.txid, index: 0, amount: res.r.tx.outputs[0].value };
    st.address = p2shAddr(res.r.successorRedeem);
    st.minter = { txid: res.txid, index: 1, amount: res.r.tx.outputs[1].value, address: p2shAddr(res.r.minterRedeem) };
    st.history.push({ kind: 'init', txid: res.txid, tokenId: st.tokenId, budgets: res.budgets, fee: res.fee.toString(), localScriptUnits: res.r.simulate.scriptUnits, at: now() });
    saveState(st);
    const seen = await waitForUtxo(rpc, st.minter.address, res.txid, 1);
    console.log(seen ? `token genesis live  : ${st.minter.address} (node reports covenant id ${seen.entry?.covenantId?.toString() ?? 'n/a'})` : 'token genesis not visible after 60 s; check before advancing');
    console.log(`successor           : ${st.address}`);
  } finally {
    await rpc.disconnect();
  }
}

async function cmdAdvance({ replay }) {
  if (!args.bundle) die('--bundle <dir>');
  const st = loadState();
  const p = { ...st.params, maxFee: BigInt(st.params.maxFee), ...st.state };
  const amount = BigInt(st.utxo.amount);
  const base = [...covenantArgs(p), '--covenant-id', st.covenantId, '--utxo', `${st.utxo.txid}:${st.utxo.index}`, '--value', amount.toString(), '--bundle', args.bundle, '--token-out', tokenKas.toString()];
  const withMinter = st.minter ? ['--minter-utxo', `${st.minter.txid}:${st.minter.index}`, '--minter-value', String(st.minter.amount)] : [];
  const build = (fee) => tool('advance', [...base, ...withMinter, '--fee', fee.toString()]);
  const a = build(0n);
  if (p2shAddr(a.redeem) !== st.address) die(`redeem for the recorded state hashes to ${p2shAddr(a.redeem)}, state file says ${st.address}`, 3);
  console.log(`covenant            : ${st.covenantId}   token ${st.tokenId ?? '(none)'}`);
  console.log(`state               : header ${st.state.header}  cursor ${st.state.cursor}`);
  console.log(`journal prev_header : ${a.journal.prevHeader}${a.journalMatchesState ? '  (matches)' : '  (DOES NOT MATCH)'}`);
  console.log(`journal new_header  : ${a.journal.newHeader}  slot ${a.journal.newSlot}  exec block ${a.journal.execBlockNumber}`);
  console.log(`journal deposits    : ${a.journal.deposits.map((d) => `#${d.nonce} ${d.amount} -> ${recipientInfo(d.kaspaSpk).address}`).join('; ') || 'none'}`);
  console.log(`mints this advance  : ${a.mints.length ? a.mints.map((d) => `#${d.nonce} ${d.amount}`).join(', ') : 'none (heartbeat)'}   tx: ${a.tx.inputs.length} inputs, ${a.tx.outputs.length} outputs`);
  console.log(`local engine        : ${a.simulate.ok ? `accepts, ${a.simulate.scriptUnits.join(' + ')} script units` : `rejects input ${a.simulate.input} (${a.simulate.error})`}`);
  if (replay) {
    if (a.simulate.ok) die('replay: the local engine ACCEPTS this spend, so it is not a replay of a used proof; refusing to submit', 3);
  } else if (!a.simulate.ok || !a.journalMatchesState) {
    die('the local engine rejects this transition; not submitting (use replay to submit a rejected spend on purpose)', 1);
  }
  const { rpc } = await connect();
  try {
    const label = replay ? '[replay]' : '[advance]';
    const res = await submitWalkup(rpc, build, { label, replay });
    if (res.rejected) {
      st.history.push({ kind: replay ? 'replay-rejected' : 'advance-rejected', bundle: args.bundle, budgets: res.budgets, error: res.rejected, stateHeader: st.state.header, cursor: st.state.cursor, at: now() });
      saveState(st);
      process.exit(replay ? 0 : 1);
    }
    if (replay) {
      console.log(`A replayed proof opened the covenant (${res.txid}); this must not happen.`);
      st.history.push({ kind: 'replay-ACCEPTED', txid: res.txid, bundle: args.bundle, at: now() });
      saveState(st);
      process.exit(3);
    }
    const r = res.r;
    st.state = r.nextState;
    st.utxo = { txid: res.txid, index: 0, amount: r.tx.outputs[0].value };
    st.address = p2shAddr(r.successorRedeem);
    const minted = [];
    if (r.mints.length) {
      st.minter = { txid: res.txid, index: 1, amount: r.tx.outputs[1].value, address: st.minter.address };
      r.mints.forEach((d, k) => {
        const rec = recipientInfo(d.kaspaSpk);
        const t = { txid: res.txid, index: 2 + k, value: r.tx.outputs[2 + k].value, nonce: d.nonce, amount: d.amount, owner: rec.payload, ownerType: rec.version === 0 ? 0 : 1, ownerAddress: rec.address, address: p2shAddr(d.tokenRedeem) };
        minted.push(t);
        st.tokens.push(t);
      });
    }
    st.history.push({ kind: 'advance', txid: res.txid, bundle: args.bundle, budgets: res.budgets, fee: res.fee.toString(),
      prevHeader: r.journal.prevHeader, newHeader: r.journal.newHeader, newCommittee: r.journal.newCommittee, newSlot: r.journal.newSlot,
      mints: r.mints.map((d) => d.nonce), cursor: r.nextState.cursor, localScriptUnits: r.simulate.scriptUnits, at: now() });
    saveState(st);
    const seen = await waitForUtxo(rpc, st.address, res.txid);
    console.log(seen ? `successor live      : ${st.address} (cursor ${st.state.cursor})` : 'successor not visible after 60 s; check before the next advance');
    for (const t of minted) console.log(`minted              : #${t.nonce} ${t.amount} units -> ${t.ownerAddress}   token UTXO ${t.txid}:${t.index} at ${t.address}`);
  } finally {
    await rpc.disconnect();
  }
}

async function cmdTransfer() {
  const st = loadState();
  if (!st.tokenId) die('no token yet');
  if (!args['from-key'] || !args.to || !args.amount) die('--from-key <file with privateKey> --to kaspa:... --amount <token units, 6 decimals e.g. 0.4>');
  const keyHex = JSON.parse(readFileSync(resolve(args['from-key']), 'utf8')).privateKey;
  const key = new PrivateKey(keyHex);
  const fromAddr = key.toAddress(network).toString();
  const fromSpk = payToAddressScript(fromAddr).script;
  const owner = fromSpk.slice(2, 66);
  const held = args.utxo
    ? st.tokens.find((t) => `${t.txid}:${t.index}` === args.utxo)
    : st.tokens.filter((t) => t.owner === owner && !t.spent).sort((a, b) => b.amount - a.amount)[0];
  if (!held) die(`no unspent token UTXO owned by ${fromAddr} in the state file (use --utxo TXID:IDX)`, 1);
  const toSpk = payToAddressScript(new Address(args.to)).script;
  const to = /^20[0-9a-f]{64}ac$/i.test(toSpk) ? { owner: toSpk.slice(2, 66), type: 0 } : /^aa20[0-9a-f]{64}87$/i.test(toSpk) ? { owner: toSpk.slice(4, 68), type: 1 } : die('--to must be a P2PK (Schnorr) or P2SH address');
  const units = BigInt(Math.round(Number(args.amount) * 1e6));
  if (units <= 0n || units > BigInt(held.amount)) die(`amount must be in (0, ${Number(held.amount) / 1e6}]`);
  const rem = BigInt(held.amount) - units;
  const outs = ['--to', to.owner, '--to-type', String(to.type), '--to-amount', units.toString()];
  if (rem > 0n) outs.push('--to2', owner, '--to2-type', '0', '--to2-amount', rem.toString());
  // KAS: the token outputs share whatever the input carries after the fee (covenant UTXOs have
  // plurality 2 under KIP-9, so small values would cost more storage mass than they are worth).
  const nOuts = rem > 0n ? 2n : 1n;
  const build = (fee) => {
    const perOut = args['token-kas'] ? tokenKas : (BigInt(held.value) - fee) / nOuts;
    if (perOut <= 0n) die(`token UTXO ${held.value} sompi cannot cover fee ${fee}`, 1);
    return tool('transfer', ['--token-id', st.tokenId, '--utxo', `${held.txid}:${held.index}`, '--value', String(held.value),
      '--owner', owner, '--owner-type', '0', '--amount', String(held.amount), '--key', keyHex, ...outs, '--token-out', perOut.toString(), '--fee', fee.toString(),
      ...(args['token-kas'] ? ['--change-spk', fromSpk] : [])]);
  };
  const r0 = build(0n);
  console.log(`token               : ${st.tokenId}`);
  console.log(`spending            : ${held.txid}:${held.index} (${Number(held.amount) / 1e6} units, ${held.value} sompi) owned by ${fromAddr}`);
  console.log(`to                  : ${args.to} ${Number(units) / 1e6} units${rem > 0n ? `, change ${Number(rem) / 1e6} units back to ${fromAddr}` : ''}`);
  console.log(`local engine        : ${r0.simulate.ok ? `accepts, ${r0.simulate.scriptUnits} script units` : `rejects (${r0.simulate.error})`}`);
  if (!r0.simulate.ok) die('the local engine rejects this transfer; not submitting', 1);
  const { rpc } = await connect();
  try {
    const res = await submitWalkup(rpc, build, { label: '[transfer]' });
    if (res.rejected) { st.history.push({ kind: 'transfer-rejected', error: res.rejected, at: now() }); saveState(st); process.exit(1); }
    held.spent = res.txid;
    const r = res.r;
    const recipients = [{ owner: to.owner, ownerType: to.type, amount: units.toString(), ownerAddress: args.to }];
    if (rem > 0n) recipients.push({ owner, ownerType: 0, amount: rem.toString(), ownerAddress: fromAddr });
    recipients.forEach((x, k) => st.tokens.push({ txid: res.txid, index: k, value: r.tx.outputs[k].value, nonce: null, ...x, address: spkAddr(r.tx.outputs[k].scriptPublicKey) }));
    st.history.push({ kind: 'transfer', txid: res.txid, from: fromAddr, to: args.to, amount: units.toString(), budgets: res.budgets, fee: res.fee.toString(), localScriptUnits: r.simulate.scriptUnits, at: now() });
    saveState(st);
    const seen = await waitForUtxo(rpc, spkAddr(r.tx.outputs[0].scriptPublicKey), res.txid, 0);
    console.log(seen ? `recipient token UTXO: ${res.txid}:0 live (covenant id ${seen.entry?.covenantId?.toString() ?? 'n/a'})` : 'recipient UTXO not visible after 60 s');
  } finally {
    await rpc.disconnect();
  }
}

function cmdShow() {
  const st = loadState();
  console.log(jsonBig({ covenantId: st.covenantId, tokenId: st.tokenId, address: st.address, state: st.state, utxo: st.utxo, minter: st.minter, tokens: st.tokens }));
  for (const h of st.history) console.log(`${h.at}  ${h.kind.padEnd(16)} ${h.txid ?? ''}${h.mints?.length ? `  mints ${h.mints.join(',')}` : ''}${h.error ? '  ' + h.error : ''}`);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const k = argv[i].slice(2);
    out[k] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  }
  return out;
}

function die(msg, code = 2) {
  console.error(msg);
  process.exit(code);
}
