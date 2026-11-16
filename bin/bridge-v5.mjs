#!/usr/bin/env node
// Sprint 7 (2026-11-15), bridge-v7 for USDC.k #1: `genesis --cell-value KAS` (default 0.3) records the covenant's KAS floor
// per minted cell and makes `--max-fee` required (v7 reads it as the fee ceiling alone); every command on a state file
// that carries `params.cellValue` checks that the Rust tool is the v7 one (`script` reports covenantVersion 7) and that
// `--token-kas` / `--auth-kas` are not below the floor. The tool is bridge-v7/target/release/bridge-covenant: point
// BRIDGE_COVENANT_V5_BIN at it (the default path is bridge-v5's, the v5 tool, which would compile the wrong covenant and
// is refused by the check). The pinned image ids: v2 `c320da…` for the old instances, the Gloas-masked `45400f5f…` for #1.
//
// BRIDGE covenant v5 driver (U7, Tipsy.k): bin/bridge.mjs (the v4 driver) with the v5 differences: `--max-mint` in the
// covenant's constants, the MinerDrip in the genesis (`genesis --drip-endow KAS --drip-prize KAS --drip-halving-days D`;
// `--prep-kas` defaults to 2 + endowment; `init` builds three outputs and records the drip; `drip-reveal` right after;
// `drip-claim` any time), the KCC-23 findability keys in `prepare` (`--minter-template`, `--artifact-url`,
// `--artifact-file`), state file bridge-v5-state.json (`v: 5`; a v4 state file is handed to bin/bridge.mjs, a v1 one
// to bin/bridge-v1.mjs). Derived from bin/bridge.mjs by u7-apply.py; the rest of this header is the v4 driver's.
//
// BRIDGE covenant v4 driver (U5): deploy bridge-v4/bridge.sil on Kaspa, write the token's KCC-23 metadata, bind
// the covenant to its KCC-20 Last Call family (reference cell + BridgeMint authority), advance its Ethereum
// light-client state with eth-prover v2 bundles (minting the status-0 deposits they carry), and move cells
// wallet-side: a plain transfer or a burn (a transfer to the unspendable owner with the KZB1 payload the relay reads).
//
//   node bin/bridge.mjs key      [--key bridge-key.json]
//   node bin/bridge.mjs genesis  --vault 0x<20 B> --eth-token 0x<20 B> --eth-token-impl 0x<20 B>
//                                (--header H --committee H | --execute-log FILE)   # FILE: stdout of `eth-prover execute`
//                                [--image-id H (pinned c320da50...)] [--chain-commitment H (mainnet)]
//                                [--amount 10] [--prep-kas 2] [--max-fee 2] --url ws://127.0.0.1:17110 [--dry-run]
//   node bin/bridge.mjs prepare  --name Wobbly --ticker Wobbly.k [--symbol Wobbly.k] [--decimals 6]
//                                --image-url https://... --image-file path.png --url ws://... [--dry-run]
//                                # the KCC-23 preparation tx: one output back to the key, payload 00 || JSON
//   node bin/bridge.mjs init     --url ws://... [--auth-kas 1]           # spends bridge + prep output; creates the family
//   node bin/bridge.mjs advance  --bundle <dir> --url ws://... [--fee-mult 2] [--token-kas 0.3] [--budget N] [--no-measure] [--dry-run]
//   node bin/bridge.mjs replay   --bundle <dir> --url ws://...           # must be REJECTED; recorded as evidence
//   node bin/bridge.mjs transfer --from-key F --to kaspa:... --amount 0.4 --url ws://... [--cell-kas 1] [--utxo TXID:IDX] [--no-fund] [--dry-run]
//   node bin/bridge.mjs burn     --from-key F --amount 10 --target 0x<relay> --recipient 0x<eth addr> [--tip 0.5]
//                                --url ws://... [--cell-kas 1] [--burn-kas K] [--utxo TXID:IDX] [--no-fund] [--dry-run]
//   node bin/bridge.mjs show
//   node bin/bridge.mjs dag --url ws://...     # the node's virtual DAA score and sink (RelayFactory's knownDaa; a START for burnwitness)
//   node bin/bridge.mjs readback --url ws://... # re-read the prep and init txs from the node (accepting block + mergeset), record the including blocks
//
// State lives in bridge-v4-state.json (--state to override): constants, covenant id, token (family) id, the live
// state (header, committee, cursor, token), the live covenant UTXO, the preparation output and its payload, the
// BridgeMint authority UTXO, every cell, every burn, every txid and rejection. All scripts, signatures and local
// engine runs come from the Rust tool bridge-v4/target/release/bridge-covenant-v4 (BRIDGE_COVENANT_V4_BIN to
// override); this file fetches UTXO entries, sets compute budgets, computes mass and fee by hand (src/cost.js) and
// talks to the node. A --state file written by the v1 driver (bridge-cp6-state.json, the live KBT instance) is
// handed to bin/bridge-v1.mjs unchanged, so the KBT service keeps working.
//
// KAS, every sompi with its reason (U5): the genesis amount is the instance's pool (every mint pays its cells' KAS
// and the advance fee from it); --prep-kas is carved out of the same funding UTXO so the KCC-23 prep tx can have
// exactly one output (the whole input minus fee) and that KAS folds back into the pool at init; the authority holds
// 1 KAS because a mint's storage mass (4C/v per covenant output) stays under its compute mass only while the
// authority and the cells are not tiny; a minted cell carries --token-kas (0.3 KAS: any value from 0.25 up leaves
// a mint compute-bound, so more would be parked for nothing); a burn cell parks cost.js optimalParkSompi (0.2 KAS at
// the minimum relay rate, the value that minimizes park + fee); a cell a holder keeps (--cell-kas, the recipient cell
// of a transfer and the change cell) carries 1 KAS because a covenant output costs 4C/v grams once and that KAS is the
// holder's to reclaim (1 KAS: 40k g; 0.3 KAS: 133k g); a transfer's fee and park come from a KAS funding input of the
// holder's key (--no-fund to drain the cell instead), so the holder's cell keeps its working KAS. Numbers from
// src/cost.js for these shapes: docs/U5-RECORD.md.
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
if (typeof globalThis.WebSocket === 'undefined') {
  try { globalThis.WebSocket = createRequire(import.meta.url)('websocket').w3cwebsocket; } catch { /* Node >= 22 has WebSocket */ }
}
import { kaspa } from '../src/sdk.js';
import { spendMasses, feeMassGrams, minimumRelayFeeSompi, coveringComputeBudget, allowedScriptUnits, storageMassGrams, utxoPlurality, optimalParkSompi, MINIMUM_RELAY_FEE_SOMPI_PER_KG } from '../src/cost.js';
import { covenantId as kip20CovenantId } from '../src/covenant-id.js';

const { RpcClient, Encoding, Transaction, PrivateKey, Keypair, Address, payToAddressScript, payToScriptHashScript, addressFromScriptPublicKey, signTransaction, kaspaToSompi, ScriptPublicKey } = kaspa;

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TOOL = process.env.BRIDGE_COVENANT_V5_BIN
  ?? [join(ROOT, 'bridge-v5', 'target', 'release', 'bridge-covenant-v5'), join(ROOT, 'bridge-v5', 'target', 'release', 'bridge-covenant')].find((p) => existsSync(p))
  ?? join(ROOT, 'bridge-v5', 'target', 'release', 'bridge-covenant-v5'); // patch 2: the binary keeps the [[bin]] name bridge-covenant
const V7_TOOL = join(ROOT, 'bridge-v7', 'target', 'release', 'bridge-covenant'); // sprint 7: what BRIDGE_COVENANT_V5_BIN must name for a v7 state
const V1_DRIVER = join(ROOT, 'bin', 'bridge-v1.mjs');
const V4_DRIVER = join(ROOT, 'bin', 'bridge.mjs');
const drip = createRequire(import.meta.url)('../minerdrip/minerdrip.js'); // schedule, checkRedeem, revealSpend, claimSpend
const SUBNET = '0000000000000000000000000000000000000000';
const TOCCATA_DAA = { mainnet: 474_165_565n, 'testnet-10': 467_579_632n };
const P2SH_SCRIPT_LEN = 35; // OpBlake2b OpData32 <hash> OpEqual
const ZERO32 = '0'.repeat(64);
/// inbound guest v2, pinned 2026-10-16 (KASPA-USDC-HANDOFF.md, U3): the image of the rehearsal instances
const PINNED_IMAGE_ID = 'c320da505b41ffb3336a5bd4d995ead15590b75f4cb4b1ae3fa25353bacb955c';
/// the pinned inbound images and their names (V4-DESIGN 2.15.5: `45400f5f…` is USDC.k #1's, inbound-mask 0fa57ca, Gloas epoch masked)
const PINNED_IMAGE_IDS = {
  [PINNED_IMAGE_ID]: 'inbound v2 (a09fe80; Wobbly.k, Tipsy.k, Sepia.k)',
  '45400f5f582380ce9919fbc5bf94f83d19e2b9aa9f5b2043030cb69b37587fd6': 'inbound mask 0fa57ca (USDC.k #1, V4-DESIGN 2.15)',
};
/// Ethereum mainnet: keccak256(genesis_validators_root || cbor(forks)); printed by every eth-prover fetch as "chain commit"
const MAINNET_CHAIN_COMMITMENT = 'ffc6300b0673ffdeaa10b11d162bc7bc375514c89e29dd03dc6eeabd88b0c90b';
/// KCC-20 Last Call reference cell (argent-lang/kcc20-reference c8a0871); the family's token class
const CELL_TEMPLATE = '9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7';
const BURN_OWNER = 'd379e50f3e2203f9a92584916335bb7cd014b237ceaa8b36f1d3d80d0cc88b32';
const SILVERSCRIPT = 'kaspanet/silverscript@a0dd7448ccc7bad5b99140f2c8edbbd0b2a874f1';

const [cmd, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);
const network = args.network ?? 'mainnet';
const statePath = resolve(args.state ?? 'bridge-v5-state.json');
const keyPath = resolve(args.key ?? 'bridge-key.json');
const feeMult = BigInt(args['fee-mult'] ?? (cmd === 'transfer' || cmd === 'burn' ? 1 : 2));
const tokenKas = kaspaToSompi(String(args['token-kas'] ?? '0.3'));
/// sprint 7: the state file's cell floor (sompi, bigint) or null for a v5/v6 covenant
const cellFloorOf = (st) => (st?.params?.cellValue != null ? BigInt(st.params.cellValue) : null);

const jsonBig = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
const loadState = () => {
  if (!existsSync(statePath)) die(`no ${statePath}; run genesis first`);
  const st = JSON.parse(readFileSync(statePath, 'utf8'));
  checkTool(st);
  return st;
};
/** sprint 7: a v7 state file (params.cellValue) needs the v7 tool, and the v5 tool must not be handed --cell-value (it would
 *  ignore it and compile the wrong covenant). The tool's `script` output says which it is; a v5/v6 state refuses a v7 tool too. */
function checkTool(st) {
  if (!st?.params || cmd === 'show') return;
  const want = cellFloorOf(st) != null ? 7 : 5;
  const s = tool('script', covenantArgs(paramsOf(st)));
  const got = s.covenantVersion ?? 5;
  if (got !== want) die(`${statePath} is a covenant v${want} state file but the tool ${TOOL} is the v${got} tool${want === 7 ? ` (set BRIDGE_COVENANT_V5_BIN=${V7_TOOL})` : ''}`, 3);
  if (want === 7 && String(s.cellValue) !== String(st.params.cellValue)) die(`tool cellValue ${s.cellValue} differs from the state file's ${st.params.cellValue}`, 3);
  if (want === 7 && p2shAddr(s.redeem) !== st.address) die(`the v7 tool's redeem for the recorded state hashes to ${p2shAddr(s.redeem)}, state file says ${st.address}`, 3);
}
const saveState = (s) => writeFileSync(statePath, jsonBig(s) + '\n');
const p2shAddr = (redeemHex) => addressFromScriptPublicKey(payToScriptHashScript(redeemHex), network).toString();
const spkAddr = (scriptHex) => addressFromScriptPublicKey(new ScriptPublicKey(0, scriptHex), network).toString();
const now = () => new Date().toISOString();
const units = (s, zeroOk = false) => { const n = Number(s); const u = Number.isFinite(n) ? BigInt(Math.round(n * 1e6)) : -1n; if (u < 0n || (u === 0n && !zeroOk)) die(`bad token amount ${s}`); return u; };
const hex20 = (s, name) => { const v = String(s ?? '').replace(/^0x/, '').toLowerCase(); if (!/^[0-9a-f]{40}$/.test(v)) die(`--${name} must be 20 bytes of hex`); return v; };
const hex32 = (s, name) => { const v = String(s ?? '').replace(/^0x/, '').toLowerCase(); if (!/^[0-9a-f]{64}$/.test(v)) die(`--${name} must be 32 bytes of hex`); return v; };

// A state file of an earlier driver (v4: Wobbly.k; v1: the KBT instance): hand the whole command to that driver.
if (existsSync(statePath) && cmd !== 'key') {
  const st = JSON.parse(readFileSync(statePath, 'utf8'));
  if (st.v !== 5) {
    const drv = st.v === 4 ? V4_DRIVER : V1_DRIVER;
    if (!existsSync(drv)) die(`${statePath} is a v${st.v} state file and ${drv} is missing`);
    const r = spawnSync(process.execPath, [drv, ...process.argv.slice(2)], { stdio: 'inherit' });
    process.exit(r.status ?? 1);
  }
}

switch (cmd) {
  case 'key': await cmdKey(); break;
  case 'genesis': await cmdGenesis(); break;
  case 'prepare': await cmdPrepare(); break;
  case 'init': await cmdInit(); break;
  case 'advance': await cmdAdvance({ replay: false }); break;
  case 'replay': await cmdAdvance({ replay: true }); break;
  case 'transfer': await cmdMove({ burn: false }); break;
  case 'burn': await cmdMove({ burn: true }); break;
  case 'drip-reveal': await cmdDrip('reveal'); break;
  case 'drip-claim': await cmdDrip('claim'); break;
  case 'show': cmdShow(); break;
  case 'readback': await cmdReadback(); break;
  case 'dag': { const { rpc, dag } = await connect(); console.log(`virtualDaaScore ${dag.virtualDaaScore}  sink ${dag.sink}`); await rpc.disconnect(); break; }
  default:
    console.error('usage: bridge-v5.mjs key | genesis | prepare | init | drip-reveal | drip-claim | advance --bundle DIR | replay --bundle DIR | transfer | burn | show   (all but key/show need --url WS)');
    process.exit(2);
}

// ---------------------------------------------------------------------------

function covenantArgs(p) {
  return ['--image-id', p.imageId, '--chain-commitment', p.chainCommitment, '--vault', p.vault, '--eth-token', p.ethToken, '--eth-token-impl', p.ethTokenImpl,
    '--max-fee', String(p.maxFee), '--max-mint', String(p.maxMint), ...(p.cellValue != null ? ['--cell-value', String(p.cellValue)] : []),
    '--extension-commitment', p.extensionCommitment ?? ZERO32,
    '--header', p.header, '--committee', p.committee, '--cursor', String(p.cursor ?? 0), '--token', p.token ?? ZERO32];
}

function paramsOf(st) {
  return { ...st.params, maxFee: BigInt(st.params.maxFee), ...st.state };
}

function tool(sub, a) {
  try {
    return JSON.parse(execFileSync(TOOL, [sub, ...a], { encoding: 'utf8', maxBuffer: 64 << 20 }));
  } catch (e) {
    die(`${TOOL} ${sub} failed: ${e.stderr || e.message}\n(build it: cd bridge-v5 && cargo build --release; for a v7 instance cd bridge-v7 && cargo build --release and set BRIDGE_COVENANT_V5_BIN=${V7_TOOL})`);
  }
}

function loadKey(path = keyPath) {
  if (!existsSync(path)) die(`no ${path}`);
  const hex = JSON.parse(readFileSync(path, 'utf8')).privateKey;
  const key = new PrivateKey(hex);
  const addr = key.toAddress(network).toString();
  const spk = payToAddressScript(addr);
  if (!/^20[0-9a-f]{64}ac$/i.test(spk.script)) die(`${addr} is not a Schnorr P2PK address`);
  return { hex, key, addr, spk, xonly: spk.script.slice(2, 66).toLowerCase() };
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

async function waitForUtxo(rpc, address, txid, index = 0, timeoutMs = 90_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const { entries } = await rpc.getUtxosByAddresses([address]);
    const e = entries.find((x) => x.outpoint.transactionId === txid && x.outpoint.index === index);
    if (e) return e;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}

/** The chain block that accepted `txid`, found from a sink captured before submission (as burnwitness does). */
async function findAcceptingBlock(rpc, startHash, txid, timeoutMs = 120_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const r = await rpc.getVirtualChainFromBlock({ startHash, includeAcceptedTransactionIds: true });
      for (const a of r.acceptedTransactionIds ?? []) {
        if ((a.acceptedTransactionIds ?? []).some((t) => String(t) === txid)) return String(a.acceptingBlockHash);
      }
    } catch (e) {
      console.log(`  (getVirtualChainFromBlock: ${firstLine(e)}; retrying)`);
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return null;
}

/**
 * The node's copy of a transaction (full fields, payload included) given the chain block that accepted it: the
 * body sits in the including block, which is the accepting block itself or one of its mergeset (blues, then reds).
 * Returns { tx, block } or null.
 */
async function readTxFromBlock(rpc, acceptingBlock, txid) {
  const find = (b) => (b.transactions ?? []).find((t) => String(t.verboseData?.transactionId ?? t.id ?? '').toLowerCase() === txid.toLowerCase()) ?? null;
  const r = await rpc.getBlock({ hash: acceptingBlock, includeTransactions: true });
  const b = r.block ?? r;
  let tx = find(b);
  if (tx) return { tx, block: acceptingBlock };
  const v = b.verboseData ?? {};
  const merged = [...(v.mergeSetBluesHashes ?? []), ...(v.mergeSetRedsHashes ?? [])].map(String);
  for (const h of merged) {
    const rb = await rpc.getBlock({ hash: h, includeTransactions: true });
    tx = find(rb.block ?? rb);
    if (tx) return { tx, block: h };
  }
  return null;
}

/** Mature P2PK UTXOs of an address, largest first; `exclude` outpoints are skipped. */
async function matureUtxos(rpc, dag, address, exclude = []) {
  const { entries } = await rpc.getUtxosByAddresses([address]);
  return entries
    .filter((e) => !e.entry.isCoinbase || dag.virtualDaaScore - e.entry.blockDaaScore >= 100n)
    .filter((e) => !exclude.includes(`${e.outpoint.transactionId}:${e.outpoint.index}`))
    .sort((a, b) => (b.amount > a.amount ? 1 : b.amount < a.amount ? -1 : 0));
}

/** The node's UTXO entry for each input of a tool-built tx (by address of its spk). */
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
    lockTime: 0n, subnetworkId: SUBNET, gas: 0n, payload: txJson.payload ?? '',
  });
  if (genesisGroups.length) tx.populateGenesisCovenants(genesisGroups);
  return tx;
}

/** Fee for a tool-built tx shape at these budgets: max(compute, storage, transient/2) * feeMult. */
function feeFor(txJson, budgets) {
  const masses = spendMasses({ version: 1,
    inputs: txJson.inputs.map((i, k) => ({ signatureScriptLen: i.signatureScript.length / 2, computeBudget: budgets[k] })),
    outputs: txJson.outputs.map((o) => ({ scriptLen: o.scriptPublicKey.length / 2, covenant: !!o.covenant })),
    payloadLen: (txJson.payload ?? '').length / 2 });
  const storage = storageMassGrams(
    txJson.inputs.map((i) => ({ amount: BigInt(i.amount), plurality: utxoPlurality(i.scriptPublicKey.length / 2, !!i.covenantId) })),
    txJson.outputs.map((o) => ({ amount: BigInt(o.value), plurality: utxoPlurality(o.scriptPublicKey.length / 2, !!o.covenant) })));
  const mass = [feeMassGrams(masses), storage].reduce((a, b) => (a > b ? a : b));
  return { fee: minimumRelayFeeSompi(mass) * feeMult, mass, storage, compute: masses.compute };
}

/**
 * Submit a tool-built tx with budget walk-up. `build(fee)` returns the tool JSON for that fee (the tool rebuilds
 * the tx so the fee comes out of the right output). Starts input 0 one under the local engine's count so the node
 * reports its own (an under-budget spend is a free rejection with used=N), the other inputs at their local count + 1.
 * With dryRun, prints the shape, mass and fee and returns without connecting the inputs to the node.
 */
async function submitWalkup(rpc, build, { label, replay = false, genesisGroups = [], dryRun = false }) {
  let r = build(0n);
  const local = r.simulate.ok ? r.simulate.budgets.map(Number) : r.tx.inputs.map(() => 1560);
  let budgets = local.map((b, k) => (k === 0 ? (args.budget ? Number(args.budget) : (args['no-measure'] || replay ? b : b - 1)) : b + 1));
  for (let round = 1; round <= 8; round++) {
    // fee fixed point: the fee changes the output values, which change the storage mass
    let { fee, mass, storage, compute } = feeFor(r.tx, budgets);
    for (let k = 0; k < 6; k++) {
      r = build(fee);
      const again = feeFor(r.tx, budgets);
      if (again.fee <= fee) break;
      ({ fee, mass, storage, compute } = again);
    }
    const line = `${label} budgets [${budgets.join(', ')}] (limits ${budgets.map((b) => allowedScriptUnits(b)).join('/')} units), mass ${mass} g (compute ${compute}, storage ${storage}), fee ${fee} sompi (${feeMult}x)`;
    if (dryRun) {
      console.log(`${line} ... dry-run, not submitted`);
      console.log(`outputs             : ${r.tx.outputs.map((o, i) => `[${i}] ${o.value} sompi${o.covenant ? ' (covenant)' : ''}`).join(', ')}`);
      return { dryRun: true, budgets, fee, r };
    }
    const entries = await fetchEntries(rpc, r.tx);
    const tx = sdkTx(r.tx, budgets, entries, genesisGroups);
    process.stdout.write(`${line} ... `);
    try {
      const res = await rpc.submitTransaction({ transaction: tx, allowOrphan: false });
      console.log(`ACCEPTED  txid ${res.transactionId}`);
      return { txid: res.transactionId, budgets, fee, mass, r, tx };
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
  // 33-byte kaspa_spk hex -> owner scheme + address (version 0 -> p2pk-schnorr scheme 0, version 8 -> p2sh scheme 3)
  const version = parseInt(spk.slice(0, 2), 16);
  const payload = spk.slice(2);
  const script = version === 0 ? `20${payload}ac` : `aa20${payload}87`;
  return { version, payload, ownerScheme: version === 0 ? 0 : 3, address: spkAddr(script) };
}

function cellAddress(owner, ownerScheme, amount, ext = ZERO32) {
  return spkAddr(tool('cell-script', ['--owner', owner, '--owner-scheme', String(ownerScheme), '--amount', String(amount), '--extension-commitment', ext]).scriptPublicKey);
}

/** A plain P2PK spend built with the SDK (genesis, prepare): one input of the key, these outputs, this payload. */
async function submitP2pk(rpc, { label, key, utxo, outputs, payloadHex = '', genesisGroups = [], dryRun = false, note = null }) {
  let budget = Number(args['key-budget'] ?? 10);
  for (let round = 1; round <= 6; round++) {
    const shape = (fee) => {
      const outs = outputs(fee);
      return { ins: [{ sigLen: 66, budget, amount: utxo.amount, scriptLen: key.spk.script.length / 2 }],
        outs: outs.map((o) => ({ scriptLen: o.scriptPublicKey.script.length / 2, covenant: !!o.covenantOut, amount: o.value })), outs2: outs };
    };
    let fee = 0n, mass = 0n, storage = 0n;
    for (let i = 0; i < 6; i++) {
      const s = shape(fee);
      const masses = spendMasses({ version: 1, inputs: s.ins.map((x) => ({ signatureScriptLen: x.sigLen, computeBudget: x.budget })), outputs: s.outs.map((o) => ({ scriptLen: o.scriptLen, covenant: o.covenant })), payloadLen: payloadHex.length / 2 });
      const st = storageMassGrams(s.ins.map((x) => ({ amount: x.amount, plurality: utxoPlurality(x.scriptLen, false) })), s.outs.map((o) => ({ amount: o.amount, plurality: utxoPlurality(o.scriptLen, o.covenant) })));
      const m = [feeMassGrams(masses), st].reduce((a, b) => (a > b ? a : b));
      const f2 = minimumRelayFeeSompi(m) * feeMult;
      mass = m; storage = st;
      if (f2 <= fee) break;
      fee = f2;
    }
    const outs = outputs(fee);
    if (outs.some((o) => o.value <= 0n)) die(`UTXO ${utxo.amount} sompi cannot cover the outputs plus fee ${fee}`, 1);
    const tx = new Transaction({
      version: 1,
      inputs: [{ previousOutpoint: { transactionId: utxo.outpoint.transactionId, index: utxo.outpoint.index }, signatureScript: '', sequence: 0n, sigOpCount: 0, computeBudget: budget,
        utxo: { outpoint: { transactionId: utxo.outpoint.transactionId, index: utxo.outpoint.index }, amount: utxo.amount, scriptPublicKey: { version: key.spk.version, script: key.spk.script }, blockDaaScore: utxo.entry.blockDaaScore, isCoinbase: utxo.entry.isCoinbase } }],
      outputs: outs.map((o) => ({ value: o.value, scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.script } })),
      lockTime: 0n, subnetworkId: SUBNET, gas: 0n, payload: payloadHex,
    });
    if (genesisGroups.length) tx.populateGenesisCovenants(genesisGroups);
    const covenantIds = genesisGroups.map((g) => tx.outputs[g.outputs[0]].covenant.toJSON().covenantId);
    const signed = signTransaction(tx, [key.key], true);
    if (dryRun) { console.log(`dry-run: ${label} txid ${signed.id}, budget ${budget}, mass ${mass} g (storage ${storage}), fee ${fee} sompi (${feeMult}x)${covenantIds.length ? `, covenant id ${covenantIds[0]}` : ''}`); return { dryRun: true, fee, covenantIds }; }
    if (note) note(outs, fee);
    process.stdout.write(`${label} budget ${budget}, mass ${mass} g (storage ${storage}), fee ${fee} sompi (${feeMult}x) ... `);
    try {
      const res = await rpc.submitTransaction({ transaction: signed, allowOrphan: false });
      console.log(`ACCEPTED  txid ${res.transactionId}`);
      return { txid: res.transactionId, budget, fee, mass, outs, covenantIds };
    } catch (e) {
      const msg = firstLine(e);
      const used = usedUnits(msg);
      if (used === null) die(`rejected: ${msg}`, 1);
      console.log(`under budget (used=${used})`);
      const next = Number(coveringComputeBudget(used));
      budget = next > budget ? next : budget + 1;
    }
  }
  die('budget walk-up did not converge', 1);
}

// ---------------------------------------------------------------------------

async function cmdKey() {
  if (existsSync(keyPath)) die(`${keyPath} exists; refusing to overwrite`);
  const kp = Keypair.random();
  writeFileSync(keyPath, JSON.stringify({ privateKey: kp.privateKey, note: 'throwaway key that funds the BRIDGE covenant genesis output' }, null, 2) + '\n');
  chmodSync(keyPath, 0o600);
  console.log(`key file     : ${keyPath} (chmod 600)`);
  console.log(`fund address : ${kp.toAddress(network).toString()}`);
}

function executeLogState(file) {
  const s = readFileSync(resolve(file), 'utf8');
  const h = s.match(/prev_header\s*:\s*(?:0x)?([0-9a-fA-F]{64})/)?.[1];
  const c = s.match(/prev_committee\s*:\s*(?:0x)?([0-9a-fA-F]{64})/)?.[1];
  const cc = s.match(/chain[ _]commit(?:ment)?\s*:\s*(?:0x)?([0-9a-fA-F]{64})/)?.[1];
  if (!h || !c) die(`${file}: no prev_header / prev_committee lines (the stdout of \`eth-prover execute\` in dev mode)`);
  return { header: h.toLowerCase(), committee: c.toLowerCase(), chainCommitment: cc?.toLowerCase() };
}

async function cmdGenesis() {
  if (existsSync(statePath)) die(`${statePath} exists: a covenant is already deployed from this directory (use --state for another instance)`);
  let header = args.header, committee = args.committee, cc = args['chain-commitment'];
  if (args['execute-log']) {
    const x = executeLogState(args['execute-log']);
    header ??= x.header; committee ??= x.committee; cc ??= x.chainCommitment;
  }
  cc ??= MAINNET_CHAIN_COMMITMENT;
  if (!header || !committee) die('--header H --committee H (the finalized beacon header root and its sync committee hash) or --execute-log FILE');
  if (!args['max-mint']) die('--max-mint <units> is required (v5: the vault\'s MAX_DEPOSIT, e.g. 10000 for $10k)');
  // sprint 7: bridge-v7 when --cell-value is given (the floor of every minted cell, KAS; 0.3 is the cell KAS every mint pays
  // today); v7 reads --max-fee as the fee ceiling alone, so it must be given and tight (a copier can take max_fee minus the
  // real fee per advance). Without --cell-value this is a v5/v6 genesis as before.
  const v7 = args['cell-value'] != null;
  const cellValue = v7 ? kaspaToSompi(String(args['cell-value'] === true ? '0.3' : args['cell-value'])) : null;
  if (v7 && cellValue <= 0n) die('--cell-value must be above 0 (KAS; 0.3 is the cell KAS every mint pays)');
  if (v7 && args['max-fee'] == null) die('--max-fee <KAS> is required with --cell-value (v7: the fee ceiling alone; set it to about twice the measured advance fee)');
  if (v7 && tokenKas < cellValue) die(`--token-kas ${tokenKas} sompi is below --cell-value ${cellValue}: every mint would be refused by the covenant`);
  const dripTerms = dripScheduleFromArgs();
  const p = {
    imageId: hex32(args['image-id'] ?? PINNED_IMAGE_ID, 'image-id'), chainCommitment: hex32(cc, 'chain-commitment'),
    vault: hex20(args.vault, 'vault'), ethToken: hex20(args['eth-token'], 'eth-token'), ethTokenImpl: hex20(args['eth-token-impl'], 'eth-token-impl'),
    maxFee: kaspaToSompi(String(args['max-fee'] ?? '2')), maxMint: units(args['max-mint']), extensionCommitment: ZERO32,
    ...(v7 ? { cellValue } : {}),
    header: hex32(header, 'header'), committee: hex32(committee, 'committee'), cursor: 0, token: ZERO32,
  };
  if (!PINNED_IMAGE_IDS[p.imageId]) console.log(`WARNING: image id ${p.imageId} is not a pinned inbound image (${Object.keys(PINNED_IMAGE_IDS).join(', ')})`);
  const amount = kaspaToSompi(String(args.amount ?? '10'));
  // the prep output carries the KCC-23 prep tx's KAS plus the drip's endowment, which init pays out of it
  const prepKas = args['prep-kas'] ? kaspaToSompi(String(args['prep-kas'])) : kaspaToSompi('2') + dripTerms.endowment;
  const s = tool('script', covenantArgs(p));
  if (s.cellTemplate !== CELL_TEMPLATE) die(`tool's cell template ${s.cellTemplate} is not the reference cell ${CELL_TEMPLATE}`, 3);
  if ((s.covenantVersion ?? 5) !== (v7 ? 7 : 5)) die(`the tool ${TOOL} is the v${s.covenantVersion ?? 5} tool; this genesis is v${v7 ? 7 : 5}${v7 ? ` (set BRIDGE_COVENANT_V5_BIN=${V7_TOOL})` : ''}`, 3);
  if (v7 && String(s.cellValue) !== cellValue.toString()) die(`the tool compiled cellValue ${s.cellValue}, asked ${cellValue}`, 3);
  const covAddr = p2shAddr(s.redeem);
  const contractDir = v7 ? 'bridge-v7' : 'bridge-v5';
  console.log(`covenant program    : ${contractDir}/bridge.sil (covenant v${v7 ? 7 : 5})${v7 ? `, cell floor ${cellValue} sompi (${Number(cellValue) / 1e8} KAS) per minted cell` : ''}`);
  console.log(`program (image id)  : ${p.imageId}${PINNED_IMAGE_IDS[p.imageId] ? ` (pinned: ${PINNED_IMAGE_IDS[p.imageId]})` : ''}`);
  console.log(`chain commitment    : ${p.chainCommitment}`);
  console.log(`vault / token / impl: 0x${p.vault} / 0x${p.ethToken} / 0x${p.ethTokenImpl}`);
  console.log(`initial header      : ${p.header}`);
  console.log(`initial committee   : ${p.committee}`);
  console.log(`cursor / token      : 0 / (none yet)`);
  console.log(`max fee per spend   : ${p.maxFee} sompi${v7 ? ' (v7: the fee ceiling alone; the cells\' KAS is allowed on top, cell floor each)' : ''}`);
  console.log(`max mint per deposit: ${p.maxMint} units (${Number(p.maxMint) / 1e6})`);
  console.log(`miner drip (init)   : ${Number(dripTerms.endowment) / 1e8} KAS endowed, first prize ${Number(dripTerms.firstPrize) / 1e8} KAS, a claim every ${dripTerms.claimEveryHours.toFixed(1)} h (period ${dripTerms.period} DAA, divisor ${dripTerms.divisor}, floor ${Number(dripTerms.minPrize) / 1e8} KAS)`);
  console.log(`family templates    : cell ${s.cellTemplate} (prefix ${s.cellPrefixLen} B, suffix ${s.cellSuffixLen} B), authority ${s.authorityTemplate}`);
  console.log(`redeem script       : ${s.redeemLen} bytes, state at [${s.stateSpan}]`);
  console.log(`covenant address    : ${covAddr}`);
  console.log(`pool / prep fund    : ${amount} sompi into the covenant, ${prepKas} sompi carved out for the KCC-23 preparation tx`);
  const k = loadKey();
  const covSpk = payToScriptHashScript(s.redeem);
  const { rpc, dag } = await connect();
  try {
    const u = (await matureUtxos(rpc, dag, k.addr))[0];
    if (!u || u.amount < amount + prepKas + 20_000_000n) die(`fund ${k.addr} with >= ${(Number(amount + prepKas) / 1e8 + 0.2).toFixed(2)} KAS in one UTXO and rerun`, 1);
    console.log(`funding UTXO        : ${u.outpoint.transactionId}:${u.outpoint.index} (${u.amount} sompi)`);
    const start = dag.sink;
    const res = await submitP2pk(rpc, {
      label: '[genesis]', key: k, utxo: u, dryRun: !!args['dry-run'], genesisGroups: [{ authorizingInput: 0, outputs: [0] }],
      outputs: (fee) => [
        { value: amount, scriptPublicKey: covSpk, covenantOut: true },
        { value: prepKas, scriptPublicKey: k.spk },
        { value: u.amount - amount - prepKas - fee, scriptPublicKey: k.spk },
      ],
    });
    if (res.dryRun) return;
    const covenantId = res.covenantIds[0];
    console.log(`covenant id         : ${covenantId}`);
    const st = {
      v: 5, covenant: v7 ? 7 : 5, network, contract: `${contractDir}/bridge.sil`, cell: `${contractDir}/KCC20.sil`, authority: `${contractDir}/BridgeMint.sil`, drip: `${contractDir}/MinerDrip.sil`, silverscript: SILVERSCRIPT,
      family: { cellTemplate: s.cellTemplate, cellPrefixLen: s.cellPrefixLen, cellSuffixLen: s.cellSuffixLen, authorityTemplate: s.authorityTemplate, burnOwner: BURN_OWNER },
      params: { imageId: p.imageId, chainCommitment: p.chainCommitment, vault: p.vault, ethToken: p.ethToken, ethTokenImpl: p.ethTokenImpl, maxFee: p.maxFee.toString(), maxMint: p.maxMint.toString(), ...(v7 ? { cellValue: cellValue.toString() } : {}), extensionCommitment: ZERO32 },
      dripTerms: { period: dripTerms.period.toString(), divisor: dripTerms.divisor.toString(), minPrize: dripTerms.minPrize.toString(), endowment: dripTerms.endowment.toString(), firstPrize: dripTerms.firstPrize.toString(), claimEveryHours: +dripTerms.claimEveryHours.toFixed(2), halvingDays: Number(args['drip-halving-days'] ?? 7) },
      covenantId, genesisTxid: res.txid, genesisStart: start, tokenId: null,
      state: { header: p.header, committee: p.committee, cursor: 0, token: ZERO32 },
      utxo: { txid: res.txid, index: 0, amount: amount.toString() }, address: covAddr,
      key: { address: k.addr, xonly: k.xonly },
      prepFund: { txid: res.txid, index: 1, amount: prepKas.toString() }, prep: null, authorityUtxo: null, cells: [], burns: [],
      history: [{ kind: 'genesis', txid: res.txid, header: p.header, committee: p.committee, budget: res.budget, fee: res.fee.toString(), mass: res.mass.toString(), at: now() }],
    };
    saveState(st);
    const seen = await waitForUtxo(rpc, covAddr, res.txid);
    const cid = seen?.entry?.covenantId?.toString();
    console.log(seen ? `covenant UTXO live  : ${covAddr} (node reports covenant id ${cid ?? 'n/a'})` : 'not visible in the UTXO index after 90 s; check before prepare');
    if (cid && cid !== covenantId) die(`node reports covenant id ${cid}, expected ${covenantId}`, 3);
    const block = await findAcceptingBlock(rpc, start, res.txid);
    st.genesisBlock = block;
    saveState(st);
    console.log(`accepting block     : ${block ?? 'not found from the pre-submission sink (record it by hand for verify-token)'}`);
    console.log(`next                : node bin/bridge.mjs prepare --name ... --ticker ... --image-url ... --image-file ... --url ${args.url}`);
  } finally {
    await rpc.disconnect();
  }
}

async function cmdPrepare() {
  const st = loadState();
  if (st.prep) die(`the preparation tx is already made: ${st.prep.txid} (payload ${st.prep.payloadHex.length / 2} bytes)`);
  if (!st.prepFund) die('no prep fund output recorded by genesis');
  const name = args.name, ticker = args.ticker, symbol = args.symbol ?? args.ticker;
  if (!name || !ticker) die('--name and --ticker are required (e.g. --name Wobbly --ticker Wobbly.k)');
  const decimals = Number(args.decimals ?? 6);
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) die('--decimals must be an integer 0..255');
  // U5's stealth rule for the rehearsal tokens: no Dollar, USDC or stable in a name before the reveal. USDC.k #1 names USDC
  // on purpose (11-15: "Kozmic Bridged USDC", kzUSDC), so --allow-usdc-name says so explicitly; without it the rule stands.
  const forbidden = /dollar|usdc|stable/i;
  if (!args['allow-usdc-name']) for (const [k, v] of Object.entries({ name, ticker, symbol })) if (forbidden.test(v)) die(`${k} "${v}" contains a word that must not appear before the reveal (U5 rule: no Dollar, USDC or stable; --allow-usdc-name for the real bridge)`);
  const meta = { name, ticker, symbol, decimals };
  // sprint 7 (11-15): the instance number is its own field, never part of the name; a later Kozmic bridge is a separate token with its own id
  if (args['instance-number'] != null) {
    const n = Number(args['instance-number']);
    if (!Number.isInteger(n) || n < 1) die('--instance-number must be a positive integer');
    meta.instance_number = n;
  }
  if (args['image-url']) {
    if (!args['image-file']) die('--image-url needs --image-file (the exact bytes the URL will serve; image_hash is their sha256)');
    const bytes = readFileSync(resolve(args['image-file']));
    meta.image = args['image-url'];
    meta.image_hash = createHash('sha256').update(bytes).digest('hex');
    console.log(`image               : ${meta.image} (${bytes.length} bytes, sha256 ${meta.image_hash}; the URL must serve exactly these bytes, forever)`);
  }
  // U5: the instance's provenance keys (KCC-23 defines no key set; KCC-0021's name/ticker/symbol/decimals/image/image_hash are
  // conventions, extra keys are not forbidden). Readers that know the bridge can check both against the chains.
  meta.eth_vault = `0x${st.params.vault}`;
  meta.bridge_covenant_id = st.covenantId;
  // U7 findability (handoff section 7): the minter's template hash, and the BridgeMint artifact served at its own URL
  if (!args['no-findability']) {
    const mt = args['minter-template'] ?? tool('script', covenantArgs(paramsOf(st))).authorityTemplate;
    meta.minter_template = hex32(mt, 'minter-template');
    if (!args['artifact-url'] || !args['artifact-file']) die('--artifact-url URL --artifact-file FILE (the BridgeMint artifact the URL serves, byte for byte); or --no-findability');
    const art = readFileSync(resolve(args['artifact-file']));
    meta.artifact = args['artifact-url'];
    meta.artifact_hash = createHash('sha256').update(art).digest('hex');
    console.log(`minter template     : ${meta.minter_template} (BridgeMint)`);
    console.log(`artifact            : ${meta.artifact} (${art.length} bytes, sha256 ${meta.artifact_hash}; the URL must serve exactly these bytes, forever)`);
  }
  const json = JSON.stringify(meta); // serialized exactly once; the hex below is what the chain commits to
  const payloadHex = '00' + Buffer.from(json, 'utf8').toString('hex');
  console.log(`metadata JSON       : ${json}`);
  console.log(`payload             : ${payloadHex.length / 2} bytes = 00 || JSON; sha256(payload) ${createHash('sha256').update(Buffer.from(payloadHex, 'hex')).digest('hex')}`);
  const k = loadKey();
  const { rpc, dag } = await connect();
  try {
    const { entries } = await rpc.getUtxosByAddresses([k.addr]);
    const u = entries.find((e) => e.outpoint.transactionId === st.prepFund.txid && e.outpoint.index === st.prepFund.index);
    if (!u) die(`prep fund UTXO ${st.prepFund.txid}:${st.prepFund.index} not found at ${k.addr}`, 1);
    const start = dag.sink;
    // KCC-23 shape: version 1, exactly one output (p2pk back to the key, the whole input minus the fee), payload 00 || JSON.
    // One output so no other output of this transaction can claim the declaration.
    const res = await submitP2pk(rpc, {
      label: '[prepare]', key: k, utxo: u, payloadHex, dryRun: !!args['dry-run'],
      outputs: (fee) => [{ value: u.amount - fee, scriptPublicKey: k.spk }],
    });
    if (res.dryRun) return;
    st.prep = { txid: res.txid, index: 0, amount: res.outs[0].value.toString(), payloadHex, metadata: meta, start, acceptingBlock: null, readBack: null, spent: null };
    st.history.push({ kind: 'prepare', txid: res.txid, payloadBytes: payloadHex.length / 2, budget: res.budget, fee: res.fee.toString(), mass: res.mass.toString(), at: now() });
    saveState(st);
    const seen = await waitForUtxo(rpc, k.addr, res.txid, 0);
    console.log(seen ? `prep output live    : ${res.txid}:0 (${seen.amount} sompi)` : 'prep output not visible after 90 s');
    const block = await findAcceptingBlock(rpc, start, res.txid);
    st.prep.acceptingBlock = block;
    if (block) {
      const found = await readTxFromBlock(rpc, block, res.txid);
      const tx = found?.tx;
      const got = String(tx?.payload ?? '').replace(/^0x/, '').toLowerCase();
      st.prep.readBack = tx ? got === payloadHex : null;
      st.prep.includingBlock = found?.block ?? null;
      console.log(`accepting block     : ${block}${found ? ` (included in ${found.block})` : ''}`);
      console.log(`payload read back   : ${tx ? `${got.length / 2} bytes, ${got === payloadHex ? 'EQUAL byte for byte to what was signed' : 'DIFFERS from what was signed'}` : 'tx not found in the accepting block or its mergeset (bridge.mjs readback retries)'}`);
      if (tx) console.log(`tx version / outputs: ${tx.version} / ${tx.outputs?.length}`);
    } else {
      console.log('accepting block     : not found from the pre-submission sink; the read-back check is pending (verify-token takes --prep-block)');
    }
    saveState(st);
    console.log(`next                : node bin/bridge.mjs init --url ${args.url}`);
  } finally {
    await rpc.disconnect();
  }
}

async function cmdInit() {
  const st = loadState();
  if (st.tokenId) die(`token already initialized: ${st.tokenId}`);
  if (!st.prep) die('no preparation tx yet: run prepare first (KCC-23: the family genesis spends the metadata output)');
  if (st.prep.spent) die(`the prep output ${st.prep.txid}:0 is already spent (${st.prep.spent})`);
  const k = loadKey();
  const p = paramsOf(st);
  const amount = BigInt(st.utxo.amount);
  const authKas = kaspaToSompi(String(args['auth-kas'] ?? '1'));
  if (cellFloorOf(st) != null && authKas < cellFloorOf(st)) die(`--auth-kas ${authKas} sompi is below the covenant's cell floor ${cellFloorOf(st)}`);
  if (!st.dripTerms) die('no drip terms in the state file (a v5 genesis records them)');
  const build = (fee) => tool('init', [...covenantArgs(p), '--covenant-id', st.covenantId, '--utxo', `${st.utxo.txid}:${st.utxo.index}`, '--value', amount.toString(),
    '--fee', fee.toString(), '--token-out', authKas.toString(), '--prep-utxo', `${st.prep.txid}:${st.prep.index}`, '--prep-value', st.prep.amount, '--prep-key', k.hex, ...dripArgs(st)]);
  const r0 = build(0n);
  if (p2shAddr(r0.redeem) !== st.address) die(`redeem for the recorded state hashes to ${p2shAddr(r0.redeem)}, state file says ${st.address}`, 3);
  if (!r0.kcc23) die('the tool did not build the KCC-23 shape', 3);
  if (!r0.drip || r0.tx.outputs.length !== 3 || r0.tx.outputs[2].covenant) die('the tool did not build the v5 shape (three outputs, the drip unbound at 2)', 3);
  drip.checkRedeem(r0.drip.redeem, r0.tokenId); // the Studio's check: the MinerDrip program, the token id stamped in
  const dripAddr = spkAddr(r0.drip.scriptPublicKey);
  console.log(`miner drip          : ${dripAddr} (${r0.drip.redeemLen} B redeem, ${r0.drip.endowment} sompi at output 2, stamped with the token id)`);
  const authAddr = p2shAddr(r0.authorityRedeem);
  console.log(`covenant            : ${st.covenantId}`);
  console.log(`token id (expected) : ${r0.tokenId}  (KIP-20: prep outpoint ${st.prep.txid}:0 + output 1)`);
  console.log(`authority           : ${authAddr} (BridgeMint, ${r0.authorityRedeem.length / 2} B redeem, ${authKas} sompi)`);
  console.log(`successor           : ${p2shAddr(r0.successorRedeem)}`);
  console.log(`local engine        : ${r0.simulate.ok ? `accepts, ${r0.simulate.scriptUnits.join(' + ')} script units` : `rejects input ${r0.simulate.input} (${r0.simulate.error})`}`);
  if (!r0.simulate.ok) die('the local engine rejects init; not submitting', 1);
  // a third derivation of the family id, from the tool's tx bytes (src/covenant-id.js), beside the tool's and the SDK's
  const o1 = r0.tx.outputs[1];
  const jsId = kip20CovenantId({ txid: st.prep.txid, index: st.prep.index }, [{ index: 1, value: o1.value, version: o1.scriptVersion, script: o1.scriptPublicKey }]);
  if (jsId !== r0.tokenId) die(`src/covenant-id.js derives ${jsId}, the tool ${r0.tokenId}`, 3);
  const { rpc, dag } = await connect();
  try {
    const start = dag.sink;
    const res = await submitWalkup(rpc, build, { label: '[init]', genesisGroups: [{ authorizingInput: 1, outputs: [1] }], dryRun: !!args['dry-run'] });
    if (res.dryRun) return;
    if (res.rejected) { st.history.push({ kind: 'init-rejected', error: res.rejected, at: now() }); saveState(st); process.exit(1); }
    const sdkTokenId = res.tx.outputs[1].covenant.toJSON().covenantId;
    if (sdkTokenId !== res.r.tokenId) die(`SDK derived token id ${sdkTokenId}, the tool ${res.r.tokenId}`, 3);
    st.tokenId = res.r.tokenId;
    st.state = res.r.nextState;
    st.utxo = { txid: res.txid, index: 0, amount: res.r.tx.outputs[0].value };
    st.address = p2shAddr(res.r.successorRedeem);
    st.authorityUtxo = { txid: res.txid, index: 1, amount: res.r.tx.outputs[1].value, address: authAddr };
    st.prep.spent = res.txid;
    st.initTxid = res.txid;
    st.drip = { address: dripAddr, redeem: r0.drip.redeem, scriptPublicKey: r0.drip.scriptPublicKey, terms: st.dripTerms, utxo: { txid: res.txid, index: 2, amount: r0.drip.endowment }, genesisTxid: res.txid, revealTxid: null, claims: [] };
    st.initStart = start;
    st.history.push({ kind: 'init', txid: res.txid, tokenId: st.tokenId, budgets: res.budgets, fee: res.fee.toString(), mass: res.mass.toString(), localScriptUnits: res.r.simulate.scriptUnits, at: now() });
    saveState(st);
    const seen = await waitForUtxo(rpc, authAddr, res.txid, 1);
    const cid = seen?.entry?.covenantId?.toString();
    console.log(seen ? `authority live      : ${authAddr} (node reports covenant id ${cid ?? 'n/a'})` : 'authority not visible after 90 s; check before advancing');
    if (cid && cid !== st.tokenId) die(`node reports family id ${cid}, expected ${st.tokenId}`, 3);
    console.log(`token (family) id   : ${st.tokenId}   tool == SDK == covenant-id.js${cid ? ' == node' : ''}`);
    const block = await findAcceptingBlock(rpc, start, res.txid);
    st.initBlock = block;
    saveState(st);
    console.log(`accepting block     : ${block ?? 'not found from the pre-submission sink (record it by hand for verify-token)'}`);
    console.log(`successor           : ${st.address} (${st.utxo.amount} sompi)`);
    console.log(`drip                : ${st.drip.address} funded with ${st.drip.utxo.amount} sompi at ${res.txid}:2`);
    console.log(`next                : node bin/bridge-v5.mjs drip-reveal --url ${args.url} --state ${statePath}   (puts the drip script on chain, pays the first miner)`);
    console.log(`then                : RelayFactoryV2.create with tokenCovId ${st.tokenId} (usdc/script/u7.sh create ...)`);
  } finally {
    await rpc.disconnect();
  }
}

async function cmdAdvance({ replay }) {
  if (!args.bundle) die('--bundle <dir>');
  const st = loadState();
  const p = paramsOf(st);
  const amount = BigInt(st.utxo.amount);
  if (cellFloorOf(st) != null && tokenKas < cellFloorOf(st)) die(`--token-kas ${tokenKas} sompi is below the covenant's cell floor ${cellFloorOf(st)}; the covenant would refuse the mint`);
  const base = [...covenantArgs(p), '--covenant-id', st.covenantId, '--utxo', `${st.utxo.txid}:${st.utxo.index}`, '--value', amount.toString(), '--bundle', args.bundle, '--token-out', tokenKas.toString()];
  const withAuth = st.authorityUtxo ? ['--authority-utxo', `${st.authorityUtxo.txid}:${st.authorityUtxo.index}`, '--authority-value', String(st.authorityUtxo.amount)] : [];
  const build = (fee) => tool('advance', [...base, ...withAuth, '--fee', fee.toString()]);
  const a = build(0n);
  if (p2shAddr(a.redeem) !== st.address) die(`redeem for the recorded state hashes to ${p2shAddr(a.redeem)}, state file says ${st.address}`, 3);
  console.log(`covenant            : ${st.covenantId}   token ${st.tokenId ?? '(none)'}`);
  console.log(`state               : header ${st.state.header}  cursor ${st.state.cursor}`);
  console.log(`journal prev_header : ${a.journal.prevHeader}${a.journalMatchesState ? '  (matches)' : '  (DOES NOT MATCH)'}`);
  console.log(`journal new_header  : ${a.journal.newHeader}  slot ${a.journal.newSlot}  exec block ${a.journal.execBlockNumber}`);
  console.log(`journal token/impl  : 0x${a.journal.token} / 0x${a.journal.implementation}`);
  console.log(`journal deposits    : ${a.journal.deposits.map((d) => `#${d.nonce} ${d.amount} -> ${recipientInfo(d.kaspaSpk).address} [${d.status}]`).join('; ') || 'none'}`);
  console.log(`mints this advance  : ${a.mints.length ? a.mints.map((d) => `#${d.nonce} ${d.amount}`).join(', ') : 'none (heartbeat shape)'}   tx: ${a.tx.inputs.length} inputs, ${a.tx.outputs.length} outputs`);
  console.log(`local engine        : ${a.simulate.ok ? `accepts, ${a.simulate.scriptUnits.join(' + ')} script units` : `rejects input ${a.simulate.input} (${a.simulate.error})`}`);
  if (replay) {
    if (a.simulate.ok) die('replay: the local engine ACCEPTS this spend, so it is not a replay of a used proof; refusing to submit', 3);
  } else if (!a.simulate.ok || !a.journalMatchesState) {
    die('the local engine rejects this transition; not submitting (use replay to submit a rejected spend on purpose)', 1);
  }
  const { rpc } = await connect();
  try {
    const label = replay ? '[replay]' : '[advance]';
    const res = await submitWalkup(rpc, build, { label, replay, dryRun: !!args['dry-run'] });
    if (res.dryRun) return;
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
      st.authorityUtxo = { txid: res.txid, index: 1, amount: r.tx.outputs[1].value, address: st.authorityUtxo.address };
      r.mints.forEach((d, k) => {
        const rec = recipientInfo(d.kaspaSpk);
        const c = { txid: res.txid, index: 2 + k, value: r.tx.outputs[2 + k].value, nonce: d.nonce, amount: String(d.amount), owner: rec.payload, ownerScheme: rec.ownerScheme, ownerAddress: rec.address, address: spkAddr(r.tx.outputs[2 + k].scriptPublicKey) };
        minted.push(c);
        st.cells.push(c);
      });
    }
    st.history.push({ kind: 'advance', txid: res.txid, bundle: args.bundle, budgets: res.budgets, fee: res.fee.toString(), mass: res.mass.toString(),
      prevHeader: r.journal.prevHeader, newHeader: r.journal.newHeader, newCommittee: r.journal.newCommittee, newSlot: r.journal.newSlot,
      deposits: r.journal.deposits.map((d) => ({ nonce: d.nonce, amount: d.amount, status: d.status })),
      mints: r.mints.map((d) => d.nonce), cursor: r.nextState.cursor, localScriptUnits: r.simulate.scriptUnits, at: now() });
    saveState(st);
    const seen = await waitForUtxo(rpc, st.address, res.txid);
    console.log(seen ? `successor live      : ${st.address} (cursor ${st.state.cursor})` : 'successor not visible after 90 s; check before the next advance');
    for (const c of minted) console.log(`minted              : #${c.nonce} ${Number(c.amount) / 1e6} units -> ${c.ownerAddress}   cell ${c.txid}:${c.index} at ${c.address} (${c.value} sompi)`);
  } finally {
    await rpc.disconnect();
  }
}

/** transfer (to a Kaspa address) or burn (to the unspendable owner with the KZB1 payload), from a key's cell. */
async function cmdMove({ burn }) {
  const st = loadState();
  if (!st.tokenId) die('no token yet');
  if (!args['from-key'] || !args.amount) die(`--from-key <file with privateKey> --amount <units, 6 decimals>${burn ? ' --target 0x<relay> --recipient 0x<eth address> [--tip N]' : ' --to kaspa:...'}`);
  const k = loadKey(resolve(args['from-key']));
  const held = args.utxo
    ? st.cells.find((c) => `${c.txid}:${c.index}` === args.utxo)
    : st.cells.filter((c) => c.owner === k.xonly && c.ownerScheme === 0 && !c.spent).sort((a, b) => Number(b.amount) - Number(a.amount))[0];
  if (!held) die(`no unspent p2pk cell owned by ${k.addr} in the state file (use --utxo TXID:IDX)`, 1);
  if (held.spent) die(`cell ${held.txid}:${held.index} is spent (${held.spent})`);
  if (held.owner !== k.xonly || held.ownerScheme !== 0) die(`cell ${held.txid}:${held.index} is not a p2pk cell of ${k.addr}`);
  const amount = units(args.amount);
  const heldUnits = BigInt(held.amount);
  if (amount > heldUnits) die(`amount ${amount} exceeds the cell's ${heldUnits}`);
  const rem = heldUnits - amount;
  const cellKas = kaspaToSompi(String(args['cell-kas'] ?? '1'));
  let to, payload = '', target, recipient, tipUnits = 0n, beacon = null;
  if (burn) {
    target = hex20(args.target, 'target');
    recipient = hex20(args.recipient, 'recipient');
    tipUnits = args.tip === undefined || args.tip === true ? 0n : units(args.tip, true); // --tip 0 (or a bare --tip) is a legal, free exit
    if (tipUnits > amount) die('tip exceeds the burned amount (the guest refuses it)');
    if (args.beacon) {
      // S3b, guest v3: KZB1 | 03 | target(20) | tip(8 BE) | recipient(20) | eth block(8 BE) | eth hash(32), the beacon
      // from --beacon NET, the eth-net.json network the relay lives on (V4-DESIGN 2.2). Guest v3 needs tip < amount.
      if (args.beacon === true) die('--beacon needs the network the relay lives on: --beacon sepolia | mainnet');
      if (tipUnits >= amount) die('tip must be below the burned amount (guest v3 refuses tip == amount)');
      const { ethBeacon, burnPayload } = await import('../src/beacon.js');
      beacon = await ethBeacon(ROOT, String(args.beacon), Number(args['beacon-depth'] ?? 3));
      payload = burnPayload({ target, tipUnits, recipient, beacon });
      if (payload.length !== 186) die('payload is not 93 bytes');
    } else {
      // KZB1 | 02 | target(20) | tip(8 BE, base units) | recipient(20): the payload the relay guest v2 reads
      payload = '4b5a4231' + '02' + target + tipUnits.toString(16).padStart(16, '0') + recipient;
      if (payload.length !== 106) die('payload is not 53 bytes');
    }
    to = { owner: BURN_OWNER, scheme: 3, address: cellAddress(BURN_OWNER, 3, amount) };
  } else {
    if (!args.to) die('--to kaspa:...');
    const toSpk = payToAddressScript(new Address(args.to)).script;
    to = /^20[0-9a-f]{64}ac$/i.test(toSpk) ? { owner: toSpk.slice(2, 66).toLowerCase(), scheme: 0 }
      : /^aa20[0-9a-f]{64}87$/i.test(toSpk) ? { owner: toSpk.slice(4, 68).toLowerCase(), scheme: 3 }
      : die('--to must be a P2PK (Schnorr) or P2SH address');
    to.address = args.to;
  }
  // KAS: a burn cell parks the mass-optimal value at the fee rate in use (cost.js: v + 4C/v * rate is smallest at
  // v = sqrt(4C * rate), 0.2 KAS at the minimum relay rate; --burn-kas overrides); a recipient cell and the change
  // cell carry --cell-kas each. The fee and whatever the cell's own KAS does not cover come from a funding input of
  // the key (its largest mature P2PK UTXO, or --fund-utxo); the remainder returns to the key as KAS change.
  const rate = (MINIMUM_RELAY_FEE_SOMPI_PER_KG / 1000n) * feeMult;
  const firstKas = burn ? (args['burn-kas'] ? kaspaToSompi(String(args['burn-kas'])) : optimalParkSompi(rate)) : cellKas;
  const { rpc, dag } = await connect();
  try {
    let fund = null;
    if (!args['no-fund']) {
      const utxos = await matureUtxos(rpc, dag, k.addr);
      const f = args['fund-utxo'] ? utxos.find((e) => `${e.outpoint.transactionId}:${e.outpoint.index}` === args['fund-utxo']) : utxos[0];
      if (!f) die(`no mature P2PK UTXO of ${k.addr} to fund the transfer (fund the key, or --no-fund to pay from the cell's KAS)`, 1);
      fund = { utxo: `${f.outpoint.transactionId}:${f.outpoint.index}`, value: BigInt(f.amount) };
    }
    const build = (fee) => {
      const a = ['--token-id', st.tokenId, '--utxo', `${held.txid}:${held.index}`, '--value', String(held.value), '--owner', k.xonly, '--amount', heldUnits.toString(), '--key', k.hex,
        '--to', to.owner, '--to-scheme', String(to.scheme), '--to-amount', amount.toString(), '--token-out', firstKas.toString(), '--fee', fee.toString(), '--change-spk', k.spk.script];
      if (rem > 0n) a.push('--to2', k.xonly, '--to2-scheme', '0', '--to2-amount', rem.toString(), '--to2-kas', cellKas.toString());
      if (payload) a.push('--payload', payload);
      if (fund) a.push('--fund-utxo', fund.utxo, '--fund-value', fund.value.toString());
      return tool('transfer', a);
    };
    const r0 = build(0n);
    console.log(`token               : ${st.tokenId}`);
    console.log(`spending            : ${held.txid}:${held.index} (${Number(heldUnits) / 1e6} units, ${held.value} sompi) owned by ${k.addr}`);
    console.log(burn
      ? `burn                : ${Number(amount) / 1e6} units to ${BURN_OWNER} (scheme 3); target 0x${target}, recipient 0x${recipient}, tip ${Number(tipUnits) / 1e6} units`
      : `to                  : ${to.address} ${Number(amount) / 1e6} units`);
    if (rem > 0n) console.log(`change cell         : ${Number(rem) / 1e6} units back to ${k.addr}, ${cellKas} sompi`);
    console.log(`${burn ? 'burn cell KAS' : 'recipient cell KAS'}  ${burn ? '     ' : ''}: ${firstKas} sompi${burn ? ` parked forever (${args['burn-kas'] ? '--burn-kas' : `mass-optimal at ${rate} sompi/g`})` : ''}`);
    console.log(`funding input       : ${fund ? `${fund.utxo} (${fund.value} sompi); KAS change back to ${k.addr}` : 'none (the cell pays)'}`);
    if (payload) console.log(`payload             : ${payload}`);
    if (beacon) console.log(`beacon              : ${beacon.net} block ${beacon.number} (head ${beacon.head}) 0x${beacon.hash}, time ${new Date(Number(beacon.timestamp) * 1000).toISOString()}`);
    console.log(`local engine        : ${r0.simulate.ok ? `accepts, ${r0.simulate.scriptUnits.join(' + ')} script units` : `rejects input ${r0.simulate.input} (${r0.simulate.error})`}`);
    if (!r0.simulate.ok) die('the local engine rejects this transfer; not submitting', 1);
    if (payload && r0.tx.payload !== payload) die(`the tool built payload ${r0.tx.payload}, expected ${payload}`, 3);
    const start = dag.sink;
    const res = await submitWalkup(rpc, build, { label: burn ? '[burn]' : '[transfer]', dryRun: !!args['dry-run'] });
    if (res.dryRun) return;
    if (res.rejected) { st.history.push({ kind: `${burn ? 'burn' : 'transfer'}-rejected`, error: res.rejected, at: now() }); saveState(st); process.exit(1); }
    held.spent = res.txid;
    const r = res.r;
    const outs = r.tx.outputs.map((o, idx) => ({ index: idx, value: o.value, address: spkAddr(o.scriptPublicKey), covenant: !!o.covenant }));
    const first = { txid: res.txid, index: 0, value: outs[0].value, nonce: null, amount: amount.toString(), owner: to.owner, ownerScheme: to.scheme, ownerAddress: to.address, address: outs[0].address, burn: burn || undefined };
    st.cells.push(first);
    if (rem > 0n) st.cells.push({ txid: res.txid, index: 1, value: outs[1].value, nonce: null, amount: rem.toString(), owner: k.xonly, ownerScheme: 0, ownerAddress: k.addr, address: outs[1].address });
    const rec = { kind: burn ? 'burn' : 'transfer', txid: res.txid, from: k.addr, to: to.address, amount: amount.toString(), budgets: res.budgets, fee: res.fee.toString(), mass: res.mass.toString(), fund: fund?.utxo ?? null, localScriptUnits: r.simulate.scriptUnits, at: now() };
    if (burn) {
      const b = { txid: res.txid, start, burnIndex: 0, burnUnits: amount.toString(), tip: tipUnits.toString(), target: `0x${target}`, recipient: `0x${recipient}`, payload, parkedSompi: outs[0].value, outputs: outs, beacon: beacon ? { net: beacon.net, number: beacon.number.toString(), hash: beacon.hash, timestamp: beacon.timestamp.toString() } : undefined, at: now() };
      st.burns.push(b);
      Object.assign(rec, { start, target: b.target, recipient: b.recipient, tip: b.tip, parkedSompi: outs[0].value });
    }
    st.history.push(rec);
    saveState(st);
    const seen = await waitForUtxo(rpc, outs[0].address, res.txid, 0);
    console.log(seen ? `${burn ? 'burn cell' : 'recipient cell'}       : ${res.txid}:0 live (covenant id ${seen.entry?.covenantId?.toString() ?? 'n/a'}, ${outs[0].value} sompi${burn ? ' parked forever' : ''})` : 'output 0 not visible after 90 s');
    if (rem > 0n) console.log(`change cell         : ${res.txid}:1 (${Number(rem) / 1e6} units, ${outs[1].value} sompi)`);
    const kasChange = outs.find((o, i) => !o.covenant && i >= (rem > 0n ? 2 : 1));
    if (kasChange) console.log(`KAS change          : ${res.txid}:${kasChange.index} (${kasChange.value} sompi)`);
    if (burn) {
      console.log(`START (sink before) : ${start}`);
      console.log(`\nnext (when T has 100 attesters, ~10 min): burnwitness --url ${args.url} --txid ${res.txid} --start ${start} --token ${st.tokenId} --k <relay checkpoint> --levels 30 --min-attest 100 --min-count 100 --out witness-u5-<n>.json`);
    }
  } finally {
    await rpc.disconnect();
  }
}

/** Re-read the prep and init transactions from the node (accepting block + mergeset) and record the including blocks. */
async function cmdReadback() {
  const st = loadState();
  const { rpc } = await connect();
  try {
    if (st.prep?.acceptingBlock) {
      const found = await readTxFromBlock(rpc, st.prep.acceptingBlock, st.prep.txid);
      const got = String(found?.tx?.payload ?? '').replace(/^0x/, '').toLowerCase();
      st.prep.readBack = found ? got === st.prep.payloadHex : null;
      st.prep.includingBlock = found?.block ?? null;
      console.log(`prep ${st.prep.txid}: ${found ? `included in ${found.block}; version ${found.tx.version}, ${found.tx.outputs?.length} output(s); payload ${got.length / 2} bytes ${st.prep.readBack ? 'EQUAL byte for byte to what was signed' : 'DIFFERS from what was signed'}` : 'not found in the accepting block or its mergeset'}`);
    } else console.log('no prep accepting block recorded');
    if (st.initBlock && st.initTxid) {
      const found = await readTxFromBlock(rpc, st.initBlock, st.initTxid);
      st.initIncludingBlock = found?.block ?? null;
      const o1 = found?.tx?.outputs?.[1];
      console.log(`init ${st.initTxid}: ${found ? `included in ${found.block}; version ${found.tx.version}, ${found.tx.inputs?.length} inputs, ${found.tx.outputs?.length} outputs; output 1 covenant ${JSON.stringify(o1?.covenant ?? o1?.verboseData?.covenant ?? null)}` : 'not found in the accepting block or its mergeset'}`);
    } else console.log('no init accepting block recorded');
    saveState(st);
  } finally {
    await rpc.disconnect();
  }
}

/** The drip's terms from --drip-endow KAS, --drip-prize KAS, --drip-halving-days D (minerdrip.js schedule; Tipsy.k: 1, 0.05, 7). */
function dripScheduleFromArgs() {
  const endow = kaspaToSompi(String(args['drip-endow'] ?? '1'));
  const prize = kaspaToSompi(String(args['drip-prize'] ?? '0.05'));
  const days = Number(args['drip-halving-days'] ?? 7);
  try { return drip.schedule(endow, prize, days); } catch (e) { die(`drip terms: ${e.message}`); }
}
function dripArgs(st) {
  const t = st.dripTerms ?? st.drip?.terms;
  return ['--drip-period', String(t.period), '--drip-divisor', String(t.divisor), '--drip-min-prize', String(t.minPrize), '--drip-endowment', String(t.endowment)];
}

/** drip-reveal (once, right after init) and drip-claim (any time the coin is old enough): the one-input one-output spend
 *  the tool builds and simulates; nobody signs; the budget walks up on the node's used=N. */
async function cmdDrip(entry) {
  const st = loadState();
  if (!st.drip?.utxo) die('no drip in the state file (init first)');
  if (entry === 'reveal' && st.drip.revealTxid) die(`already revealed: ${st.drip.revealTxid}`);
  const { rpc, dag } = await connect();
  try {
    const { entries } = await rpc.getUtxosByAddresses([st.drip.address]);
    const u = entries.find((e) => e.outpoint.transactionId === st.drip.utxo.txid && e.outpoint.index === st.drip.utxo.index)
      ?? entries.sort((a, b) => (b.amount > a.amount ? 1 : b.amount < a.amount ? -1 : 0))[0];
    if (!u) die(`no UTXO at the drip address ${st.drip.address} (not in the UTXO index yet? retry in a few seconds)`, 1);
    const value = BigInt(u.amount);
    const r = tool('drip-spend', ['--entry', entry, '--token-id', st.tokenId, ...dripArgs(st), '--utxo', `${u.outpoint.transactionId}:${u.outpoint.index}`, '--value', value.toString()]);
    if (spkAddr(r.scriptPublicKey) !== st.drip.address) die(`the tool's drip address ${spkAddr(r.scriptPublicKey)} is not the recorded ${st.drip.address}`, 3);
    console.log(`drip                : ${st.drip.address}  coin ${u.outpoint.transactionId}:${u.outpoint.index} (${value} sompi)`);
    console.log(`${entry.padEnd(20)}: keeps ${r.keep} sompi, pays ${r.fee} sompi to the miner as the fee, sequence ${r.sequence}`);
    console.log(`local engine        : ${r.simulate.ok ? `accepts, ${r.simulate.scriptUnits.join(' + ')} script units` : `rejects (${r.simulate.error})`}`);
    if (!r.simulate.ok) die(`the local engine rejects the ${entry}; not submitting`, 1);
    let budget = args.budget ? Number(args.budget) : Number(r.simulate.budgets[0]);
    const start = dag.sink;
    for (let round = 1; round <= 8; round++) {
      const tx = new Transaction({
        version: 1,
        inputs: [{ previousOutpoint: { transactionId: u.outpoint.transactionId, index: u.outpoint.index }, signatureScript: r.tx.inputs[0].signatureScript, sequence: BigInt(r.sequence), sigOpCount: 0, computeBudget: budget,
          utxo: { outpoint: { transactionId: u.outpoint.transactionId, index: u.outpoint.index }, amount: value, scriptPublicKey: { version: 0, script: r.scriptPublicKey }, blockDaaScore: u.entry.blockDaaScore, isCoinbase: u.entry.isCoinbase } }],
        outputs: [{ value: BigInt(r.keep), scriptPublicKey: { version: 0, script: r.scriptPublicKey } }],
        lockTime: 0n, subnetworkId: SUBNET, gas: 0n, payload: '',
      });
      if (args['dry-run']) { console.log(`dry-run: ${entry} txid ${tx.id}, budget ${budget}; not submitted`); return; }
      process.stdout.write(`[drip-${entry}] budget ${budget} ... `);
      try {
        const res = await rpc.submitTransaction({ transaction: tx, allowOrphan: false });
        console.log(`ACCEPTED  txid ${res.transactionId}`);
        if (entry === 'reveal') st.drip.revealTxid = res.transactionId; else (st.drip.claims ??= []).push({ txid: res.transactionId, prize: r.fee, at: now() });
        st.drip.utxo = { txid: res.transactionId, index: 0, amount: r.keep };
        st.history.push({ kind: `drip-${entry}`, txid: res.transactionId, keep: r.keep, fee: r.fee, budget, at: now() });
        saveState(st);
        const seen = await waitForUtxo(rpc, st.drip.address, res.transactionId, 0);
        console.log(seen ? `drip coin live      : ${res.transactionId}:0 (${seen.amount} sompi)` : 'drip coin not visible after 90 s; check before the next claim');
        const block = await findAcceptingBlock(rpc, start, res.transactionId);
        console.log(`accepting block     : ${block ?? 'not found yet'}`);
        if (entry === 'reveal') console.log(`the script, with the token id ${st.tokenId} stamped in it, is now on chain in that input; tell the Studio: genesis ${st.drip.genesisTxid}, drip ${st.drip.address}, redeem ${st.drip.redeem.slice(0, 16)}..., terms ${JSON.stringify(st.drip.terms)}`);
        return;
      } catch (e) {
        const msg = firstLine(e);
        const used = usedUnits(msg);
        if (used === null) {
          console.log('rejected');
          console.log(`  ${msg}`);
          if (/sequence|lock|immature|age/i.test(msg)) console.log('  (the coin is too young for the node\'s sequence check: retry in a few seconds for a reveal, or wait out the period for a claim)');
          st.history.push({ kind: `drip-${entry}-rejected`, error: msg, at: now() }); saveState(st); process.exit(1);
        }
        console.log(`under budget (used=${used})`);
        const next = Number(coveringComputeBudget(used));
        budget = next > budget ? next : budget + 1;
      }
    }
    die('budget walk-up did not converge', 1);
  } finally {
    await rpc.disconnect();
  }
}

function cmdShow() {
  const st = loadState();
  console.log(jsonBig({ covenantId: st.covenantId, tokenId: st.tokenId, address: st.address, state: st.state, maxMint: st.params?.maxMint, utxo: st.utxo, authority: st.authorityUtxo, prep: st.prep && { txid: st.prep.txid, bytes: st.prep.payloadHex.length / 2, metadata: st.prep.metadata, acceptingBlock: st.prep.acceptingBlock, readBack: st.prep.readBack }, initTxid: st.initTxid, initBlock: st.initBlock, drip: st.drip && { address: st.drip.address, terms: st.drip.terms, utxo: st.drip.utxo, revealTxid: st.drip.revealTxid, claims: (st.drip.claims ?? []).length }, cells: st.cells, burns: st.burns }));
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
