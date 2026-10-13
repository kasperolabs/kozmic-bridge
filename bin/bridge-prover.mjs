#!/usr/bin/env node
// CP-7 prover service for the Kaspa ZK bridge: watch Ethereum, prove, submit, heartbeat. No manual step.
//
//   node bin/bridge-prover.mjs --url ws://127.0.0.1:17110              # run forever (pm2)
//   node bin/bridge-prover.mjs --url ws://... --once                    # one tick, then exit
//   node bin/bridge-prover.mjs --url ws://... --once --force heartbeat  # prove + advance now even if nothing is due
//   node bin/bridge-prover.mjs --url ws://... --once --dry-run          # fetch + dev-mode execute only, no pod, no tx
//
// Options: --state bridge-cp6-state.json  --heartbeat-days 7  --poll 60  --pod-cap 3600  --min-bridge-kas 6
//          --beacons URL,URL  --eth-rpc eth-rpc-url.txt  --runpod-key runpod-api-key.txt  --ssh-key ~/.ssh/id_ed25519
//          --no-submit (stop after wrap; print the advance command)
//
// One tick: read the light-client finality update (beacon endpoints with failover) and the vault nonce at
// its execution block. A cycle runs when a deposit beyond the cursor is provable there, or when the last
// advance is older than --heartbeat-days, and the finalized header has moved past the covenant's. A cycle:
//   1. eth-prover fetch from the covenant's header, nonces cursor+1 .. min(nonce, cursor+4)
//      (heartbeat: re-prove nonce = cursor; bridge.sil requires journal.vault == VAULT on every advance,
//      so a journal without deposits can never open the covenant; deposits <= cursor are skipped, not minted)
//   2. RISC0_DEV_MODE execute on this box: cycle count, and the journal's prev_header checked against the state
//   3. Runpod GPU pod (image kasperolabs/eth-prover:cuda): upload, prove --no-wrap, download, delete the pod
//   4. image_id.hex must equal the covenant's pinned image id; eth-prover wrap (Docker) on this box
//   5. node bin/bridge.mjs advance --bundle DIR (local engine check, budget walk-up, state file update)
// Every event goes to bridge-prover.log.jsonl. Pods are named bridge-prover-*; any such pod alive outside a
// cycle is an orphan and is deleted on the next tick. Nothing here holds a Kaspa or Ethereum key.
import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = parseArgs(process.argv.slice(2));
const PROVER = process.env.ETH_PROVER_BIN ?? join(ROOT, 'eth-prover', 'target', 'release', 'eth-prover');
const STATE = resolve(ROOT, args.state ?? 'bridge-cp6-state.json');
const LOG = resolve(ROOT, 'bridge-prover.log.jsonl');
const LOCK = resolve(ROOT, 'bridge-prover.lock');
const BEACONS = String(args.beacons ?? 'https://ethereum-beacon-api.publicnode.com,https://lodestar-mainnet.chainsafe.io').split(',');
const HB_MS = Number(args['heartbeat-days'] ?? 7) * 86_400_000;
const POLL_MS = Number(args.poll ?? 60) * 1000;
const POD_CAP_S = Number(args['pod-cap'] ?? 3600);
const MIN_KAS = Number(args['min-bridge-kas'] ?? 6);
const IMAGE = 'kasperolabs/eth-prover:cuda';
const GPUS = ['NVIDIA GeForce RTX 4090', 'NVIDIA L40S', 'NVIDIA RTX 6000 Ada Generation', 'NVIDIA A40', 'NVIDIA GeForce RTX 3090'];
const MAX_DEPOSITS = 4;
if (!args.url && !args['dry-run']) die('--url ws://<node>:17110 is required');

const ethRpc = readSecret(args['eth-rpc'] ?? 'eth-rpc-url.txt', 'Ethereum RPC URL');
const redact = (s) => String(s).split(ethRpc).join('<eth-rpc>');
let backoffUntil = 0, backoffMs = 0, lastIdleLog = 0;

// ---------------------------------------------------------------- main
acquireLock();
process.on('exit', () => { try { unlinkSync(LOCK); } catch { /* gone */ } });
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, async () => { await deleteOurPods('signal'); process.exit(130); });
event('start', { beacons: BEACONS.map(host), heartbeatDays: HB_MS / 86_400_000, poll: POLL_MS / 1000, dryRun: !!args['dry-run'] });
for (;;) {
  try { await tick(); } catch (e) { event('tick-error', { error: redact(e.message ?? e) }); }
  if (args.once) break;
  await sleep(POLL_MS);
}

// ---------------------------------------------------------------- tick
async function tick() {
  if (!args['dry-run']) await deleteOurPods('orphan-sweep');
  const st = JSON.parse(readFileSync(STATE, 'utf8'));
  const cursor = Number(st.state.cursor);
  const fin = await finality();
  if (!fin) { event('stall', { reason: 'no beacon endpoint returned a finality update' }); return; }
  const nonce = await vaultNonce(st.params.vault, fin.execBlock);
  const lastAdv = [...st.history].reverse().find((h) => h.newSlot || h.kind === 'genesis' || h.kind === 'init');
  const covSlot = [...st.history].reverse().find((h) => h.newSlot)?.newSlot ?? 0;
  const lastAt = Date.parse(lastAdv?.at ?? 0);
  const kas = Number(st.utxo.amount) / 1e8;
  if (kas < MIN_KAS) event('alarm-balance', { bridgeKas: kas, min: MIN_KAS, address: st.address });

  const pending = nonce > cursor;
  const due = Date.now() - lastAt >= HB_MS;
  const force = args.force === 'heartbeat';
  const progress = fin.slot > covSlot;
  const view = { cursor, vaultNonce: nonce, finalizedSlot: fin.slot, execBlock: fin.execBlock, covenantSlot: covSlot, lagMin: fin.lagMin, via: fin.via };
  if (!pending && !due && !force) {
    if (Date.now() - lastIdleLog > 3_600_000 || args.once) { event('idle', { ...view, nextHeartbeatIn: `${((lastAt + HB_MS - Date.now()) / 3_600_000).toFixed(1)} h` }); lastIdleLog = Date.now(); }
    return;
  }
  if (!progress) { event('wait-finality', view); return; }
  if (Date.now() < backoffUntil) return;
  let nonces;
  if (pending) nonces = range(cursor + 1, Math.min(nonce, cursor + MAX_DEPOSITS));
  else if (cursor >= 1) nonces = [cursor];
  else { event('heartbeat-impossible', { reason: 'cursor 0: no deposit to re-prove, and bridge.sil rejects a journal without the vault' }); return; }
  try {
    await cycle(st, nonces, pending ? 'mint' : 'heartbeat', view);
    backoffMs = 0;
  } catch (e) {
    backoffMs = Math.min(backoffMs ? backoffMs * 2 : 600_000, 7_200_000);
    backoffUntil = Date.now() + backoffMs;
    event('cycle-failed', { error: redact(e.message ?? e), retryInMin: backoffMs / 60_000 });
  }
}

// ---------------------------------------------------------------- one cycle
async function cycle(st, nonces, kind, view) {
  const t0 = Date.now();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const rel = `eth-prover/out-auto-${stamp}`;
  const dir = join(ROOT, rel);
  mkdirSync(dir, { recursive: true });
  const rec = { kind, nonces, dir: rel, ...view, t: {} };
  event('cycle-start', rec);

  // 1. fetch, failover across beacons
  let fetched = null;
  for (const b of BEACONS) {
    const r = run(PROVER, ['fetch', '--network', 'mainnet', '--consensus-rpc', b, '--checkpoint', `0x${st.state.header}`,
      '--execution-rpc', ethRpc, '--vault', `0x${st.params.vault}`, ...nonces.flatMap((n) => ['--nonce', String(n)]), '--out', join(dir, 'inputs.cbor')], { timeout: 180_000 });
    writeFileSync(join(dir, `fetch-${host(b)}.log`), redact(r.out));
    if (r.code === 0) { fetched = { via: host(b), out: r.out }; break; }
    event('fetch-failed', { via: host(b), tail: redact(tail(r.out, 3)) });
  }
  if (!fetched) throw new Error('fetch failed on every beacon endpoint');
  rec.rotations = Number(fetched.out.match(/sync committee updates: (\d+)/)?.[1] ?? 0);
  rec.t.fetch = secs(t0);

  // 2. dev-mode execute: cycles, and the journal must continue from the covenant's state
  const ex = run(PROVER, ['execute', '--inputs', join(dir, 'inputs.cbor')], { timeout: 900_000, env: { ...process.env, RISC0_DEV_MODE: '1' } });
  writeFileSync(join(dir, 'execute.log'), ex.out);
  if (ex.code !== 0) throw new Error(`dev-mode execute failed: ${tail(ex.out, 3)}`);
  rec.userCycles = Number(ex.out.match(/user cycles\s*:\s*(\d+)/)?.[1] ?? 0);
  rec.segments = Number(ex.out.match(/segments\s*:\s*(\d+)/)?.[1] ?? 0);
  const prev = ex.out.match(/prev_header\s*:\s*0x([0-9a-f]{64})/)?.[1];
  const prevC = ex.out.match(/prev_committee\s*:\s*0x([0-9a-f]{64})/)?.[1];
  if (prev !== st.state.header || prevC !== st.state.committee) throw new Error(`journal starts at ${prev}/${prevC}, covenant is at ${st.state.header}/${st.state.committee}`);
  rec.newHeader = ex.out.match(/new_header\s*:\s*0x([0-9a-f]{64})/)?.[1];
  rec.t.execute = secs(t0) - rec.t.fetch;
  event('preflight-ok', { rotations: rec.rotations, userCycles: rec.userCycles, segments: rec.segments, newHeader: rec.newHeader });
  if (args['dry-run']) { event('dry-run-done', rec); return; }

  // 3. GPU pod
  const pod = await provePod(join(dir, 'inputs.cbor'), dir, `bridge-prover-${stamp}`);
  Object.assign(rec, { pod: { gpu: pod.gpu, dc: pod.dc, costPerHr: pod.costPerHr, costUsd: pod.costUsd }, t: { ...rec.t, ...pod.t } });
  const imageId = readFileSync(join(dir, 'image_id.hex'), 'utf8').trim();
  if (imageId !== st.params.imageId) throw new Error(`pod proved image ${imageId}, the covenant pins ${st.params.imageId}`);
  if (!existsSync(join(dir, 'receipt.succinct.bin'))) throw new Error('pod returned no receipt.succinct.bin');

  // 4. Groth16 wrap on this box (Docker)
  const tw = Date.now();
  const w = run(PROVER, ['wrap', '--receipt', join(dir, 'receipt.succinct.bin'), '--out', dir], { timeout: 900_000 });
  writeFileSync(join(dir, 'wrap.log'), w.out);
  if (w.code !== 0 || !existsSync(join(dir, 'receipt.hex'))) throw new Error(`wrap failed: ${tail(w.out, 3)}`);
  rec.t.wrap = secs(tw);
  if (args['no-submit']) { event('bundle-ready', { ...rec, next: `node bin/bridge.mjs advance --bundle ${rel} --url ${args.url}` }); return; }

  // 5. advance on Kaspa
  const ta = Date.now();
  const a = run(process.execPath, [join(ROOT, 'bin', 'bridge.mjs'), 'advance', '--bundle', rel, '--url', args.url, '--state', STATE], { timeout: 600_000, cwd: ROOT });
  writeFileSync(join(dir, 'advance.log'), a.out);
  rec.t.advance = secs(ta);
  rec.t.total = secs(t0);
  if (a.code !== 0) throw new Error(`advance failed (exit ${a.code}): ${tail(a.out, 4)}`);
  const after = JSON.parse(readFileSync(STATE, 'utf8'));
  const h = after.history[after.history.length - 1];
  event('advanced', { ...rec, txid: h.txid, budgets: h.budgets, fee: h.fee, mints: h.mints, cursor: h.cursor, bridgeKas: Number(after.utxo.amount) / 1e8 });
}

// ---------------------------------------------------------------- Runpod
async function rp(method, path, body) {
  const key = readSecret(args['runpod-key'] ?? 'runpod-api-key.txt', 'Runpod API key');
  const r = await fetch(`https://rest.runpod.io/v1${path}`, {
    method, headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30_000),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`Runpod ${method} ${path}: ${r.status} ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}

async function deleteOurPods(why) {
  let pods;
  try { pods = await rp('GET', '/pods'); } catch (e) { event('runpod-list-failed', { error: e.message }); return; }
  for (const p of pods ?? []) {
    if (!String(p.name).startsWith('bridge-prover-')) continue;
    try { await rp('DELETE', `/pods/${p.id}`); event('pod-deleted', { id: p.id, name: p.name, why }); }
    catch (e) { event('ALARM-pod-delete-failed', { id: p.id, error: e.message }); }
  }
}

async function provePod(inputs, outDir, name) {
  const sshKey = args['ssh-key'] ?? [join(homedir(), '.ssh/id_ed25519'), join(homedir(), '.ssh/id_rsa')].find((p) => existsSync(p) && existsSync(p + '.pub'));
  if (!sshKey) throw new Error('no SSH key (ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519)');
  const pub = readFileSync(sshKey + '.pub', 'utf8').trim();
  const t0 = Date.now();
  const body = { name, imageName: IMAGE, computeType: 'GPU', gpuTypeIds: GPUS, gpuTypePriority: 'custom', gpuCount: 1,
    interruptible: false, containerDiskInGb: 40, volumeInGb: 0, ports: ['22/tcp'], env: { PUBLIC_KEY: pub } };
  let created;
  try { created = await rp('POST', '/pods', { ...body, cloudType: 'SECURE' }); }
  catch (e) { event('pod-secure-unavailable', { error: e.message }); created = await rp('POST', '/pods', { ...body, cloudType: 'COMMUNITY', supportPublicIp: true }); }
  const pod = { id: created.id, gpu: created.machine?.gpuDisplayName ?? created.gpu?.displayName ?? created.machine?.gpuTypeId, dc: created.machine?.dataCenterId,
    costPerHr: created.costPerHr ?? created.adjustedCostPerHr, t: {} };
  event('pod-created', { id: pod.id, gpu: pod.gpu, dc: pod.dc, costPerHr: pod.costPerHr });
  const left = () => POD_CAP_S * 1000 - (Date.now() - t0);
  try {
    let ip = null, port = null;
    while (!ip || !port) {
      if (left() <= 0) throw new Error('pod cap reached before the pod got an IP');
      await sleep(5000);
      const p = await rp('GET', `/pods/${pod.id}`);
      ip = p.publicIp || null; port = p.portMappings?.['22'] ?? null;
      pod.gpu = p.machine?.gpuDisplayName ?? pod.gpu;
    }
    pod.t.podIp = secs(t0);
    const sshArgs = ['-i', sshKey, '-p', String(port), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
      '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=30', '-o', 'LogLevel=ERROR', `root@${ip}`];
    const ssh = (cmd, opts = {}) => run('ssh', [...sshArgs, cmd], opts);
    while (ssh('true', { timeout: 20_000 }).code !== 0) {
      if (left() <= 0) throw new Error('pod cap reached before SSH answered');
      await sleep(5000);
    }
    pod.t.podSsh = secs(t0);
    const up = ssh('mkdir -p /root/job && cat > /root/job/inputs.cbor', { input: readFileSync(inputs), timeout: 120_000 });
    if (up.code !== 0) throw new Error(`upload failed: ${tail(up.out, 2)}`);
    const tp = Date.now();
    const capS = Math.max(60, Math.floor(left() / 1000) - 120);
    const pr = ssh(`cd /root/job && nvidia-smi --query-gpu=name,clocks.sm,temperature.gpu --format=csv,noheader; timeout ${capS} eth-prover prove --inputs inputs.cbor --no-wrap --out out 2>&1 | tail -20; echo "exit=\${PIPESTATUS[0]}"`, { timeout: (capS + 60) * 1000 });
    writeFileSync(join(outDir, 'prove.log'), pr.out);
    pod.t.prove = secs(tp);
    if (!/exit=0\s*$/.test(pr.out)) throw new Error(`prove failed on the pod: ${tail(pr.out, 3)}`);
    const dl = spawnSync('ssh', [...sshArgs, 'tar -C /root/job/out -cf - .'], { timeout: 300_000, maxBuffer: 256 << 20 });
    if (dl.status !== 0) throw new Error(`download failed: ${String(dl.stderr).slice(0, 200)}`);
    const x = spawnSync('tar', ['-C', outDir, '-xf', '-'], { input: dl.stdout });
    if (x.status !== 0) throw new Error(`untar failed: ${String(x.stderr).slice(0, 200)}`);
  } finally {
    try { await rp('DELETE', `/pods/${pod.id}`); event('pod-deleted', { id: pod.id, why: 'cycle-end' }); }
    catch (e) { event('ALARM-pod-delete-failed', { id: pod.id, error: e.message }); }
    pod.t.podTotal = secs(t0);
    pod.costUsd = pod.costPerHr ? +((pod.costPerHr * pod.t.podTotal) / 3600).toFixed(3) : null;
  }
  return pod;
}

// ---------------------------------------------------------------- Ethereum
async function finality() {
  const curSlot = Math.floor((Date.now() / 1000 - 1606824023) / 12);
  for (const b of BEACONS) {
    try {
      const r = await fetch(`${b}/eth/v1/beacon/light_client/finality_update`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20_000) });
      if (!r.ok) continue;
      const d = (await r.json()).data;
      const slot = Number(d.finalized_header.beacon.slot);
      const execBlock = Number(d.finalized_header.execution?.block_number);
      if (!execBlock) { event('ALARM-no-execution-header', { via: host(b), note: 'Gloas header? the storage-proof path needs the execution-header witness' }); continue; }
      return { slot, execBlock, via: host(b), lagMin: +(((curSlot - slot) * 12) / 60).toFixed(1) };
    } catch { /* next endpoint */ }
  }
  return null;
}

async function vaultNonce(vault, block) {
  const r = await fetch(ethRpc, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(20_000),
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getStorageAt', params: [`0x${vault}`, '0x0', `0x${block.toString(16)}`] }) });
  const j = await r.json();
  if (j.error) throw new Error(`eth_getStorageAt: ${j.error.message}`);
  return Number(BigInt(j.result) & 0xffffffffffffffffn); // slot 0 = nonce (uint64, low 8 bytes)
}

// ---------------------------------------------------------------- helpers
function run(cmd, a, { timeout = 120_000, env, cwd, input } = {}) {
  const r = spawnSync(cmd, a, { encoding: 'utf8', timeout, env, cwd, input, maxBuffer: 64 << 20 });
  return { code: r.status ?? (r.signal ? 124 : 1), out: `${r.stdout ?? ''}${r.stderr ?? ''}${r.error ? `\n${r.error.message}` : ''}` };
}
function event(kind, data = {}) {
  const line = { at: new Date().toISOString(), kind, ...data };
  appendFileSync(LOG, JSON.stringify(line) + '\n');
  console.log(`${line.at}  ${kind.padEnd(18)} ${JSON.stringify(data)}`);
}
function acquireLock() {
  if (existsSync(LOCK)) {
    const pid = Number(readFileSync(LOCK, 'utf8'));
    try { process.kill(pid, 0); die(`another bridge-prover is running (pid ${pid}); ${LOCK}`); } catch { /* stale lock */ }
  }
  writeFileSync(LOCK, String(process.pid));
}
function readSecret(p, what) {
  const f = resolve(ROOT, p);
  if (!existsSync(f)) die(`no ${f} (${what})`);
  return readFileSync(f, 'utf8').trim();
}
function range(a, b) { const o = []; for (let i = a; i <= b; i++) o.push(i); return o; }
function secs(t0) { return Math.round((Date.now() - t0) / 1000); }
function tail(s, n) { return String(s).trim().split('\n').slice(-n).join(' | '); }
function host(u) { return new URL(u).host; }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function die(s) { console.error(s); process.exit(2); }
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const k = argv[i].slice(2);
    out[k] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  }
  return out;
}

