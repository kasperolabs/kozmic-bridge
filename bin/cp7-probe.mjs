#!/usr/bin/env node
// CP-7 probe: measure what the prover service depends on before designing around it.
//
//   node bin/cp7-probe.mjs                     # beacon endpoints + Ethereum RPC; free, about a minute
//   node bin/cp7-probe.mjs --pod               # + one Runpod RTX 4090 pod: cold start to SSH, GPU info, then delete
//   node bin/cp7-probe.mjs --pod --prove-inputs eth-prover/<inputs>.cbor
//                                              # + a real `prove --no-wrap` on that pod, bundle copied back
//
// Run from the repo root (kaspa-zk-tests). Reads eth-rpc-url.txt and runpod-api-key.txt there
// (--eth-rpc / --runpod-key to override). Never prints either. Writes cp7-probe-<stamp>.json.
// The pod is deleted in every exit path, including Ctrl-C; --pod-cap (default 2400 s) is a wall-clock cap.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

const args = parseArgs(process.argv.slice(2));
const GENESIS_TIME = 1606824023;
const SLOTS_PER_DAY = 7200;
const SLOTS_PER_PERIOD = 8192;
const COVENANT_HEADER = args.header ?? '0x6dc6c279c8bf03e4de767d69585e02215e6ea6ee049d417ce8fe965fd830a3e5';
const VAULT = '0x3DD8Cd71C3efE664d4db96d30fbFEcBEeA06D529';
const BEACONS = String(args.beacons ?? [
  'https://lodestar-mainnet.chainsafe.io',
  'https://www.lightclientdata.org',
  'https://ethereum-beacon-api.publicnode.com',
  'https://mainnet.beacon-api.nimbus.team',
].join(',')).split(',');
const AGES_DAYS = [1, 7, 30, 120];
const UPDATE_PERIODS_BACK = [1, 7, 30, 105, 140];
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const report = { at: new Date().toISOString(), currentSlot: null, currentPeriod: null, roots: {}, beacons: {}, eth: {}, pod: null };

const curSlot = Math.floor((Date.now() / 1000 - GENESIS_TIME) / 12);
const curPeriod = Math.floor(curSlot / SLOTS_PER_PERIOD);
report.currentSlot = curSlot;
report.currentPeriod = curPeriod;
log(`wall-clock slot ${curSlot}, period ${curPeriod}`);

// ---------------------------------------------------------------- beacon
async function get(url, timeoutMs = 25_000) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs) });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { status: r.status, ms: Date.now() - t0, json, bytes: text.length };
  } catch (e) {
    return { status: 0, ms: Date.now() - t0, err: String(e.cause?.code ?? e.name ?? e).slice(0, 80) };
  }
}

// Checkpoint roots k days back: block root at the epoch-start slot, or the last block before it.
for (const d of AGES_DAYS) {
  const target = Math.floor((curSlot - d * SLOTS_PER_DAY) / 32) * 32;
  let found = null;
  for (const b of BEACONS) {
    for (let s = target; s > target - 32 && !found; s--) {
      const r = await get(`${b}/eth/v1/beacon/headers/${s}`, 10_000);
      if (r.status === 200 && r.json?.data?.root) found = { root: r.json.data.root, slot: s, via: host(b) };
      else if (r.status !== 404) break; // endpoint lacks the route or failed; try the next endpoint
    }
    if (found) break;
  }
  report.roots[`${d}d`] = found ?? { root: null, slot: target };
  log(`root ${String(d).padStart(3)}d back: ${found ? `${found.root} slot ${found.slot} (via ${found.via})` : 'not resolvable on any endpoint'}`);
}

for (const b of BEACONS) {
  const h = host(b);
  const out = { finality: null, bootstrap: {}, updates: {} };
  report.beacons[h] = out;
  const f = await get(`${b}/eth/v1/beacon/light_client/finality_update`);
  if (f.status === 200 && f.json?.data) {
    const d = f.json.data;
    const slot = Number(d.finalized_header?.beacon?.slot);
    out.finality = { version: f.json.version, finalizedSlot: slot, execBlock: Number(d.finalized_header?.execution?.block_number), lagMin: +(((curSlot - slot) * 12) / 60).toFixed(1), ms: f.ms };
  } else out.finality = { status: f.status, err: f.err, ms: f.ms };
  const bs = async (label, root) => {
    if (!root) { out.bootstrap[label] = 'no root'; return; }
    const r = await get(`${b}/eth/v1/beacon/light_client/bootstrap/${root}`);
    out.bootstrap[label] = r.status === 200 ? `200 ${r.ms}ms` : `${r.status || r.err} ${r.ms}ms`;
  };
  await bs('covenant', COVENANT_HEADER);
  for (const d of AGES_DAYS) await bs(`${d}d`, report.roots[`${d}d`].root);
  for (const k of UPDATE_PERIODS_BACK) {
    const p = curPeriod - k;
    const r = await get(`${b}/eth/v1/beacon/light_client/updates?start_period=${p}&count=1`);
    out.updates[`-${k} (p${p})`] = r.status === 200 && Array.isArray(r.json) ? `200 n=${r.json.length} ${r.ms}ms` : `${r.status || r.err} ${r.ms}ms`;
  }
  log(`\n${h}`);
  log(`  finality_update : ${out.finality.finalizedSlot ? `slot ${out.finality.finalizedSlot}, exec block ${out.finality.execBlock}, lag ${out.finality.lagMin} min, ${out.finality.version}, ${out.finality.ms}ms` : `FAIL ${out.finality.status || out.finality.err}`}`);
  log(`  bootstrap       : ${Object.entries(out.bootstrap).map(([k, v]) => `${k}=${v}`).join('  ')}`);
  log(`  updates         : ${Object.entries(out.updates).map(([k, v]) => `${k} ${v}`).join('  ')}`);
}

// ---------------------------------------------------------------- Ethereum execution RPC
const rpcFile = resolve(args['eth-rpc'] ?? 'eth-rpc-url.txt');
const lcFinal = Object.values(report.beacons).map((x) => x.finality?.execBlock).filter(Boolean).sort((a, b) => b - a)[0];
if (existsSync(rpcFile) && lcFinal) {
  const url = readFileSync(rpcFile, 'utf8').trim();
  const call = async (method, params) => {
    const t0 = Date.now();
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(20_000) });
      const j = await r.json();
      return { ok: !j.error, v: j.result, err: j.error?.message?.slice(0, 120), ms: Date.now() - t0 };
    } catch (e) { return { ok: false, err: String(e.cause?.code ?? e.name), ms: Date.now() - t0 }; }
  };
  const hex = (n) => '0x' + n.toString(16);
  const head = await call('eth_blockNumber', []);
  const fin = await call('eth_getBlockByNumber', ['finalized', false]);
  const nLc = await call('eth_getStorageAt', [VAULT, '0x0', hex(lcFinal)]);
  const nLatest = await call('eth_getStorageAt', [VAULT, '0x0', 'latest']);
  const old = lcFinal - 7 * SLOTS_PER_DAY;
  const nOld = await call('eth_getStorageAt', [VAULT, '0x0', hex(old)]);
  const proofOld = await call('eth_getProof', [VAULT, ['0x0'], hex(old)]);
  report.eth = {
    head: head.ok ? parseInt(head.v, 16) : head.err,
    executionFinalized: fin.ok ? parseInt(fin.v.number, 16) : fin.err,
    lightClientFinalized: lcFinal,
    vaultNonceAtLcFinal: nLc.ok ? parseInt(nLc.v, 16) : nLc.err,
    vaultNonceLatest: nLatest.ok ? parseInt(nLatest.v, 16) : nLatest.err,
    storageAt7dBack: nOld.ok ? `ok (${parseInt(nOld.v, 16)})` : nOld.err,
    getProof7dBack: proofOld.ok ? 'ok' : proofOld.err,
  };
  log('\nEthereum RPC (URL not printed)');
  for (const [k, v] of Object.entries(report.eth)) log(`  ${k.padEnd(22)}: ${v}`);
} else log(`\nEthereum RPC: skipped (${existsSync(rpcFile) ? 'no light-client finalized block' : `no ${rpcFile}`})`);

// ---------------------------------------------------------------- Runpod pod
let podId = null;
let rpKey = null;
async function rp(method, path, body) {
  const r = await fetch(`https://rest.runpod.io/v1${path}`, {
    method, headers: { authorization: `Bearer ${rpKey}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30_000),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`Runpod ${method} ${path}: ${r.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}
async function cleanup() {
  if (!podId) return;
  const id = podId; podId = null;
  try { await rp('DELETE', `/pods/${id}`); log(`pod ${id} deleted`); }
  catch (e) { log(`DELETE FAILED: delete pod ${id} in the Runpod console now. ${e.message}`); }
}
process.on('SIGINT', async () => { await cleanup(); process.exit(130); });

if (args.pod) {
  const keyFile = resolve(args['runpod-key'] ?? 'runpod-api-key.txt');
  if (!existsSync(keyFile)) die(`no ${keyFile}: create an API key in Runpod (Settings, API Keys, read/write) and save it there, chmod 600`);
  rpKey = readFileSync(keyFile, 'utf8').trim();
  const sshKey = args['ssh-key'] ?? [join(homedir(), '.ssh/id_ed25519'), join(homedir(), '.ssh/id_rsa')].find((p) => existsSync(p) && existsSync(p + '.pub'));
  if (!sshKey) die('no SSH key: ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519');
  const pub = readFileSync(sshKey + '.pub', 'utf8').trim();
  const cap = Number(args['pod-cap'] ?? 2400) * 1000;
  const pod = { t: {} };
  report.pod = pod;
  try {
    const existing = await rp('GET', '/pods');
    pod.existingPods = (existing ?? []).map((p) => `${p.id} ${p.name} ${p.desiredStatus}`);
    log(`\nRunpod API ok; existing pods: ${pod.existingPods.length ? pod.existingPods.join('; ') : 'none'}`);
    const t0 = Date.now();
    const created = await rp('POST', '/pods', {
      name: `cp7-probe-${stamp}`, imageName: 'kasperolabs/eth-prover:cuda', computeType: 'GPU',
      gpuTypeIds: ['NVIDIA GeForce RTX 4090'], gpuCount: 1, cloudType: 'SECURE', interruptible: false,
      containerDiskInGb: 40, volumeInGb: 0, ports: ['22/tcp'], env: { PUBLIC_KEY: pub },
    });
    podId = created.id;
    pod.id = created.id;
    pod.costPerHr = created.costPerHr ?? created.adjustedCostPerHr;
    log(`pod ${podId} created (${pod.costPerHr} $/h, ${created.machine?.dataCenterId ?? created.machine?.location ?? '?'})`);
    const elapsed = () => Date.now() - t0;
    let ip = null, port = null;
    while (!ip || !port) {
      if (elapsed() > cap) throw new Error('cap reached before the pod got an IP');
      await sleep(5000);
      const p = await rp('GET', `/pods/${podId}`);
      ip = p.publicIp || null; port = p.portMappings?.['22'] ?? null;
    }
    pod.t.ipSeconds = Math.round(elapsed() / 1000);
    log(`ip ${ip}:${port} after ${pod.t.ipSeconds} s`);
    const sshArgs = ['-i', sshKey, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=8', '-o', 'LogLevel=ERROR'];
    const ssh = (cmd, timeout = 60_000) => {
      const r = spawnSync('ssh', [...sshArgs, '-p', String(port), `root@${ip}`, cmd], { encoding: 'utf8', timeout });
      return { code: r.status, out: ((r.stdout || '') + (r.stderr || '')).trim() };
    };
    const scp = (from, to, timeout = 300_000) => spawnSync('scp', [...sshArgs, '-P', String(port), '-r', from, to], { encoding: 'utf8', timeout });
    while (ssh('true', 20_000).code !== 0) {
      if (elapsed() > cap) throw new Error('cap reached before SSH answered');
      await sleep(5000);
    }
    pod.t.sshSeconds = Math.round(elapsed() / 1000);
    log(`ssh ready after ${pod.t.sshSeconds} s (image pull + container start)`);
    const info = ssh('nvidia-smi --query-gpu=name,memory.total,clocks.max.sm,driver_version --format=csv,noheader; nproc; free -g | sed -n 2p; command -v eth-prover; df -h / | tail -1');
    pod.info = info.out;
    log(info.out.split('\n').map((l) => `  ${l}`).join('\n'));

    if (args['prove-inputs']) {
      const inputs = resolve(String(args['prove-inputs']));
      if (!existsSync(inputs)) throw new Error(`no ${inputs}`);
      const up = scp(inputs, `root@${ip}:/root/inputs.cbor`);
      if (up.status !== 0) throw new Error(`scp up failed: ${up.stderr}`);
      log('proving (prove --no-wrap) ...');
      const tp = Date.now();
      const left = cap - elapsed() - 120_000;
      const pr = ssh('cd /root && nvidia-smi --query-gpu=clocks.sm,temperature.gpu,power.draw --format=csv,noheader; eth-prover prove --inputs /root/inputs.cbor --no-wrap --out /root/out-probe 2>&1 | tail -15; nvidia-smi --query-gpu=clocks.sm,temperature.gpu,power.draw --format=csv,noheader', left);
      pod.t.proveWallSeconds = Math.round((Date.now() - tp) / 1000);
      pod.proveTail = pr.out;
      log(pr.out.split('\n').map((l) => `  ${l}`).join('\n'));
      const dest = resolve('eth-prover', `out-probe-${stamp}`);
      mkdirSync(dest, { recursive: true });
      const down = scp(`root@${ip}:/root/out-probe/.`, dest);
      pod.bundle = down.status === 0 ? dest : `scp down failed: ${down.stderr}`;
      log(`prove wall ${pod.t.proveWallSeconds} s; bundle ${pod.bundle}`);
    }
    pod.t.totalSeconds = Math.round(elapsed() / 1000);
    pod.costUsd = pod.costPerHr ? +((pod.costPerHr * pod.t.totalSeconds) / 3600).toFixed(3) : null;
  } catch (e) {
    pod.error = e.message;
    log(`pod probe error: ${e.message}`);
  } finally {
    await cleanup();
  }
  log(`pod total ${pod.t.totalSeconds ?? '?'} s, about $${pod.costUsd ?? '?'}`);
}

const outFile = `cp7-probe-${stamp}.json`;
writeFileSync(outFile, JSON.stringify(report, null, 2) + '\n');
log(`\nwrote ${outFile}`);

// ----------------------------------------------------------------
function host(u) { return new URL(u).host; }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function log(s) { console.log(s); }
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

