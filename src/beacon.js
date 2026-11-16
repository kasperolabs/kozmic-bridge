// Ethereum beacon for burn payload v3 (docs/V4-DESIGN.md 2.2): a recent block of the Ethereum network the relay lives
// on, read from that network's RPC (eth-net.json entry -> rpcFile, first line). The relay checks the hash against its
// own chain's history (EIP-2935), so the beacon must come from the relay's chain: sepolia for a rehearsal, mainnet for
// USDC.k. `depth` blocks behind head, so a one-block Ethereum reorg does not void it. The RPC URL is never printed.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export async function ethBeacon(root, net, depth = 3) {
  const nets = JSON.parse(readFileSync(resolve(root, 'eth-net.json'), 'utf8'));
  const n = nets[net];
  if (!n || !n.rpcFile) throw new Error(`eth-net.json has no network "${net}" with an rpcFile`);
  const url = readFileSync(resolve(root, n.rpcFile), 'utf8').split('\n')[0].trim();
  const call = async (method, params) => {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    const j = await r.json();
    if (j.error) throw new Error(`${method}: ${j.error.message ?? JSON.stringify(j.error)}`);
    return j.result;
  };
  const chainId = BigInt(await call('eth_chainId', []));
  if (chainId !== BigInt(n.chainId)) throw new Error(`the ${net} RPC answers chain id ${chainId}, eth-net.json says ${n.chainId}`);
  const head = BigInt(await call('eth_blockNumber', []));
  const number = head - BigInt(depth);
  const b = await call('eth_getBlockByNumber', ['0x' + number.toString(16), false]);
  if (!b || !/^0x[0-9a-fA-F]{64}$/.test(b.hash ?? '')) throw new Error(`no block ${number} from the ${net} RPC`);
  if (BigInt(b.number) !== number) throw new Error(`asked for block ${number}, got ${BigInt(b.number)}`);
  return { net, chainId, number, hash: b.hash.slice(2).toLowerCase(), timestamp: BigInt(b.timestamp), head };
}

/** KZB1 burn payload: v2 (53 bytes) without a beacon, v3 (93 bytes) with one. target and recipient: 40 hex chars. */
export function burnPayload({ target, tipUnits, recipient, beacon = null }) {
  const tip = BigInt(tipUnits).toString(16).padStart(16, '0');
  if (!beacon) return '4b5a4231' + '02' + target + tip + recipient;
  return '4b5a4231' + '03' + target + tip + recipient + BigInt(beacon.number).toString(16).padStart(16, '0') + beacon.hash;
}
