#!/usr/bin/env node
// kaspa-spk.mjs: Kaspa address -> the 33-byte recipient the Vault stores and the journal carries.
//
//   node bin/kaspa-spk.mjs kaspa:qr...          -> 0x00<32-byte payload>   (P2PK Schnorr, version 0)
//   node bin/kaspa-spk.mjs kaspa:pq...          -> 0x08<32-byte payload>   (P2SH, version 8)
//   node bin/kaspa-spk.mjs --decode 0x00...     -> the address back (mainnet)
//
// The 33 bytes are: address version byte + 32-byte payload. The output script the covenant must
// build from them (CP-6): version 0 -> 20<payload>ac, version 8 -> aa20<payload>87. ECDSA
// addresses (version 1, 33-byte payload) are refused, as in Vault.sol.
import { kaspa } from '../src/sdk.js';

const { Address, ScriptPublicKey, payToAddressScript, addressFromScriptPublicKey } = kaspa;
const args = process.argv.slice(2);

function encode(addrStr) {
  if (!Address.validate(addrStr)) throw new Error(`not a valid Kaspa address: ${addrStr}`);
  const spk = payToAddressScript(new Address(addrStr));
  const script = spk.script; // hex
  let version, payload;
  if (/^20[0-9a-f]{64}ac$/i.test(script)) { version = 0; payload = script.slice(2, 66); }       // P2PK schnorr
  else if (/^aa20[0-9a-f]{64}87$/i.test(script)) { version = 8; payload = script.slice(4, 68); } // P2SH
  else throw new Error(`unsupported address kind (ECDSA?): script ${script}`);
  return { version, payload, script, hex: '0x' + version.toString(16).padStart(2, '0') + payload };
}

function decode(hex) {
  const h = hex.replace(/^0x/, '');
  if (h.length !== 66) throw new Error('expected 33 bytes');
  const version = parseInt(h.slice(0, 2), 16);
  const payload = h.slice(2);
  const script = version === 0 ? `20${payload}ac` : version === 8 ? `aa20${payload}87` : null;
  if (!script) throw new Error(`unsupported version ${version}`);
  const addr = addressFromScriptPublicKey(new ScriptPublicKey(0, script), 'mainnet');
  return { version, payload, script, address: addr?.toString() };
}

if (args[0] === '--decode') {
  const d = decode(args[1]);
  console.log(`version : ${d.version}`);
  console.log(`payload : ${d.payload}`);
  console.log(`script  : ${d.script}`);
  console.log(`address : ${d.address}`);
} else if (args[0]) {
  const e = encode(args[0]);
  const back = decode(e.hex);
  if (back.address !== args[0]) throw new Error(`roundtrip mismatch: ${back.address}`);
  console.error(`version ${e.version}, payload ${e.payload}, output script ${e.script} (roundtrip ok)`);
  console.log(e.hex);
} else {
  console.error('usage: kaspa-spk.mjs <kaspa:address> | --decode 0x<33 bytes hex>');
  process.exit(2);
}
