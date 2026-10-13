// Loads the vendored Kaspa WASM SDK (v2.0.0, Toccata). No npm needed.
// The SDK is the same Rust code that runs in kaspad, compiled to wasm32,
// so ScriptBuilder / P2SH / mass calculations here are consensus-exact.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

export const kaspa = require(join(here, '..', 'vendor', 'kaspa', 'kaspa.js'));

export const {
  ScriptBuilder,
  Opcodes,
  payToScriptHashScript,
  payToScriptHashSignatureScript,
  addressFromScriptPublicKey,
  calculateTransactionMass,
  Transaction,
  NetworkType,
  NetworkId,
  version,
} = kaspa;

export function sdkVersion() {
  return version();
}
