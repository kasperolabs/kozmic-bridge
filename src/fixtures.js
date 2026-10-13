// Proof fixtures lifted verbatim from rusty-kaspa v2.0.0 (commit 90dbf07),
// crypto/txscript/src/zk_precompiles/tests/. These are the vectors the
// consensus engine's own unit tests verify, so they are known-valid under
// OpZkPrecompile on mainnet and testnet-10.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function readHex(name) {
  return readFileSync(join(fixturesDir, 'succinct', name), 'utf8').trim();
}

/** Groth16 (BN254) fixture: { vk, proof, inputs[] } as hex strings. */
export function loadGroth16() {
  const j = JSON.parse(readFileSync(join(fixturesDir, 'groth16.json'), 'utf8'));
  return { vk: j.vk, proof: j.proof, inputs: j.inputs };
}

/**
 * RISC Zero Succinct fixture. Field names match the engine's verify_zk():
 *   hashfn, controlId, imageId, journal, seal, controlDigests, controlIndex, claim
 */
export function loadSuccinct() {
  return {
    seal: readHex('succinct.seal.hex'),
    controlId: readHex('succinct.control_id.hex'),
    claim: readHex('succinct.claim.hex'),
    hashfn: readHex('succinct.hashfn.hex'),
    controlIndex: readHex('succinct.control_index.hex'),
    controlDigests: readHex('succinct.control_digests.hex'),
    imageId: readHex('succinct.image.hex'),
    journal: readHex('succinct.journal.hex'),
  };
}
