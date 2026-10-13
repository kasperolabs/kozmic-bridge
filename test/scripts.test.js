import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sdkVersion, Opcodes } from '../src/sdk.js';
import { loadGroth16, loadSuccinct } from '../src/fixtures.js';
import {
  ZK_TAG,
  OP_ZK_PRECOMPILE,
  groth16RedeemScript,
  groth16UnlockScript,
  groth16SignatureScript,
  groth16StandaloneScript,
  succinctRedeemScript,
  succinctUnlockScript,
  succinctSignatureScript,
  succinctStandaloneScript,
  p2shScriptPublicKey,
  p2shAddress,
  decodeScript,
} from '../src/zk-scripts.js';
import { MAX_SIGNATURE_SCRIPT_LEN_POST_TOCCATA, MAX_SCRIPT_ELEMENT_SIZE_POST_TOCCATA } from '../src/cost.js';

const g = loadGroth16();
const s = loadSuccinct();

test('SDK is the Toccata build and exposes OpZkPrecompile = 0xa6', () => {
  assert.equal(sdkVersion(), '2.1.0');
  assert.equal(Opcodes.OpZkPrecompile, OP_ZK_PRECOMPILE);
  assert.equal(Opcodes.OpZkPrecompile, 166);
});

test('fixture sizes match rusty-kaspa test vectors', () => {
  assert.equal(g.vk.length / 2, 424, 'compressed BN254 VK with 6 gamma_abc elements');
  assert.equal(g.proof.length / 2, 128, 'compressed Groth16 proof (A:32, B:64, C:32)');
  assert.equal(g.inputs.length, 5);
  for (const i of g.inputs) assert.equal(i.length / 2, 32, 'Fr element is 32 bytes');
  assert.equal(s.seal.length / 2, 222668, 'Succinct seal bytes');
  assert.equal((s.seal.length / 2) % 4, 0, 'seal is a list of u32 words');
  assert.equal(s.imageId.length / 2, 32);
  assert.equal(s.journal.length / 2, 32);
  assert.equal(s.claim.length / 2, 32);
  assert.equal(s.controlId.length / 2, 32);
  assert.equal(s.controlDigests.length / 2, 256, '8 x 32-byte digests (Poseidon2 control tree depth 8)');
  assert.equal(s.controlIndex.length / 2, 4);
  assert.equal(s.hashfn.length / 2, 1);
});

test('Groth16 redeem script = push(vk) push(0x20) OpZkPrecompile', () => {
  const redeem = groth16RedeemScript(g.vk);
  const ops = decodeScript(redeem);
  assert.equal(ops.length, 3);
  assert.equal(ops[0].op, 0x4d, 'OpPushData2 for 424-byte VK');
  assert.equal(ops[0].data, g.vk);
  assert.equal(ops[1].dataLen, 1);
  assert.equal(ops[1].data, '20');
  assert.equal(ops[2].op, OP_ZK_PRECOMPILE);
  assert.equal(redeem.length / 2, 3 + 424 + 2 + 1);
});

test('Groth16 unlock script pushes inputs reversed, count, proof (engine pops vk, proof, n, inputs[0..n))', () => {
  const unlock = groth16UnlockScript(g.proof, g.inputs);
  const ops = decodeScript(unlock);
  assert.equal(ops.length, 7);
  for (let k = 0; k < 5; k++) assert.equal(ops[k].data, g.inputs[4 - k], `input ${4 - k} pushed at position ${k}`);
  assert.equal(ops[5].op, 0x55, 'count 5 encodes as Op5 (canonical small int)');
  assert.equal(ops[6].op, 0x4c, 'OpPushData1 for 128-byte proof');
  assert.equal(ops[6].data, g.proof);
});

test('Groth16 P2SH signature script = unlock || push(redeem), and stand-alone script matches helpers.rs order', () => {
  const redeem = groth16RedeemScript(g.vk);
  const unlock = groth16UnlockScript(g.proof, g.inputs);
  const sig = groth16SignatureScript(g);
  assert.ok(sig.startsWith(unlock));
  const tail = decodeScript(sig.slice(unlock.length));
  assert.equal(tail.length, 1);
  assert.equal(tail[0].data, redeem);
  // standalone: inputs rev, n, proof, vk, tag, op
  const standalone = decodeScript(groth16StandaloneScript(g));
  assert.deepEqual(
    standalone.map((o) => o.data ?? o.op),
    [...[...g.inputs].reverse(), '05', g.proof, g.vk, '20', OP_ZK_PRECOMPILE],
  );
});

test('Succinct redeem pins image_id, control_id, hashfn, tag; unlock carries claim, index, digests, seal, journal', () => {
  const redeem = decodeScript(succinctRedeemScript(s));
  assert.deepEqual(
    redeem.map((o) => o.data ?? o.op),
    [s.imageId, s.controlId, s.hashfn, '21', OP_ZK_PRECOMPILE],
  );
  const unlock = decodeScript(succinctUnlockScript(s));
  assert.deepEqual(
    unlock.map((o) => o.data),
    [s.claim, s.controlIndex, s.controlDigests, s.seal, s.journal],
  );
  assert.equal(unlock[3].op, 0x4e, 'OpPushData4 for 222 KB seal (needs post-Toccata element limit)');
  // standalone matches R0Fields::script(): claim, idx, digests, seal, journal, image, control, hashfn, tag, op
  const standalone = decodeScript(succinctStandaloneScript(s));
  assert.deepEqual(
    standalone.map((o) => o.data ?? o.op),
    [s.claim, s.controlIndex, s.controlDigests, s.seal, s.journal, s.imageId, s.controlId, s.hashfn, '21', OP_ZK_PRECOMPILE],
  );
});

test('Succinct signature script fits the post-Toccata limits (250 KB sig script, 1 MB element)', () => {
  const sig = succinctSignatureScript(s);
  const bytes = sig.length / 2;
  assert.ok(bytes < MAX_SIGNATURE_SCRIPT_LEN_POST_TOCCATA, `${bytes} < 250000`);
  assert.ok(s.seal.length / 2 < MAX_SCRIPT_ELEMENT_SIZE_POST_TOCCATA);
  // but it is far beyond the pre-Toccata 10 KB cap: this spend only exists post-fork
  assert.ok(bytes > 10_000);
});

test('P2SH script public key is blake2b-256 of redeem, wrapped OpBlake2b <32> OpEqual', () => {
  const spk = p2shScriptPublicKey(groth16RedeemScript(g.vk));
  assert.equal(spk.version, 0);
  assert.equal(spk.script.length / 2, 35);
  assert.ok(spk.script.startsWith('aa20'), 'OpBlake2b, push 32');
  assert.ok(spk.script.endsWith('87'), 'OpEqual');
});

test('P2SH address is deterministic per redeem script and differs per network prefix', () => {
  const redeem = groth16RedeemScript(g.vk);
  const tn = p2shAddress(redeem, 'testnet-10');
  const mn = p2shAddress(redeem, 'mainnet');
  assert.ok(tn.startsWith('kaspatest:p'), tn);
  assert.ok(mn.startsWith('kaspa:p'), mn);
  assert.equal(tn, p2shAddress(redeem, 'testnet-10'));
  assert.equal(tn, 'kaspatest:ppnsz9gete7gqg7lcez3dm4gnk6pusrucpplywwv0sdf4gs44z5pqf9kxarug');
});

test('a different verifying key yields a different covenant address (program binding)', () => {
  const other = g.vk.slice(0, -2) + (g.vk.endsWith('8f') ? '8e' : '8f');
  assert.notEqual(p2shAddress(groth16RedeemScript(other)), p2shAddress(groth16RedeemScript(g.vk)));
});

test('tags are the engine values', () => {
  assert.equal(ZK_TAG.GROTH16, 0x20);
  assert.equal(ZK_TAG.R0_SUCCINCT, 0x21);
});

test('ZkScriptBuilder (2.1.0): commitToGroth16 yields the redeem before any proof; finalize reproduces it', async () => {
  const { kaspa } = await import('../src/sdk.js');
  const { readFileSync } = await import('node:fs');
  const img = readFileSync(new URL('../fixtures/r0-example/image_id.hex', import.meta.url), 'utf8').trim();
  const jh = readFileSync(new URL('../fixtures/r0-example/journal_hash.hex', import.meta.url), 'utf8').trim();
  const rcpt = readFileSync(new URL('../fixtures/r0-example/receipt.hex', import.meta.url), 'utf8').trim();
  const a = kaspa.ZkScriptBuilder.newR0({ flags: { covenantsEnabled: true } });
  a.commitToGroth16(img);
  const redeem = a.script();
  assert.equal(redeem.length / 2, 801);
  assert.ok(redeem.startsWith('20' + img), 'redeem begins by pushing the image id');
  const b = kaspa.ZkScriptBuilder.newR0({ flags: { covenantsEnabled: true } });
  b.commitToGroth16(img);
  const fin = b.finalizeWithGroth16Proof(rcpt, jh);
  assert.equal(fin.redeemScript, redeem);
  assert.ok(fin.sigScript.endsWith(redeem));
  assert.equal(fin.sigScript.length / 2, 967);
  assert.equal(p2shAddress(redeem, 'mainnet'), 'kaspa:prr6mc7myqn2umzt758qhv2gnvahrqapq0d5zwul4y5t55gexw55geyupwjud');
});
