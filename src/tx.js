// Transaction v1 (Toccata) construction for a P2SH ZK spend.
// v1 inputs carry a compute_budget (u16) instead of sig_op_count; the engine
// allows budget*10_000 + 9_999 script units for that input, and the tx pays
// budget*100 grams of compute mass for it.
//
// NOTE: the SDK's calculateTransactionMass() is a wallet-side estimator that
// does not yet model v1 compute budgets (wallet/core/src/tx/mass.rs has a
// literal "TODO: Add support for v1 transactions"). We compute consensus
// masses ourselves in cost.js and only use the SDK for construction/serialization.
import { Transaction } from './sdk.js';
import { p2shScriptPublicKey } from './zk-scripts.js';
import { spendMasses, minimumRelayFeeSompi, suggestedComputeBudget, feeMassGrams } from './cost.js';

export const SUBNETWORK_NATIVE = '0000000000000000000000000000000000000000';
export const TX_VERSION_TOCCATA = 1;

/** Plan the spend: budget, masses, and minimum fee, before touching the SDK. */
export function planZkSpend({ tag, nInputs = 0, redeemHex, signatureScriptHex, toScriptHex, marginPct = 1 }) {
  const redeemLen = redeemHex.length / 2;
  const computeBudget = suggestedComputeBudget({ tag, nInputs, redeemLen }, marginPct); // measured floor on mainnet for 5-input Groth16 P2SH: 1550
  if (computeBudget === null) throw new RangeError('required script units exceed u16 compute budget');
  const masses = spendMasses({
    version: TX_VERSION_TOCCATA,
    inputs: [{ signatureScriptLen: signatureScriptHex.length / 2, computeBudget }],
    outputs: [{ scriptLen: toScriptHex.length / 2 }],
  });
  return { computeBudget: Number(computeBudget), masses, feeMass: feeMassGrams(masses), minFeeSompi: minimumRelayFeeSompi(feeMassGrams(masses)) };
}

/**
 * Build the proof-unlocked v1 spend of a P2SH ZK UTXO. No key signature is
 * involved: the "signature" is the proof + public inputs + redeem script.
 */
export function buildZkSpend({ prevTxId, prevIndex, prevAmount, redeemHex, signatureScript, computeBudget, toScriptHex, fee }) {
  if (computeBudget < 0 || computeBudget > 0xffff) throw new RangeError('computeBudget must fit u16');
  const value = BigInt(prevAmount) - BigInt(fee);
  if (value <= 0n) throw new RangeError('fee exceeds input amount');
  const spk = p2shScriptPublicKey(redeemHex);
  return new Transaction({
    version: TX_VERSION_TOCCATA,
    inputs: [
      {
        previousOutpoint: { transactionId: prevTxId, index: prevIndex },
        signatureScript,
        sequence: 0n,
        sigOpCount: 0,
        computeBudget,
        utxo: {
          outpoint: { transactionId: prevTxId, index: prevIndex },
          amount: BigInt(prevAmount),
          scriptPublicKey: { version: spk.version, script: spk.script },
          blockDaaScore: 0n,
          isCoinbase: false,
        },
      },
    ],
    outputs: [{ value, scriptPublicKey: { version: 0, script: toScriptHex } }],
    lockTime: 0n,
    subnetworkId: SUBNETWORK_NATIVE,
    gas: 0n,
    payload: '',
  });
}
