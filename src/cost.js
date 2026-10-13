// Cost model transcribed from rusty-kaspa v2.0.0 / v2.1.0:
//   consensus/core/src/mass/units.rs, consensus/core/src/mass/mod.rs,
//   consensus/core/src/config/params.rs (MAINNET_PARAMS / TESTNET_PARAMS),
//   crypto/txscript/src/zk_precompiles/tags.rs, .../groth16/mod.rs,
//   crypto/txscript/src/lib.rs (script size limits).
// Every constant below is checked against the Rust tests in test/cost.test.js.

export const SCRIPT_UNITS_PER_GRAM = 100n;
export const GRAMS_PER_COMPUTE_BUDGET_UNIT = 100n;
export const SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT = GRAMS_PER_COMPUTE_BUDGET_UNIT * SCRIPT_UNITS_PER_GRAM; // 10_000
export const FREE_SCRIPT_UNITS_PER_INPUT = SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT - 1n; // 9_999
export const MAX_COMPUTE_BUDGET = 65535n; // u16

// ZkTag::cost(), in grams
export const ZK_TAG_COST_GRAMS = Object.freeze({
  0x20: 1000n * 140n, // Groth16
  0x21: 1000n * 250n, // RISC Zero Succinct
});
export const ZK_TAG_MAX_COST_GRAMS = 1000n * 250n;

// groth16/mod.rs: charged per gamma_abc_g1 element (= public_inputs + 1)
export const GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS = 250_000n;

// opcodes/mod.rs HashOpcodePricing (units per byte)
export const HASH_UNITS_PER_BYTE = Object.freeze({ blake2b: 2n, blake3: 1n, sha256: 1n });

// Network params (identical on mainnet and testnet-10)
export const MASS_PER_TX_BYTE = 1n;
export const MASS_PER_SCRIPT_PUB_KEY_BYTE = 10n;
export const TRANSIENT_BYTE_TO_MASS_FACTOR = 4n;
export const BLOCK_COMPUTE_MASS_LIMIT = 500_000n;
export const BLOCK_TRANSIENT_MASS_LIMIT_POST_TOCCATA = 1_000_000n;
export const MAX_SIGNATURE_SCRIPT_LEN_POST_TOCCATA = 250_000;
export const MAX_SCRIPT_ELEMENT_SIZE_POST_TOCCATA = 1_000_000;
export const MAX_SCRIPTS_SIZE_POST_TOCCATA = 1_000_000;
// consensus/core/src/constants.rs: STORAGE_MASS_PARAMETER = SOMPI_PER_KASPA * 10_000
export const STORAGE_MASS_PARAMETER = 100_000_000n * 10_000n;

export function zkTagCostUnits(tag) {
  const grams = ZK_TAG_COST_GRAMS[tag];
  if (grams === undefined) return ZK_TAG_MAX_COST_GRAMS * SCRIPT_UNITS_PER_GRAM;
  return grams * SCRIPT_UNITS_PER_GRAM;
}

/** Script units the Groth16 precompile charges for a VK with n public inputs. */
export function groth16VkUnits(nInputs) {
  return BigInt(nInputs + 1) * GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS;
}

/**
 * Conservative script-unit estimate for a P2SH ZK spend. Literal pushes are
 * free; the big costs are the precompile and (for Groth16) the VK elements.
 * We add 2 units/byte of redeem script as headroom for the P2SH hash check.
 */
export function estimateSpendScriptUnits({ tag, nInputs = 0, redeemLen = 0 }) {
  let units = zkTagCostUnits(tag);
  if (tag === 0x20) units += groth16VkUnits(nInputs);
  units += BigInt(redeemLen) * HASH_UNITS_PER_BYTE.blake2b;
  return units;
}

/** ComputeBudget::checked_covering_script_units, returns null on u16 overflow. */
export function coveringComputeBudget(requiredUnits) {
  const charged = requiredUnits > FREE_SCRIPT_UNITS_PER_INPUT ? requiredUnits - FREE_SCRIPT_UNITS_PER_INPUT : 0n;
  const budget = (charged + SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT - 1n) / SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT;
  return budget > MAX_COMPUTE_BUDGET ? null : budget;
}

/** ComputeCommit::from(ComputeBudget(b)).allowed_script_units() */
export function allowedScriptUnits(budget) {
  return BigInt(budget) * SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT + FREE_SCRIPT_UNITS_PER_INPUT;
}

/** Suggested budget with a safety margin (over-budgeting only costs fee). */
/** Measured on mainnet 2026-10-11: 5-input Groth16 P2SH spend used 15,500,893 units => budget 1550 (txid e1ee1814...). */
export const MEASURED_GROTH16_5IN_P2SH_UNITS = 15_500_893n;

export function suggestedComputeBudget(params, marginPct = 1) {
  const units = estimateSpendScriptUnits(params);
  const padded = units + (units * BigInt(marginPct)) / 100n;
  return coveringComputeBudget(padded);
}

/** calc_non_contextual_masses for a v1 tx, given serialized size and total SPK bytes (2 + script len each). */
export function computeMassGrams({ serializedSize, totalSpkBytes, computeBudgets }) {
  const budget = computeBudgets.reduce((a, b) => a + BigInt(b), 0n);
  return BigInt(serializedSize) * MASS_PER_TX_BYTE + BigInt(totalSpkBytes) * MASS_PER_SCRIPT_PUB_KEY_BYTE + budget * GRAMS_PER_COMPUTE_BUDGET_UNIT;
}

export function transientMassGrams(serializedSize) {
  return BigInt(serializedSize) * TRANSIENT_BYTE_TO_MASS_FACTOR;
}

/** tags.rs test: how many verifies of this tag fit in one block's compute limit. */
export function verifiesPerBlock(tag) {
  return BLOCK_COMPUTE_MASS_LIMIT / ZK_TAG_COST_GRAMS[tag];
}

// ---------- consensus serialized-size + fee (consensus/core/src/mass/mod.rs, mining config) ----------

export const HASH_SIZE = 32n;
export const SUBNETWORK_ID_SIZE = 20n;
/** mempool: DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE = 100_000 sompi per kg => 100 sompi/gram */
export const MINIMUM_RELAY_FEE_SOMPI_PER_KG = 100_000n;

/** transaction_estimated_serialized_size for a plain (non-covenant-output) tx description. */
export function estimatedSerializedSize({ version, inputs, outputs, payloadLen = 0 }) {
  let size = 2n + 8n; // version + input count
  for (const i of inputs) {
    size += HASH_SIZE + 4n; // outpoint
    size += 8n + BigInt(i.signatureScriptLen); // sig script len + bytes
    size += 8n; // sequence
    if (version >= 1) size += 2n; // compute_budget
  }
  size += 8n; // output count
  for (const o of outputs) {
    size += 8n + 2n + 8n + BigInt(o.scriptLen);
    if (o.covenant) size += 2n + HASH_SIZE;
  }
  size += 8n + SUBNETWORK_ID_SIZE + 8n + HASH_SIZE; // lock time, subnetwork, gas, payload hash
  size += 8n + BigInt(payloadLen);
  return size;
}

/** Full non-contextual masses for a v1 ZK spend description (ignores storage mass, which depends on values). */
export function spendMasses(desc) {
  const size = estimatedSerializedSize(desc);
  const totalSpkBytes = desc.outputs.reduce((a, o) => a + 2n + BigInt(o.scriptLen), 0n);
  const compute = computeMassGrams({ serializedSize: size, totalSpkBytes, computeBudgets: desc.inputs.map((i) => i.computeBudget) });
  const transient = transientMassGrams(size);
  return { size, compute, transient };
}

export function minimumRelayFeeSompi(massGrams) {
  return (massGrams * MINIMUM_RELAY_FEE_SOMPI_PER_KG) / 1000n;
}

/**
 * mempool check_transaction_standard: fee_mass = max(compute, normalized_transient) where
 * normalized_transient = ceil(transient * compute_limit / transient_limit) = ceil(transient * 0.5).
 */
export function feeMassGrams({ compute, transient }) {
  const normalized = (transient * BLOCK_COMPUTE_MASS_LIMIT + BLOCK_TRANSIENT_MASS_LIMIT_POST_TOCCATA - 1n) / BLOCK_TRANSIENT_MASS_LIMIT_POST_TOCCATA;
  return compute > normalized ? compute : normalized;
}

// ---------- KIP-9 storage mass (consensus/core/src/mass/mod.rs: utxo_plurality, calc_storage_mass) ----------

/**
 * utxo_plurality: how many 100-byte storage units a UTXO occupies. 63 fixed bytes + script
 * length (+ 32 for a covenant id). Standard P2PK/P2SH outputs: 1; covenant outputs: 2.
 */
export function utxoPlurality(scriptLen, hasCovenant) {
  const UTXO_CONST_STORAGE = 32 + 4 + 8 + 8 + 1 + 2 + 8;
  return BigInt(Math.ceil((UTXO_CONST_STORAGE + scriptLen + (hasCovenant ? 32 : 0)) / 100));
}

/**
 * calc_storage_mass: cells are { amount: bigint sompi, plurality: bigint }.
 *   harmonic_outs = sum C * p^2 / amount over outputs
 *   relaxed (|O| = 1, or |I| = 1, or |O| = |I| = 2, pluralities counted): subtract the inputs' harmonic sum
 *   otherwise: subtract |I| * (C / mean input amount)
 */
export function storageMassGrams(inputs, outputs) {
  const C = STORAGE_MASS_PARAMETER;
  let outsPlurality = 0n, harmonicOuts = 0n;
  for (const o of outputs) {
    outsPlurality += o.plurality;
    harmonicOuts += (C * o.plurality * o.plurality) / o.amount;
  }
  const insPlurality = inputs.reduce((a, i) => a + i.plurality, 0n);
  const relaxed = outsPlurality === 1n || (inputs.length <= 2 && (insPlurality === 1n || (outsPlurality === 2n && insPlurality === 2n)));
  if (relaxed) {
    const harmonicIns = inputs.reduce((a, i) => a + (C * i.plurality * i.plurality) / i.amount, 0n);
    return harmonicOuts > harmonicIns ? harmonicOuts - harmonicIns : 0n;
  }
  const sumIns = inputs.reduce((a, i) => a + i.amount, 0n);
  let meanIns = sumIns / insPlurality;
  if (meanIns < 1n) meanIns = 1n;
  const arithmeticIns = insPlurality * (C / meanIns);
  return harmonicOuts > arithmeticIns ? harmonicOuts - arithmeticIns : 0n;
}
