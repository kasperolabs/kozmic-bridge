#!/usr/bin/env bash
# Self-rescue, Kaspa -> Ethereum: prove one burn of the bridge token yourself and submit the proof to the relay.
# This is what Kaspero's robot does, as six commands, with your own GPU. The relay pays the exit to the Ethereum
# address the burn named; the proof's tip goes to the address you pass as PROVER. No Kaspero service is involved.
#
#   KASPA_URL=ws://127.0.0.1:17110 TXID=<burn txid> START=<a block hash at or before the burn's block> \
#   RELAY=0x... TOKEN=<token covenant id, 64 hex> PROVER=0x<your eth address> ETH_RPC_FILE=eth-rpc-url.txt \
#   ETH_KEY_FILE=eth-key.txt  bash bin/prove-exit.sh [OUT_DIR]
#
# Needs: a Kaspa node (rusty-kaspa 2.1.0+, wRPC Borsh, --utxoindex); the host binaries built
# (`cargo build --release` in outbound/burnwitness and outbound/kaspa-prover, see their READMEs); Docker with the
# NVIDIA Container Toolkit (24 GB VRAM recommended; a 600-attester exit is about 700M cycles, 15 to 25 min on an RTX 4090);
# foundry's `cast`; an Ethereum RPC URL in ETH_RPC_FILE and the private key of an account with a little ETH in
# ETH_KEY_FILE (chmod 600 both; nothing here prints them).
set -u
cd "$(dirname "$0")/.." || exit 1
: "${KASPA_URL:?}" "${TXID:?}" "${START:?}" "${RELAY:?}" "${TOKEN:?}" "${PROVER:?}" "${ETH_RPC_FILE:?}" "${ETH_KEY_FILE:?}"
OUT=${1:-outbound/kaspa-prover/out-rescue-$(date -u +%Y%m%dT%H%M%SZ)}; mkdir -p "$OUT"
BW=${BURNWITNESS_BIN:-outbound/burnwitness/target/release/burnwitness}
KP=${KASPA_PROVER_BIN:-outbound/kaspa-prover/target/release/kaspa-prover}
IMAGE=${KASPA_PROVER_IMAGE:-kasperolabs/kaspa-prover@sha256:d034995ff605ecceb535eb86b43a1101f298c54eb92a7ff77b8983ba4e159f92}
PINNED_IMAGE_ID=c61fd96588598d7f9b2a16aae765932ea3648177f42ddb167370f18f7d9a97f2
LEVELS=${LEVELS:-30}
RPC=$(tr -d '\n' < "$ETH_RPC_FILE")
c() { cast "$@" --rpc-url "$RPC"; }
step() { echo; echo "== $*"; }

step "0. the relay's rule (read from the contract, never typed)"
FLOOR=$(c call "$RELAY" 'FLOOR()(uint32)'); UNIT=$(c call "$RELAY" 'ATTEST_UNIT()(uint64)'); IMG=$(c call "$RELAY" 'IMAGE_ID()(bytes32)')
TOK=$(c call "$RELAY" 'TOKEN_COV_ID()(bytes32)'); CMP=$(c call "$RELAY" 'CMP_LEVEL()(uint8)')
echo "floor $FLOOR  attest unit $UNIT  cmp level $CMP  image $IMG"
[[ ${IMG#0x} == "$PINNED_IMAGE_ID" ]] || { echo "the relay pins image ${IMG#0x}; this script knows $PINNED_IMAGE_ID. Check the README, do not continue."; exit 1; }
[[ ${TOK#0x} == "${TOKEN#0x}" ]] || { echo "the relay pins token ${TOK#0x}, you passed $TOKEN"; exit 1; }
[[ ${LEVELS##*,} == "$CMP" ]] || { echo "LEVELS must end with the relay's CMP_LEVEL $CMP"; exit 1; }
# how many attesting superblocks the relay wants: max(floor, amount/unit), plus the time term it adds while you prove.
# Start with the floor plus 10 percent; if step 5's free call says "not enough attestation", rerun with NEEDED larger.
NEEDED=${NEEDED:-$(( FLOOR + FLOOR / 10 ))}; DEPTH=$(( NEEDED * 62 * 13 / 10 ))   # ~62 DAA per level-30 superblock on mainnet
echo "asking burnwitness for $NEEDED attesting superblocks after your burn's block, about $DEPTH DAA (~$(( DEPTH / 600 )) min of chain)"

step "1. burnwitness: the headers and the attestation ladder (fails with 'DAA to go' if the chain is not deep enough yet; wait and rerun)"
"$BW" --url "$KASPA_URL" --txid "$TXID" --start "$START" --token "${TOKEN#0x}" --levels "$LEVELS" --min-attest "$NEEDED" --min-count "$NEEDED" \
      --depth-daa "$DEPTH" --extra-nonchain 3 --out "$OUT/witness.json" || exit 1

step "2. the guest input frame, every intermediate checked against your node"
"$KP" relay --witness "$OUT/witness.json" --prover "$PROVER" --native-only --out-input "$OUT/relay-input.bin" || exit 1

step "3. dev-mode execution: cycles and the journal the GPU must reproduce (no proof yet)"
mkdir -p "$OUT/devexec"
RISC0_DEV_MODE=1 "$KP" prove --input "$OUT/relay-input.bin" --no-wrap --out "$OUT/devexec" | tee "$OUT/execute.log" | grep -E 'cycles|journal|level' || exit 1

step "4. the STARK on your GPU (docker, image pinned by digest), then the Groth16 wrap and the verify on this machine"
docker run --rm --gpus all -v "$(cd "$OUT" && pwd)":/work "$IMAGE" kaspa-prover prove --input /work/relay-input.bin --no-wrap --out /work | tee "$OUT/prove.log" | grep -E 'proved in|journal|NVIDIA' || exit 1
"$KP" wrap --receipt "$OUT/receipt.succinct.bin" --out "$OUT" | tail -2 || exit 1
IMAGE_ID=$(tr -d '\n' < "$OUT/image_id.hex")
[[ $IMAGE_ID == "$PINNED_IMAGE_ID" ]] || { echo "the GPU proved image $IMAGE_ID, the relay pins $PINNED_IMAGE_ID (wrong docker image?)"; exit 1; }
cmp -s "$OUT/journal.hex" "$OUT/devexec/journal.hex" || { echo "the GPU's journal differs from the dev-mode journal"; exit 1; }
"$KP" verify --bundle "$OUT" --image-id "$IMAGE_ID" | tail -2 || exit 1

step "5. submit: a free call first (the revert reason tells you what to fix), then the transaction"
J=$(tr -d '\n' < "$OUT/journal.hex"); J=${J#0x}
ANCHOR=$(( 16#${J:498:16} ))                                   # KZO6 journal: anchor block number at byte 249
RLP=$(c block "$ANCHOR" --raw); SEAL=0x$(tr -d '\n' < "$OUT/eth-seal.hex"); SEAL=${SEAL/0x0x/0x}
echo "beacon: Ethereum block $ANCHOR"
if ! c call "$RELAY" 'submit(bytes,bytes,bytes)' "$SEAL" "0x$J" "$RLP" --from "$PROVER" > "$OUT/submit-call.log" 2>&1; then
  echo "the relay would refuse this proof:"; grep -oE 'revert[^\n]*|execution reverted[^\n]*' "$OUT/submit-call.log" | head -2
  echo "  'not enough attestation' -> rerun with NEEDED=$(( NEEDED + NEEDED / 4 )) (deeper ladder)"
  echo "  'already settled'        -> someone else proved it; your exit is paid, nothing to do"
  echo "  'history window'         -> the burn's Ethereum beacon is too old (about 27 h); see docs/SELF-RESCUE.md, rescue burn"
  exit 1
fi
read -r -p "the free call succeeds. Send the transaction from the key in $ETH_KEY_FILE? [y/N] " yn; [[ $yn == y ]] || exit 0
cast send "$RELAY" 'submit(bytes,bytes,bytes)' "$SEAL" "0x$J" "$RLP" --rpc-url "$RPC" --private-key "$(tr -d '\n' < "$ETH_KEY_FILE")" --gas-limit 800000 | grep -E 'transactionHash|status|blockNumber'
echo "done. The relay has paid the exit to the burn's recipient (less the fee) and recorded the tip for $PROVER; claim it with:"
echo "  cast send $RELAY 'claim()' --rpc-url <rpc> --private-key <key>"
