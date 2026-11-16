#!/usr/bin/env bash
# Self-rescue, Ethereum -> Kaspa: prove the Ethereum finality update that covers a deposit and advance the Kaspa
# covenant, which mints the token to the address the deposit named. The covenant accepts a valid proof from anyone;
# the Kaspa fees (about 0.5 KAS per advance, 1 KAS parked per minted cell) come from the key you pass.
#
#   ETH_RPC_FILE=eth-rpc-url.txt BEACON=https://<beacon node with light-client endpoints> VAULT=0x... TOKEN=0x<USDC> \
#   STATE=bridge-state.json STORE=eth-prover/stores/mainnet KASPA_URL=ws://127.0.0.1:17110 KAS_KEY=kas-key.json \
#   NONCES="12 13"  bash bin/prove-deposit.sh [OUT_DIR]
#
# STATE is the instance's current state file and STORE its light-client store (one file per finalized root). Both
# are public data; Kaspero publishes them for the live instance (docs/SELF-RESCUE.md says where). Without the store
# file of the covenant's current header no beacon node can serve a bootstrap for it (post-Gloas), so get both first.
# Needs: eth-prover built (`cargo build --release` in eth-prover, see its README), Node 20 for the driver, Docker
# with the NVIDIA Container Toolkit, the bridge-v7 tool (`cargo build --release` in bridge-v7).
set -u
cd "$(dirname "$0")/.." || exit 1
: "${ETH_RPC_FILE:?}" "${BEACON:?}" "${VAULT:?}" "${TOKEN:?}" "${STATE:?}" "${STORE:?}" "${KASPA_URL:?}" "${KAS_KEY:?}" "${NONCES:?}"
OUT=${1:-eth-prover/out-rescue-$(date -u +%Y%m%dT%H%M%SZ)}; mkdir -p "$OUT"
EP=${ETH_PROVER_BIN:-eth-prover/target/release/eth-prover}
IMAGE=${ETH_PROVER_IMAGE:?set ETH_PROVER_IMAGE to the digest-pinned kasperolabs/eth-prover image named in README.md}
PINNED_IMAGE_ID=c320da505b41ffb3336a5bd4d995ead15590b75f4cb4b1ae3fa25353bacb955c
export BRIDGE_COVENANT_V5_BIN=${BRIDGE_COVENANT_V5_BIN:-bridge-v7/target/release/bridge-covenant}
step() { echo; echo "== $*"; }

step "0. the covenant's current header (from the state file; the proof must start exactly there)"
HEADER=$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['state']['header'])" "$STATE") || exit 1
echo "header 0x$HEADER"; [[ -f $STORE/$HEADER.bin || -n $(ls "$STORE" 2>/dev/null | grep -i "$HEADER") ]] || echo "warning: no store file for this header in $STORE; fetch will try a bootstrap and may fail"
"$EP" ids | grep -i "${PINNED_IMAGE_ID:0:16}" >/dev/null || { echo "$EP is not the pinned guest $PINNED_IMAGE_ID; build eth-prover at this commit"; exit 1; }

step "1. fetch: light-client updates from the beacon node and the deposits' storage proofs (the RPC URL is read from the file, never shown)"
N=(); for n in $NONCES; do N+=(--nonce "$n"); done
"$EP" fetch --network mainnet --consensus-rpc "$BEACON" --checkpoint "0x$HEADER" --execution-rpc "$ETH_RPC_FILE" --vault "$VAULT" --token "$TOKEN" "${N[@]}" --store "$STORE" --out "$OUT" 2>&1 | grep -vi 'http' | tail -5 || exit 1

step "2. dev-mode execution: cycles, journal, and which nonces mint"
RISC0_DEV_MODE=1 "$EP" execute --inputs "$OUT/inputs.cbor" | tee "$OUT/execute.log" | grep -iE 'cycles|nonce|mint|skip|journal' || exit 1

step "3. the STARK on your GPU, the Groth16 wrap here"
docker run --rm --gpus all -v "$(cd "$OUT" && pwd)":/work "$IMAGE" eth-prover prove --inputs /work/inputs.cbor --no-wrap --out /work | tee "$OUT/prove.log" | grep -iE 'proved|cycles|NVIDIA' || exit 1
"$EP" wrap --receipt "$OUT/receipt.succinct.bin" --out "$OUT" | tail -2 || exit 1
IMAGE_ID=$(tr -d '\n' < "$OUT/image_id.hex")
[[ $IMAGE_ID == "$PINNED_IMAGE_ID" ]] || { echo "the GPU proved image $IMAGE_ID; the covenant pins $PINNED_IMAGE_ID"; exit 1; }
"$EP" journal --file "$OUT/journal.hex"

step "4. advance the covenant on Kaspa: the driver builds the transaction, runs it through the real 2.1.0 script engine, then sends it"
node bin/bridge-v5.mjs advance --bundle "$OUT" --url "$KASPA_URL" --state "$STATE" --key "$KAS_KEY" || exit 1
echo "done. The minted cells are in the recipients' wallets; the state file now carries the new header (keep it: the next proof starts there)."
