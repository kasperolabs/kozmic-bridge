#!/usr/bin/env bash
# Self-rescue, Ethereum -> Kaspa: prove the Ethereum finality update that covers a deposit and advance the Kaspa
# covenant, which mints the token to the address the deposit named. The covenant accepts a valid proof from anyone
# and takes no signature; the covenant's own KAS pool pays the network fee (up to its max_fee) and the KAS parked in
# each minted cell, so you need no KAS and no Kaspa key.
#
#   ETH_RPC_FILE=eth-rpc-url.txt BEACON=https://<beacon node with light-client endpoints> \
#   VAULT=0x... TOKEN=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 STATE=bridge-state.json STORE=eth-prover/stores/mainnet \
#   KASPA_URL=ws://127.0.0.1:17110 NONCES="12 13" ETH_PROVER_IMAGE=<kasperolabs/eth-prover@sha256:... from README.md> \
#   bash bin/prove-deposit.sh [OUT_DIR]
#
# STATE is the instance's current state file and STORE its light-client store directory (one file per finalized
# root, named 0x<root>.cbor). Both are public, deterministic data, and both are needed: after Gloas no beacon node
# serves a bootstrap for the covenant's header, so the store file for that header replaces it. docs/SELF-RESCUE.md
# says where Kaspero publishes them for the live instance.
# Needs: eth-prover built (`cargo build --release` in eth-prover), the bridge-v7 tool (`cargo build --release` in
# bridge-v7), Node 20 with `npm ci` at the repository root, Docker with the NVIDIA Container Toolkit.
#
# Status: assembled from the robot's exact commands; the flags were checked against the host CLI; not yet run end to
# end by someone outside Kaspero.
set -u
cd "$(dirname "$0")/.." || exit 1
: "${ETH_RPC_FILE:?}" "${BEACON:?}" "${VAULT:?}" "${TOKEN:?}" "${STATE:?}" "${STORE:?}" "${KASPA_URL:?}" "${NONCES:?}" "${ETH_PROVER_IMAGE:?set ETH_PROVER_IMAGE to the digest-pinned image named in README.md}"
OUT=${1:-eth-prover/out-rescue-$(date -u +%Y%m%dT%H%M%SZ)}; mkdir -p "$OUT"
EP=${ETH_PROVER_BIN:-eth-prover/target/release/eth-prover}
export BRIDGE_COVENANT_V5_BIN=${BRIDGE_COVENANT_V5_BIN:-bridge-v7/target/release/bridge-covenant}
DEPLOY=${DEPLOYMENT_JSON:-$(ls usdc/deployments/2-*.json 2>/dev/null | head -1)}
RPC=$(tr -d '\n' < "$ETH_RPC_FILE")
step() { echo; echo "== $*"; }

step "0. what the covenant pins: its current header (state file) and the inbound image id (deployment record)"
HEADER=$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['state']['header'])" "$STATE") || exit 1; HEADER=${HEADER#0x}
echo "header 0x$HEADER"
[[ -f $STORE/0x$HEADER.cbor ]] || { echo "no $STORE/0x$HEADER.cbor: without the store file for the covenant's header the fetch cannot start (post-Gloas). Get the store first."; exit 1; }
PINNED=${ETH_IMAGE_ID:-$(python3 -I - "$DEPLOY" <<'PY'
import json,re,sys
d=json.load(open(sys.argv[1])); hits=[]
def walk(o,p=''):
    if isinstance(o,dict):
        for k,v in o.items(): walk(v,p+'/'+k)
    elif isinstance(o,str) and re.fullmatch(r'(0x)?[0-9a-fA-F]{64}',o) and re.search(r'image',p,re.I) and re.search(r'inbound|eth|deposit',p,re.I): hits.append(o.lower().removeprefix('0x'))
walk(d)
print(hits[0] if hits else '')
PY
)}
[[ -n $PINNED ]] || { echo "could not find the inbound image id in $DEPLOY; pass ETH_IMAGE_ID=<64 hex>"; exit 1; }
echo "inbound image id $PINNED"
"$EP" ids | grep -qi "$PINNED" || { echo "$EP does not carry guest $PINNED; build eth-prover at this commit (its ids: $("$EP" ids | tr '\n' ' '))"; exit 1; }
# the fork schedule is part of the chain commitment: the Gloas epoch must be the one the covenant was built with
GLOAS=$(python3 -I -c "import json,sys; n=json.load(open('eth-net.json')).get('mainnet',{}); print(n.get('gloasEpoch',''))")
HELIOS=$(python3 -I -c "import json,sys; n=json.load(open('eth-net.json')).get('mainnet',{}); print(n.get('helios','mainnet'))")
G=(); [[ -n $GLOAS ]] && G=(--gloas-epoch "$GLOAS")

step "1. fetch: light-client updates from the beacon node and the deposits' storage proofs (the RPC URL is read from the file and not echoed)"
N=(); for n in $NONCES; do N+=(--nonce "$n"); done
"$EP" fetch --network "$HELIOS" "${G[@]}" --store-dir "$STORE" --consensus-rpc "$BEACON" --checkpoint "0x$HEADER" --execution-rpc "$RPC" \
      --vault "$VAULT" --token "$TOKEN" "${N[@]}" --out "$OUT/inputs.cbor" 2>&1 | sed "s#$RPC#<eth-rpc>#g" | tail -6 || exit 1
[[ -f $OUT/inputs.cbor ]] || { echo "fetch wrote no inputs.cbor"; exit 1; }

step "2. dev-mode execution: cycles, journal, and which nonces mint"
RISC0_DEV_MODE=1 "$EP" execute --inputs "$OUT/inputs.cbor" | tee "$OUT/execute.log" | grep -iE 'cycles|nonce|mint|skip|journal' || exit 1

step "3. the STARK on your GPU, the Groth16 wrap here"
docker run --rm --gpus all -v "$(cd "$OUT" && pwd)":/work "$ETH_PROVER_IMAGE" eth-prover prove --inputs /work/inputs.cbor --no-wrap --out /work | tee "$OUT/prove.log" | grep -iE 'proved|cycles|NVIDIA' || exit 1
"$EP" wrap --receipt "$OUT/receipt.succinct.bin" --out "$OUT" | tail -2 || exit 1
IMAGE_ID=$(tr -d '\n' < "$OUT/image_id.hex")
[[ $IMAGE_ID == "$PINNED" ]] || { echo "the GPU proved image $IMAGE_ID; the covenant pins $PINNED (wrong ETH_PROVER_IMAGE?)"; exit 1; }
"$EP" journal --file "$OUT/journal.hex"

step "4. advance the covenant on Kaspa: the driver builds the transaction, runs it through the real 2.1.0 script engine, then sends it"
node bin/bridge-v5.mjs advance --bundle "$OUT" --url "$KASPA_URL" --state "$STATE" || exit 1
echo "done. The minted cells are in the recipients' wallets. The state file now carries the new header and the store has its file;"
echo "keep both: the next proof starts from them. (A robot still holding the old state file sees 'input not found' and stops; it"
echo "needs your new state file to continue, which is why a rescuer should publish it where they found the old one.)"
