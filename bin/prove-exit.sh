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
# NVIDIA Container Toolkit (24 GB VRAM recommended; a 600-attester exit is about 700M cycles, 15 to 25 min on an
# RTX 4090); foundry's `cast`; an Ethereum RPC URL in ETH_RPC_FILE and the private key of an account with a little
# ETH in ETH_KEY_FILE (chmod 600 both; nothing here prints them).
#
# Status: assembled from the robot's exact commands; the flags were checked against the host CLIs; not yet run end
# to end by someone outside Kaspero. If you are that someone, open an issue with what you hit.
set -u
cd "$(dirname "$0")/.." || exit 1
: "${KASPA_URL:?}" "${TXID:?}" "${START:?}" "${RELAY:?}" "${TOKEN:?}" "${PROVER:?}" "${ETH_RPC_FILE:?}" "${ETH_KEY_FILE:?}"
OUT=${1:-outbound/kaspa-prover/out-rescue-$(date -u +%Y%m%dT%H%M%SZ)}; mkdir -p "$OUT"
BW=${BURNWITNESS_BIN:-outbound/burnwitness/target/release/burnwitness}
KP=${KASPA_PROVER_BIN:-outbound/kaspa-prover/target/release/kaspa-prover}
IMAGE=${KASPA_PROVER_IMAGE:-kasperolabs/kaspa-prover@sha256:d034995ff605ecceb535eb86b43a1101f298c54eb92a7ff77b8983ba4e159f92}
LEVELS=${LEVELS:-30}
RPC=$(tr -d '\n' < "$ETH_RPC_FILE")
c() { cast "$@" --rpc-url "$RPC"; }
step() { echo; echo "== $*"; }
TOKEN=${TOKEN#0x}

step "0. the relay's rule, read from the contract (the relay is the authority on the image id; nothing is pinned here)"
FLOOR=$(c call "$RELAY" 'FLOOR()(uint32)'); UNIT=$(c call "$RELAY" 'ATTEST_UNIT()(uint64)'); IMG=$(c call "$RELAY" 'IMAGE_ID()(bytes32)')
TOK=$(c call "$RELAY" 'TOKEN_COV_ID()(bytes32)'); CMP=$(c call "$RELAY" 'CMP_LEVEL()(uint8)'); MINB=$(c call "$RELAY" 'MIN_BURN()(uint64)')
IMG=${IMG#0x}
echo "floor $FLOOR  attest unit $UNIT  min burn $MINB  cmp level $CMP  image $IMG"
[[ ${TOK#0x} == "$TOKEN" ]] || { echo "the relay pins token ${TOK#0x}, you passed $TOKEN"; exit 1; }
[[ ${LEVELS##*,} == "$CMP" ]] || { echo "LEVELS must end with the relay's CMP_LEVEL $CMP"; exit 1; }

# The relay wants attesting >= max(FLOOR, alpha x r x tau, amount / ATTEST_UNIT). The amount is known once the witness
# is built, so: ask for FLOOR plus 10 percent, read the amount from the witness, and rebuild once if the amount term is
# larger. The time term grows while you prove; if the free call in step 5 says "not enough attestation", rerun with
# NEEDED=<the number it suggests>.
NEEDED=${NEEDED:-$(( FLOOR + FLOOR / 10 ))}
witness() {
  local need=$1 depth=$(( $1 * 62 * 13 / 10 ))   # ~62 DAA per level-30 superblock on mainnet
  echo "asking burnwitness for $need attesting superblocks after your burn's block, about $depth DAA (~$(( depth / 600 )) min of chain)"
  "$BW" --url "$KASPA_URL" --txid "$TXID" --start "$START" --token "$TOKEN" --levels "$LEVELS" --min-attest "$need" --min-count "$need" \
        --depth-daa "$depth" --extra-nonchain 3 --out "$OUT/witness.json"
}
step "1. burnwitness: the headers and the attestation ladder (fails with 'DAA to go' if the chain is not deep enough yet; wait and rerun)"
witness "$NEEDED" || exit 1
AMOUNT=$(python3 -I -c 'import json,sys; w=json.load(open(sys.argv[1])); print(sum(int(c["amount"]) for b in w["burns"] for c in b.get("cells",[])))' "$OUT/witness.json")
BY_AMOUNT=$(( (AMOUNT + UNIT - 1) / UNIT ))
echo "burn amount $AMOUNT units (6 decimals): the amount term wants $BY_AMOUNT attesters"
(( AMOUNT >= MINB )) || { echo "this burn is below MIN_BURN ($MINB units); the relay will never pay it. Stop."; exit 1; }
if (( BY_AMOUNT > NEEDED )); then NEEDED=$(( BY_AMOUNT + BY_AMOUNT / 10 )); step "1b. the amount term is larger: rebuilding the witness for $NEEDED"; witness "$NEEDED" || exit 1; fi

step "2. the guest input frame, every intermediate checked against your node"
"$KP" relay --witness "$OUT/witness.json" --prover "$PROVER" --native-only --out-input "$OUT/relay-input.bin" || exit 1

step "3. dev-mode execution: cycles and the journal the GPU must reproduce (no proof yet)"
mkdir -p "$OUT/devexec"
RISC0_DEV_MODE=1 "$KP" prove --input "$OUT/relay-input.bin" --no-wrap --out "$OUT/devexec" | tee "$OUT/execute.log" | grep -E 'cycles|journal|level' || exit 1

step "4. the STARK on your GPU (docker, image pinned by digest), then the Groth16 wrap and the verify on this machine"
docker run --rm --gpus all -v "$(cd "$OUT" && pwd)":/work "$IMAGE" kaspa-prover prove --input /work/relay-input.bin --no-wrap --out /work | tee "$OUT/prove.log" | grep -E 'proved in|journal|NVIDIA' || exit 1
"$KP" wrap --receipt "$OUT/receipt.succinct.bin" --out "$OUT" | tail -2 || exit 1
IMAGE_ID=$(tr -d '\n' < "$OUT/image_id.hex")
[[ $IMAGE_ID == "$IMG" ]] || { echo "the GPU proved image $IMAGE_ID, the relay pins $IMG (wrong docker image? set KASPA_PROVER_IMAGE to the digest in README.md)"; exit 1; }
cmp -s "$OUT/journal.hex" "$OUT/devexec/journal.hex" || { echo "the GPU's journal differs from the dev-mode journal"; exit 1; }
"$KP" verify --bundle "$OUT" --image-id "$IMAGE_ID" | tail -2 || exit 1

step "5. submit: a free call first (the revert reason tells you what to fix), then the transaction"
J=$(tr -d '\n' < "$OUT/journal.hex"); J=${J#0x}
ANCHOR=$(( 16#${J:498:16} ))                                   # KZO6 journal: anchor block number at byte 249
RLP=$(c block "$ANCHOR" --raw); SEAL=$(tr -d '\n' < "$OUT/eth-seal.hex"); SEAL=0x${SEAL#0x}
echo "beacon: Ethereum block $ANCHOR"
if ! c call "$RELAY" 'submit(bytes,bytes,bytes)' "$SEAL" "0x$J" "$RLP" --from "$PROVER" > "$OUT/submit-call.log" 2>&1; then
  echo "the relay would refuse this proof:"; grep -oE 'revert[^\n]*|execution reverted[^\n]*|relay: [^"]*' "$OUT/submit-call.log" | head -2
  echo "  'not enough attestation' -> rerun with NEEDED=$(( NEEDED + NEEDED / 4 )) (deeper ladder; waiting alone never helps)"
  echo "  'journal already settled' or, after submit, settled() true -> someone else proved it; the exit is paid"
  echo "  'outside Ethereum's history window' -> the burn's beacon is older than about 27 h; see docs/SELF-RESCUE.md, rescue burn"
  exit 1
fi
read -r -p "the free call succeeds. Send the transaction from the key in $ETH_KEY_FILE? [y/N] " yn; [[ $yn == y ]] || exit 0
cast send "$RELAY" 'submit(bytes,bytes,bytes)' "$SEAL" "0x$J" "$RLP" --rpc-url "$RPC" --private-key "$(tr -d '\n' < "$ETH_KEY_FILE")" --gas-limit 800000 | grep -E 'transactionHash|status|blockNumber'
echo "done. The relay pays the burn's recipient in installments as the bucket allows (the first one in this transaction) and pays"
echo "the tip share of each installment to $PROVER. If an installment was deferred, anyone can call the next one later:"
echo "  cast send $RELAY 'claim(bytes32)' 0x${TXID#0x} --rpc-url <rpc> --private-key <key>"
