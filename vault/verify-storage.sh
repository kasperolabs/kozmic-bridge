#!/usr/bin/env bash
# Reads deposits[N] straight out of the vault's storage and checks it against the public getter.
# This is the layout the eth-prover guest hardcodes (primitives/src/lib.rs vault_layout).
#
#   usage: ./verify-storage.sh <vault address> <nonce> [block]
#   RPC URL comes from ETH_RPC_URL or ../eth-rpc-url.txt (never printed).
set -euo pipefail
VAULT=${1:?vault address}
N=${2:?deposit nonce}
BLOCK=${3:-latest}
RPC=${ETH_RPC_URL:-$(cat "$(dirname "$0")/../eth-rpc-url.txt")}

KEY0=$(cast index uint256 "$N" 1)                       # keccak256(abi.encode(uint256(n), uint256(1)))
KEY1=$(python3 -c "print('0x%064x' % (int('$KEY0',16)+1))")   # word 1 is the next slot

echo "vault         : $VAULT"
echo "block         : $BLOCK"
echo "nonce (slot 0): $(cast storage "$VAULT" 0 --block "$BLOCK" --rpc-url "$RPC")"
echo "mapping base 1: $(cast storage "$VAULT" 1 --block "$BLOCK" --rpc-url "$RPC")   (expected all zero)"
echo "key0 (word 0) : $KEY0"
W0=$(cast storage "$VAULT" "$KEY0" --block "$BLOCK" --rpc-url "$RPC")
echo "word 0        : $W0"
echo "key1 (word 1) : $KEY1"
W1=$(cast storage "$VAULT" "$KEY1" --block "$BLOCK" --rpc-url "$RPC")
echo "word 1        : $W1"
python3 - "$W0" "$W1" <<'EOF'
import sys
w0 = int(sys.argv[1], 16); w1 = sys.argv[2][2:]
amount = w0 & ((1 << 64) - 1); version = (w0 >> 64) & 0xff; rest = w0 >> 72
print(f"decoded       : amount={amount} kaspaVersion={version} upper_bits_zero={rest == 0}")
print(f"kaspa_spk     : 0x{version:02x}{w1}")
EOF
echo "getter        : $(cast call "$VAULT" 'deposits(uint64)(uint64,uint8,bytes32)' "$N" --block "$BLOCK" --rpc-url "$RPC" | tr '\n' ' ')"
echo
echo "eth_getProof (what the prover feeds the guest), sizes only:"
cast rpc eth_getProof "$VAULT" "[\"$KEY0\",\"$KEY1\"]" "$( [ "$BLOCK" = latest ] && echo latest || cast to-hex "$BLOCK")" --rpc-url "$RPC" \
  | python3 -c '
import sys, json
p = json.load(sys.stdin)
print("  storageHash  :", p["storageHash"])
print("  accountProof :", len(p["accountProof"]), "nodes")
for s in p["storageProof"]:
    print("  slot", s["key"][:18] + "...", "value", s["value"], "proof", len(s["proof"]), "nodes")
'
