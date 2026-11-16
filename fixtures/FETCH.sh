#!/usr/bin/env bash
# Download the large test fixtures (release assets, not in git) to their paths and check them against SHA256SUMS.
#   bash fixtures/FETCH.sh            # all     bash fixtures/FETCH.sh burnwitness   # only outbound/burnwitness/*
# Needs the GitHub CLI (gh) logged in, or set FIXTURES_URL to a directory that serves the files by name.
cd "$(dirname "$0")/.." || exit 1
TAG=${FIXTURES_TAG:-fixtures-v1}; ONLY=${1:-}
rc=0
while read -r sum path; do
  [[ $sum == \#* || -z $path ]] && continue
  [[ -n $ONLY && $path != *"$ONLY"* ]] && continue
  if [[ -f $path ]] && [[ $(sha256sum "$path" | cut -c1-64) == "$sum" ]]; then echo "ok    $path"; continue; fi
  mkdir -p "$(dirname "$path")"
  if [[ -n ${FIXTURES_URL:-} ]]; then curl -fsSL -o "$path" "$FIXTURES_URL/$(basename "$path")"
  else gh release download "$TAG" --pattern "$(basename "$path")" --output "$path" --clobber; fi
  if [[ $(sha256sum "$path" 2>/dev/null | cut -c1-64) == "$sum" ]]; then echo "got   $path"; else echo "BAD   $path (hash mismatch or download failed)"; rc=1; fi
done < fixtures/SHA256SUMS
exit $rc
