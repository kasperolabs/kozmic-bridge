#!/usr/bin/env python3
"""The BridgeMint artifact for KCC-23 findability (handoff section 7): one JSON file per minter template, served at
https://kasperolabs.com/kcc20/minter/<template>.json. It names no token and no instance, so every bridge instance whose
authority has this template points at the same bytes. Metadata commits to its sha256 (artifact_hash), so the bytes are
frozen once the first prep tx references them: this script is deterministic (fixed key order, indent 2, LF, one
trailing newline) and only copies bytes from the fixture file executed in rusty-kaspa 2.1.0 and from the sources.

    python3 -I bin/minter-artifact.py <fixtures.json> <BridgeMint.sil> <KCC20.sil> <out.json>
"""
import hashlib, json, sys

fx_path, bm_sil, cell_sil, out = sys.argv[1:5]
fx = json.load(open(fx_path))
bm, cell = fx["bridge_mint"], fx["kcc20"]
MINTER = "dc96afcde4874e0750e85ecffe91a845365ff16d952a4c1a92f49f7a0da70102"
CELL = "9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7"
BURN = "d379e50f3e2203f9a92584916335bb7cd014b237ceaa8b36f1d3d80d0cc88b32"
assert bm["template"] == MINTER, bm["template"]
assert cell["template"] == CELL, cell["template"]
assert fx["burn_owner_p2sh"] == BURN
assert bm["tags"] == {"mint": "e3505180", "retire": "dd5121ee"}, bm["tags"]
assert cell["prefix"] == "6b" and bm["prefix"] == "6b"
assert cell["state_window_len"] == 145


def src(path):
    b = open(path, "rb").read()
    return {"file": path.split("/")[-1], "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b), "text": b.decode("utf-8")}


art = {
    "kind": "kcc20-minter-artifact",
    "version": 1,
    "minter": {
        "name": "BridgeMint",
        "template": MINTER,
        "template_rule": "BLAKE3(LE64(len prefix) || prefix || LE64(len suffix) || suffix)",
        "prefix": bm["prefix"],
        "suffix": bm["suffix"],
        "redeem_rule": "prefix || state_window || suffix; spk = aa20 BLAKE2b-256(redeem) 87 (P2SH, version 0)",
        "state_window": [
            {"field": "kcc20_template", "push": "20", "bytes": 32},
            {"field": "bridge_mint_template", "push": "20", "bytes": 32},
            {"field": "bridge_covenant_id", "push": "20", "bytes": 32, "note": "the bridge covenant that authorizes every mint"},
            {"field": "extension_commitment", "push": "20", "bytes": 32},
        ],
        "tags": {"mint": bm["tags"]["mint"], "retire": bm["tags"]["retire"]},
        "mint_arguments": "6 grouped KCC20State field pushes (KCC-1 3.4.6), the cell prefix, the cell suffix, the dispatch tag, "
                          "then push(redeem)",
        "issuance_rule": "issuance = the cells created by mint. Authorized output 0 is the authority's continuation; outputs "
                         "1..n are the recipients' cells, each verified as aa20 BLAKE2b(6b || EncodeState(state) || suffix) 87.",
        "source": src(bm_sil),
    },
    "cell": {
        "name": "KCC20 (Last Call reference cell)",
        "template": CELL,
        "prefix": cell["prefix"],
        "suffix": cell["suffix"],
        "state_window_len": cell["state_window_len"],
        "state_window": [
            {"field": "template", "push": "20", "bytes": 32},
            {"field": "amount", "push": "08", "bytes": 8, "encoding": "LE64"},
            {"field": "owner", "push": "20", "bytes": 32},
            {"field": "owner_scheme", "push": "01", "bytes": 1, "values": {"0": "p2pk schnorr", "3": "p2sh"}},
            {"field": "borrow_scheme", "push": "01", "bytes": 1},
            {"field": "borrow_guard", "push": "20", "bytes": 32},
            {"field": "extension_commitment", "push": "20", "bytes": 32},
        ],
        "tags": cell["tags"],
        "source": src(cell_sil),
    },
    "burn_owner": {"scheme": 3, "owner": BURN, "note": "unspendable p2sh owner; a cell owned by it is burned (outbound exit)"},
    "provenance": "rusty-kaspa 2.1.0, silverscript a0dd7448; bytes copied from bridge-v4/tests/fixtures/bridgemint-fixtures.json",
}
data = (json.dumps(art, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
open(out, "wb").write(data)
print(f"wrote {out}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
