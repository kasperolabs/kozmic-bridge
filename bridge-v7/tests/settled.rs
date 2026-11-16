//! Sprint 7 (2026-11-15), the settled-inputs question of 11-14, first half: do the opcodes kUSDT's
//! `require_settled_inputs` uses (OpTxInputSeq, OpTxInputDaaScore, OpTxInputSpkLen, OpTxInputSpkSubstr; kUSDT builds on
//! silverscript 3ed97333) compile on this crate's pin, a0dd7448? Compile only; nothing is spent. The test passes either
//! way and prints the answer; the second half (does the node's mempool accept an advance copy with an extra unsettled
//! input) is a live test on the box and is not a release gate (NEXT-SESSION.md, 11-14).
//! Run: cargo test --release --test settled -- --nocapture

use silverscript_abi::ArtifactValue;
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

const SNIPPET: &str = r#"
pragma silverscript ^0.1.0;
contract Settled(int max_inputs) {
    entry check() {
        require(tx.inputs.length <= max_inputs);
        for (i, 0, tx.inputs.length, 8) {
            if (i != this.activeInputIndex) {
                require(OpTxInputSeq(i) == 0);
                require(OpTxInputDaaScore(i) > 0);
                int l = OpTxInputSpkLen(i);
                require(l == 34 || l == 35);
                byte[] head = OpTxInputSpkSubstr(i, 0, 1);
                require(head == 0x20 || head == 0xaa);
            }
        }
    }
}
"#;

#[test]
fn settled_inputs_opcodes_on_this_pin() {
    let r = compile_to_sil_abi_artifact_with_options(SNIPPET, &[ArtifactValue::Int(8)], CompileOptions::default());
    match r {
        Ok(a) => {
            let c = a.contracts.get("Settled").expect("contract");
            println!("settled-inputs: the four opcodes COMPILE on a0dd7448: {} bytes of script; the mempool question remains", c.compiled.bytecode.len());
        }
        Err(e) => {
            let msg = format!("{e}");
            println!("settled-inputs: does NOT compile on a0dd7448: {}", msg.lines().next().unwrap_or(&msg));
            println!("  (kUSDT builds on 3ed97333; if only a name differs, the opcode exists under another spelling; if the opcode is missing, v7 stays at the cell floor)");
        }
    }
}
