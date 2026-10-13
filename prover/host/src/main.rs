//! Host: runs the melody guest, produces a Groth16 receipt, and writes the bundle
//! that bin/r0spend.mjs consumes:
//!   out/image_id.hex   out/journal.hex   out/journal_hash.hex   out/receipt.hex
//!
//! Usage:
//!   cargo run --release -- --melody 60,62,64,65,67,69,71,72 --root 0 --mode major --out ../out
//!
//! Groth16 proving (STARK -> SNARK) runs through the official risc0 docker image and
//! needs an x86_64 Linux host with Docker. Set RISC0_DEV_MODE=1 to dry-run the guest
//! logic only (no real proof, nothing a covenant would accept).
use methods::{MELODY_ELF, MELODY_ID};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_prover, Digest, ExecutorEnv, ProverOpts};
use sha2::{Digest as _, Sha256};
use std::{fs, path::PathBuf};

const NOTE_NAMES: [&str; 12] = ["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut melody: Vec<u8> = vec![60, 62, 64, 65, 67, 69, 71, 72]; // C major scale, ends on C
    let mut root: u8 = 0;
    let mut mode: u8 = 0;
    let mut out = PathBuf::from("out");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--melody" => melody = args[i + 1].split(',').map(|s| s.trim().parse()).collect::<Result<_, _>>()?,
            "--root" => root = args[i + 1].parse()?,
            "--mode" => mode = match args[i + 1].as_str() { "major" | "0" => 0, "minor" | "1" => 1, m => panic!("unknown mode {m}") },
            "--out" => out = PathBuf::from(&args[i + 1]),
            a => panic!("unknown arg {a}"),
        }
        i += 2;
    }

    let image_id = Digest::from(MELODY_ID);
    println!("program image id : {}", hex::encode(image_id.as_bytes()));
    println!("claim            : a {}-note melody in {} {} that ends on the tonic", melody.len(), NOTE_NAMES[root as usize % 12], if mode == 0 { "major" } else { "minor" });

    let env = ExecutorEnv::builder().write(&root)?.write(&mode)?.write(&melody)?.build()?;

    let dev = std::env::var("RISC0_DEV_MODE").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let opts = if dev { ProverOpts::default() } else { ProverOpts::groth16() };

    let t0 = std::time::Instant::now();
    let receipt = default_prover().prove_with_opts(env, MELODY_ELF, &opts)?.receipt;
    println!("proved in        : {:.1?}", t0.elapsed());

    // The receipt verifies against the image id (same check the covenant performs, minus the chain).
    receipt.verify(MELODY_ID)?;

    let journal = receipt.journal.bytes.clone();
    let journal_hash_sha2 = Sha256::digest(&journal);
    let journal_hash_r0 = receipt.journal.digest();
    assert_eq!(journal_hash_r0.as_bytes(), journal_hash_sha2.as_slice(), "journal digest must be plain sha256 of the bytes");

    println!("journal          : {}", hex::encode(&journal));
    println!("journal hash     : {}", hex::encode(journal_hash_r0.as_bytes()));

    fs::create_dir_all(&out)?;
    fs::write(out.join("image_id.hex"), hex::encode(image_id.as_bytes()))?;
    fs::write(out.join("journal.hex"), hex::encode(&journal))?;
    fs::write(out.join("journal_hash.hex"), hex::encode(journal_hash_r0.as_bytes()))?;

    if dev {
        println!("RISC0_DEV_MODE: guest logic ran, no real receipt written. Unset it to produce one.");
        return Ok(());
    }

    // The Kaspa SDK's finalizeWithGroth16Proof expects a borsh-encoded Groth16Receipt<ReceiptClaim>.
    let groth16 = receipt.inner.groth16()?;
    let bytes = borsh::to_vec(groth16)?;
    fs::write(out.join("receipt.hex"), hex::encode(&bytes))?;
    println!("receipt          : {} bytes borsh -> {}", bytes.len(), out.join("receipt.hex").display());
    println!("\nnext: node bin/r0spend.mjs address --bundle {}", out.display());
    Ok(())
}
