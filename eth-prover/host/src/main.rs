//! eth-prover: host for the Ethereum light-client guest.
//!
//!   eth-prover fetch   --network mainnet --consensus-rpc URL [--checkpoint 0x..] [--execution-rpc URL --vault 0x.. --nonce N]... --out inputs.cbor
//!   eth-prover execute --inputs inputs.cbor            # dev-mode run: cycle count + decoded journal, no proof
//!   eth-prover prove   --inputs inputs.cbor --out dir  # real Groth16 receipt -> bundle for bin/r0spend.mjs
//!   eth-prover fixture --dir <helios testdata dir> [--step N] [--execute|--prove --out dir]   # minimal-spec test vector, offline
//!   eth-prover wrap    --receipt out/receipt.succinct.bin --out out   # Groth16-wrap a succinct receipt
//!   eth-prover journal --file out/journal.hex           # decode a journal
//!
//! The bundle format (image_id.hex, journal.hex, journal_hash.hex, receipt.hex) is the one
//! prover/ already produces for the melody guest, so r0spend.mjs consumes it unchanged.

use alloy_primitives::{Address, B256, U256};
use alloy_trie::TrieAccount;
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use eth_bridge_methods::{
    ETH_BRIDGE_GUEST_ELF, ETH_BRIDGE_GUEST_ID, ETH_BRIDGE_GUEST_MINIMAL_ELF,
    ETH_BRIDGE_GUEST_MINIMAL_ID,
};
use eth_bridge_primitives::{
    compute_chain_commitment, vault_layout, DepositProof, Journal, ProofInputs, VaultDeposits,
};
use helios_consensus_core::consensus_spec::{ConsensusSpec, MainnetConsensusSpec, MinimalConsensusSpec};
use helios_consensus_core::types::{
    Bootstrap, FinalityUpdate, FinalityUpdateBase, FinalityUpdateElectra, Forks, LightClientStore,
    Update,
};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update, calc_sync_period, get_bits,
    verify_bootstrap, verify_finality_update, verify_update,
};
use helios_ethereum::config::networks::Network;
use helios_ethereum::rpc::{http_rpc::HttpRpc, ConsensusRpc};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_executor, default_prover, Digest, ExecutorEnv, ProverOpts};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use std::time::{Instant, SystemTime};
use tree_hash::TreeHash;

#[derive(Parser)]
#[command(about = "Ethereum light-client prover for the Kaspa ZK bridge")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Fetch bootstrap + updates from a beacon node (and vault deposits from an execution RPC) and write the guest inputs.
    Fetch {
        /// mainnet | sepolia | hoodi
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// Beacon node with light-client endpoints (/eth/v1/beacon/light_client/*)
        #[arg(long)]
        consensus_rpc: String,
        /// Trusted beacon block root (checkpoint_in). Default: the latest finalized root the node reports.
        #[arg(long)]
        checkpoint: Option<String>,
        /// Execution JSON-RPC (eth_getProof), only needed with --vault. Read it from a file, never paste the key.
        #[arg(long)]
        execution_rpc: Option<String>,
        /// Vault.sol address whose deposits to prove
        #[arg(long)]
        vault: Option<String>,
        /// Deposit nonces to prove, repeatable, strictly increasing
        #[arg(long)]
        nonce: Vec<u64>,
        #[arg(long, default_value = "inputs.cbor")]
        out: PathBuf,
    },
    /// Run the guest without proving (RISC0_DEV_MODE semantics): cycles + journal.
    Execute {
        #[arg(long, default_value = "inputs.cbor")]
        inputs: PathBuf,
    },
    /// Produce a Groth16 receipt and write the r0spend bundle.
    Prove {
        #[arg(long, default_value = "inputs.cbor")]
        inputs: PathBuf,
        #[arg(long, default_value = "out")]
        out: PathBuf,
        /// Stop at the succinct STARK receipt (no Docker needed); times the STARK only. Not spendable on Kaspa.
        #[arg(long)]
        no_wrap: bool,
    },
    /// Offline run on a helios consensus-spec test vector (minimal spec).
    Fixture {
        /// e.g. helios/ethereum/consensus-core/testdata/electra/light_client_sync
        #[arg(long)]
        dir: PathBuf,
        /// Which process_update step to prove. Step N starts from the store after steps 0..N-1,
        /// so the journals of consecutive steps chain (prev_* of N == new_* of N-1).
        #[arg(long, default_value_t = 0)]
        step: usize,
        #[arg(long)]
        prove: bool,
        #[arg(long)]
        no_wrap: bool,
        #[arg(long, default_value = "out-fixture")]
        out: PathBuf,
    },
    /// Groth16-wrap a succinct receipt saved by `prove --no-wrap` (CPU + Docker, or CUDA build).
    Wrap {
        /// the receipt.succinct.bin written by prove --no-wrap
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long, default_value = "out")]
        out: PathBuf,
    },
    /// Decode a journal.hex (or raw journal bytes) with the frozen layout.
    Journal {
        #[arg(long)]
        file: PathBuf,
    },
    /// Print the image ids.
    Ids,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Fetch { network, consensus_rpc, checkpoint, execution_rpc, vault, nonce, out } => {
            fetch(&network, &consensus_rpc, checkpoint, execution_rpc, vault, nonce, &out).await
        }
        Cmd::Execute { inputs } => {
            let bytes = std::fs::read(&inputs).with_context(|| format!("read {}", inputs.display()))?;
            execute(ETH_BRIDGE_GUEST_ELF, ETH_BRIDGE_GUEST_ID, &bytes)
        }
        Cmd::Prove { inputs, out, no_wrap } => {
            let bytes = std::fs::read(&inputs).with_context(|| format!("read {}", inputs.display()))?;
            prove(ETH_BRIDGE_GUEST_ELF, ETH_BRIDGE_GUEST_ID, &bytes, &out, no_wrap)
        }
        Cmd::Fixture { dir, step, prove: do_prove, out, no_wrap } => {
            let bytes = fixture_inputs(&dir, step)?;
            if do_prove {
                prove(ETH_BRIDGE_GUEST_MINIMAL_ELF, ETH_BRIDGE_GUEST_MINIMAL_ID, &bytes, &out, no_wrap)
            } else {
                execute(ETH_BRIDGE_GUEST_MINIMAL_ELF, ETH_BRIDGE_GUEST_MINIMAL_ID, &bytes)
            }
        }
        Cmd::Wrap { receipt, out } => wrap(&receipt, &out),
        Cmd::Journal { file } => {
            let raw = std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            let bytes = match std::str::from_utf8(&raw).ok().and_then(|s| hex::decode(s.trim().trim_start_matches("0x")).ok()) {
                Some(b) => b,
                None => raw,
            };
            let sha: [u8; 32] = Sha256::digest(&bytes).into();
            println!("journal hash  : {}", hex::encode(sha));
            print_journal(&bytes);
            Ok(())
        }
        Cmd::Ids => {
            println!("eth-bridge-guest (mainnet spec) image id: {}", hex::encode(Digest::from(ETH_BRIDGE_GUEST_ID).as_bytes()));
            println!("eth-bridge-guest-minimal          image id: {}", hex::encode(Digest::from(ETH_BRIDGE_GUEST_MINIMAL_ID).as_bytes()));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

async fn fetch(
    network: &str,
    consensus_rpc: &str,
    checkpoint: Option<String>,
    execution_rpc: Option<String>,
    vault: Option<String>,
    nonces: Vec<u64>,
    out: &PathBuf,
) -> Result<()> {
    let network = match network.to_ascii_lowercase().as_str() {
        "mainnet" => Network::Mainnet,
        "sepolia" => Network::Sepolia,
        "hoodi" => Network::Hoodi,
        other => bail!("unknown network {other} (mainnet|sepolia|hoodi)"),
    };
    let base = network.to_base_config();
    let forks = base.forks.clone();
    let genesis_root = base.chain.genesis_root;
    let genesis_time = base.chain.genesis_time;

    let rpc: HttpRpc = <HttpRpc as ConsensusRpc<MainnetConsensusSpec>>::new(consensus_rpc);
    // Sanity check only: some nodes' /config/spec does not parse in helios 0.12 (e.g. Lodestar's BLOB_SCHEDULE).
    // Chain identity is enforced anyway: the bootstrap must match the checkpoint and every signature is checked
    // against this network's genesis root and fork versions, so a wrong-chain node fails below.
    match ConsensusRpc::<MainnetConsensusSpec>::chain_id(&rpc).await {
        Ok(chain_id) if chain_id != base.chain.chain_id => {
            bail!("beacon node reports chain id {chain_id}, expected {} for {network:?}", base.chain.chain_id)
        }
        Ok(_) => {}
        Err(e) => println!("note: could not read chain id from /eth/v1/config/spec ({e}); relying on signature checks"),
    }

    // The finality update is what we prove; its finalized header is checkpoint_out.
    let finality_update: FinalityUpdate<MainnetConsensusSpec> =
        rpc.get_finality_update().await.map_err(|e| anyhow!("GET finality_update: {e}"))?;
    let fu_finalized_root = finality_update.finalized_header().beacon().tree_hash_root();
    let fu_finalized_slot = finality_update.finalized_header().beacon().slot;

    // checkpoint_in: explicit, or the previous finalized checkpoint so there is progress to prove.
    // Without --checkpoint we bootstrap from the node's latest finalized root and then wait for
    // the next finality update; that is what the operator loop will do anyway.
    let checkpoint = match checkpoint {
        Some(c) => parse_b256(&c)?,
        None => {
            println!("no --checkpoint: bootstrapping at the latest finalized root {fu_finalized_root} (slot {fu_finalized_slot});");
            println!("the guest needs a finality update NEWER than that, so re-run fetch with --checkpoint {fu_finalized_root} in ~13 minutes.");
            fu_finalized_root
        }
    };

    let bootstrap: Bootstrap<MainnetConsensusSpec> = rpc
        .get_bootstrap(checkpoint)
        .await
        .map_err(|e| anyhow!("GET bootstrap/{checkpoint}: {e} (node must serve light-client bootstrap for this root)"))?;
    verify_bootstrap::<MainnetConsensusSpec>(&bootstrap, checkpoint, &forks).map_err(|e| anyhow!("bootstrap invalid: {e}"))?;
    let mut store: LightClientStore<MainnetConsensusSpec> = LightClientStore::default();
    apply_bootstrap::<MainnetConsensusSpec>(&mut store, &bootstrap);
    let store_slot = store.finalized_header.beacon().slot;
    let store_period = calc_sync_period::<MainnetConsensusSpec>(store_slot);
    let fu_period = calc_sync_period::<MainnetConsensusSpec>(*finality_update.signature_slot());
    println!("checkpoint_in : {checkpoint} slot {store_slot} period {store_period}");
    println!("finality upd  : finalized {fu_finalized_root} slot {fu_finalized_slot}, signed in period {fu_period}");

    // Sync committee updates for every period boundary between the two.
    let mut sync_committee_updates: Vec<Update<MainnetConsensusSpec>> = Vec::new();
    if fu_period > store_period {
        let count = (fu_period - store_period) as u8;
        sync_committee_updates = rpc.get_updates(store_period, count).await.map_err(|e| anyhow!("GET updates: {e}"))?;
        println!("sync committee updates: {} (periods {}..{})", sync_committee_updates.len(), store_period, fu_period - 1);
    }

    let expected_current_slot = helios_consensus_core::expected_current_slot(SystemTime::now(), genesis_time);

    // Host-side dry run of exactly what the guest will check, so a bad input fails here, not after proving.
    {
        let mut s = store.clone();
        for (i, u) in sync_committee_updates.iter().enumerate() {
            verify_update::<MainnetConsensusSpec>(u, expected_current_slot, &s, genesis_root, &forks)
                .map_err(|e| anyhow!("sync committee update {} invalid: {e}", i + 1))?;
            apply_update::<MainnetConsensusSpec>(&mut s, u);
        }
        verify_finality_update::<MainnetConsensusSpec>(&finality_update, expected_current_slot, &s, genesis_root, &forks)
            .map_err(|e| anyhow!("finality update invalid: {e}"))?;
        let bits = get_bits::<MainnetConsensusSpec>(&finality_update.sync_aggregate().sync_committee_bits);
        println!("participation : {bits}/{}", MainnetConsensusSpec::sync_committee_size());
        apply_finality_update::<MainnetConsensusSpec>(&mut s, &finality_update);
        let new_root = s.finalized_header.beacon().tree_hash_root();
        if new_root != fu_finalized_root {
            bail!("finality update would not advance the store (participation < 2/3, or not newer than checkpoint_in)");
        }
        if new_root == checkpoint {
            bail!("no progress: finality update finalizes checkpoint_in itself; wait for the next one");
        }
    }

    // Optional vault deposits at the execution block of checkpoint_out.
    let vault_deposits = match (vault, execution_rpc) {
        (Some(v), Some(rpc_url)) => {
            if nonces.is_empty() {
                bail!("--vault needs at least one --nonce");
            }
            if nonces.windows(2).any(|w| w[1] <= w[0]) || nonces[0] == 0 {
                bail!("--nonce values must be nonzero and strictly increasing");
            }
            let fh = finality_update.finalized_header();
            let exec = fh
                .execution()
                .map_err(|_| anyhow!("finalized header has no execution payload (Gloas header): storage proofs need the execution-header witness path, not implemented yet"))?;
            let block_number = *exec.block_number();
            let state_root = *exec.state_root();
            let vault_addr = v.parse::<Address>().context("--vault")?;
            println!("exec block    : {block_number} state root {state_root}");
            Some(fetch_vault_deposits(&rpc_url, vault_addr, &nonces, block_number).await?)
        }
        (None, _) => None,
        (Some(_), None) => bail!("--vault needs --execution-rpc"),
    };

    let inputs = ProofInputs::<MainnetConsensusSpec> {
        sync_committee_updates,
        finality_update,
        expected_current_slot,
        store,
        genesis_root,
        forks: forks.clone(),
        vault_deposits,
    };
    let bytes = serde_cbor::to_vec(&inputs)?;
    std::fs::write(out, &bytes)?;
    println!("chain commit  : {}", compute_chain_commitment(genesis_root, &forks));
    println!("wrote {} ({} bytes)", out.display(), bytes.len());
    Ok(())
}

/// One eth_getProof call for both words of every requested deposit, decoded with the vault
/// layout on the host too, so a bad nonce fails here and not after proving.
async fn fetch_vault_deposits(rpc_url: &str, vault: Address, nonces: &[u64], block_number: u64) -> Result<VaultDeposits> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct StorageProof { key: U256, value: U256, proof: Vec<alloy_primitives::Bytes> }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofResp {
        nonce: U256,
        balance: U256,
        storage_hash: B256,
        code_hash: B256,
        account_proof: Vec<alloy_primitives::Bytes>,
        storage_proof: Vec<StorageProof>,
    }
    #[derive(serde::Deserialize)]
    struct Rpc { result: Option<ProofResp>, error: Option<serde_json::Value> }

    let mut keys: Vec<B256> = Vec::with_capacity(nonces.len() * 2);
    for &n in nonces {
        keys.push(vault_layout::word0_key(n));
        keys.push(vault_layout::word1_key(n));
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getProof",
        "params": [vault, keys, format!("0x{block_number:x}")]
    });
    let resp: Rpc = reqwest::Client::new().post(rpc_url).json(&body).send().await?.json().await?;
    let r = resp.result.ok_or_else(|| anyhow!("eth_getProof error: {:?}", resp.error))?;
    if r.storage_proof.len() != keys.len() {
        bail!("eth_getProof returned {} storage proofs for {} keys", r.storage_proof.len(), keys.len());
    }
    let find = |key: B256| -> Result<&StorageProof> {
        r.storage_proof
            .iter()
            .find(|p| B256::from(p.key.to_be_bytes::<32>()) == key)
            .ok_or_else(|| anyhow!("eth_getProof result lacks key {key}"))
    };
    let mut deposits = Vec::with_capacity(nonces.len());
    for &n in nonces {
        let p0 = find(vault_layout::word0_key(n))?;
        let p1 = find(vault_layout::word1_key(n))?;
        let (amount, version) = vault_layout::decode_word0(p0.value)
            .ok_or_else(|| anyhow!("deposit {n}: word 0 = {} is not a Vault deposit at block {block_number} (nonce not yet deposited, or wrong vault)", p0.value))?;
        if p1.value.is_zero() {
            bail!("deposit {n}: kaspa payload is zero at block {block_number}");
        }
        let payload = B256::from(p1.value.to_be_bytes::<32>());
        println!("deposit {n:<5} : amount {amount} kaspa_spk 0x{:02x}{}", version, hex::encode(payload));
        deposits.push(DepositProof {
            nonce: n,
            word0: p0.value,
            word0_proof: p0.proof.clone(),
            payload,
            payload_proof: p1.proof.clone(),
        });
    }
    println!("vault         : {vault} storage root {} account proof {} nodes", r.storage_hash, r.account_proof.len());
    Ok(VaultDeposits {
        vault,
        account: TrieAccount {
            nonce: r.nonce.to::<u64>(),
            balance: r.balance,
            storage_root: r.storage_hash,
            code_hash: r.code_hash,
        },
        account_proof: r.account_proof,
        deposits,
    })
}

// ---------------------------------------------------------------------------
// execute / prove
// ---------------------------------------------------------------------------

fn execute(elf: &[u8], id: [u32; 8], inputs: &[u8]) -> Result<()> {
    println!("image id      : {}", hex::encode(Digest::from(id).as_bytes()));
    let env = ExecutorEnv::builder().write_frame(inputs).build()?;
    let t0 = Instant::now();
    let info = default_executor().execute(env, elf)?;
    println!("executed in   : {:.1?}", t0.elapsed());
    let user: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded: u64 = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    println!("segments      : {}", info.segments.len());
    println!("user cycles   : {user}");
    println!("padded cycles : {padded} (sum of 2^po2 per segment; this is what proving pays for)");
    print_journal(&info.journal.bytes);
    Ok(())
}

fn prove(elf: &[u8], id: [u32; 8], inputs: &[u8], out: &PathBuf, no_wrap: bool) -> Result<()> {
    let image_id = Digest::from(id);
    println!("image id      : {}", hex::encode(image_id.as_bytes()));
    let env = ExecutorEnv::builder().write_frame(inputs).build()?;
    let dev = std::env::var("RISC0_DEV_MODE").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let opts = if dev || no_wrap { ProverOpts::succinct() } else { ProverOpts::groth16() };

    let t0 = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &opts)?;
    let elapsed = t0.elapsed();
    println!("proved in     : {elapsed:.1?}");
    println!("user cycles   : {}", info.stats.user_cycles);
    println!("total cycles  : {}", info.stats.total_cycles);
    println!("segments      : {}", info.stats.segments);
    let receipt = info.receipt;
    receipt.verify(id)?;

    let journal = receipt.journal.bytes.clone();
    let jh = receipt.journal.digest();
    let sha: [u8; 32] = Sha256::digest(&journal).into();
    assert_eq!(jh.as_bytes(), &sha[..], "journal digest must be plain sha256");
    print_journal(&journal);

    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("image_id.hex"), hex::encode(image_id.as_bytes()))?;
    std::fs::write(out.join("journal.hex"), hex::encode(&journal))?;
    std::fs::write(out.join("journal_hash.hex"), hex::encode(jh.as_bytes()))?;
    std::fs::write(out.join("timing.txt"), format!("proved_in_seconds={}\nuser_cycles={}\ntotal_cycles={}\nsegments={}\n",
        elapsed.as_secs_f64(), info.stats.user_cycles, info.stats.total_cycles, info.stats.segments))?;
    if dev {
        println!("RISC0_DEV_MODE: no real receipt written.");
        return Ok(());
    }
    if no_wrap {
        let path = out.join("receipt.succinct.bin");
        std::fs::write(&path, bincode::serialize(&receipt)?)?;
        println!("--no-wrap: succinct receipt verified and saved to {} ({} bytes).", path.display(),
            std::fs::metadata(&path)?.len());
        println!("next: eth-prover wrap --receipt {} --out {}   (on a box with Docker, or a CUDA build)", path.display(), out.display());
        return Ok(());
    }
    write_groth16_bundle(&receipt, out)
}

/// STARK-to-SNARK on a saved succinct receipt. Without the `cuda` feature this shells out to
/// risc0's Docker image (risczero/risc0-groth16-prover), ~2 minutes on a CPU box.
fn wrap(receipt_path: &PathBuf, out: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(receipt_path).with_context(|| format!("read {}", receipt_path.display()))?;
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&bytes).context("decode succinct receipt")?;
    let image_id = Digest::from(
        <[u8; 32]>::try_from(std::fs::read_to_string(out.join("image_id.hex")).ok()
            .and_then(|h| hex::decode(h.trim()).ok()).unwrap_or_default()).unwrap_or([0u8; 32]));
    if image_id != Digest::ZERO {
        receipt.verify(image_id).context("succinct receipt does not verify against image_id.hex in --out")?;
        println!("image id      : {} (verified)", hex::encode(image_id.as_bytes()));
    }
    let t0 = Instant::now();
    let groth16_receipt = default_prover().compress(&ProverOpts::groth16(), &receipt)?;
    let elapsed = t0.elapsed();
    println!("wrapped in    : {elapsed:.1?}");
    std::fs::create_dir_all(out)?;
    let mut f = std::fs::OpenOptions::new().append(true).create(true).open(out.join("timing.txt"))?;
    use std::io::Write as _;
    writeln!(f, "wrapped_in_seconds={}", elapsed.as_secs_f64())?;
    print_journal(&groth16_receipt.journal.bytes);
    write_groth16_bundle(&groth16_receipt, out)
}

fn write_groth16_bundle(receipt: &risc0_zkvm::Receipt, out: &PathBuf) -> Result<()> {
    let journal = &receipt.journal.bytes;
    let jh = receipt.journal.digest();
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("journal.hex"), hex::encode(journal))?;
    std::fs::write(out.join("journal_hash.hex"), hex::encode(jh.as_bytes()))?;
    let groth16 = receipt.inner.groth16().context("receipt is not Groth16")?;
    let bytes = borsh::to_vec(groth16)?;
    std::fs::write(out.join("receipt.hex"), hex::encode(&bytes))?;
    println!("receipt       : {} bytes borsh -> {}", bytes.len(), out.join("receipt.hex").display());
    println!("\nnext: node bin/r0spend.mjs address --bundle {}", out.display());
    Ok(())
}

fn print_journal(bytes: &[u8]) {
    println!("journal       : {} bytes", bytes.len());
    match Journal::decode(bytes) {
        Some(j) => {
            println!("  chain_commitment : {}", j.chain_commitment);
            println!("  prev_header      : {}", j.prev_header);
            println!("  prev_committee   : {}", j.prev_committee);
            println!("  new_header       : {}", j.new_header);
            println!("  new_committee    : {}", j.new_committee);
            println!("  new_slot         : {}", j.new_slot);
            println!("  exec_state_root  : {}", j.exec_state_root);
            println!("  exec_block_number: {}", j.exec_block_number);
            println!("  vault            : {}", j.vault);
            println!("  deposits         : {}", j.deposits.len());
            for d in &j.deposits {
                println!("    nonce {} amount {} kaspa_spk 0x{}", d.nonce, d.amount, hex::encode(d.kaspa_spk));
            }
        }
        None => println!("  (journal does not decode as our layout)"),
    }
}

// ---------------------------------------------------------------------------
// fixture: helios consensus-spec test vector -> ProofInputs<MinimalConsensusSpec>
//
// `--step N` proves the N-th process_update of the vector, starting from the store the
// covenant holds after steps 0..N-1 were proven, so consecutive steps give consecutive
// journals (journal[N].prev_* == journal[N-1].new_*). A step whose signature period is
// ahead of the store's period gets the signed sync-committee rotation it needs: the
// latest earlier full Update attested in the store's period that carries a next
// committee (consensus-spec semantics; the guest verifies it like any other update).
// ---------------------------------------------------------------------------

fn fixture_update_to_finality<S: ConsensusSpec>(update: Update<S>) -> Result<FinalityUpdate<S>> {
    Ok(match update {
        Update::Base(u) => FinalityUpdate::Base(FinalityUpdateBase {
            attested_header: u.attested_header, finalized_header: u.finalized_header,
            finality_branch: u.finality_branch, sync_aggregate: u.sync_aggregate, signature_slot: u.signature_slot,
        }),
        Update::Electra(u) => FinalityUpdate::Electra(FinalityUpdateElectra {
            attested_header: u.attested_header, finalized_header: u.finalized_header,
            finality_branch: u.finality_branch, sync_aggregate: u.sync_aggregate, signature_slot: u.signature_slot,
        }),
        Update::Gloas(_) => bail!("gloas fixtures not supported by this reshaping"),
    })
}

/// Advance `store` by the vector's step `k` exactly as the guest would: rotation first if the
/// signature period requires it, then the step as a finality update. Returns the rotation used.
fn fixture_advance(
    store: &mut LightClientStore<MinimalConsensusSpec>,
    updates: &[(Update<MinimalConsensusSpec>, u64)],
    k: usize,
    current_slot: u64,
    genesis_root: B256,
    forks: &Forks,
) -> Result<(Vec<Update<MinimalConsensusSpec>>, FinalityUpdate<MinimalConsensusSpec>)> {
    type S = MinimalConsensusSpec;
    let (update, _) = &updates[k];
    let store_period = calc_sync_period::<S>(store.finalized_header.beacon().slot);
    let sig_period = calc_sync_period::<S>(*update.signature_slot());
    let mut rotations = Vec::new();
    if sig_period > store_period {
        if sig_period != store_period + 1 {
            bail!("step {k} is signed {} periods ahead of the store; one rotation per proof is supported", sig_period - store_period);
        }
        let has_next = |u: &Update<S>| u.next_sync_committee_branch().iter().any(|b| !b.is_zero());
        let j = (0..k)
            .rev()
            .find(|&j| has_next(&updates[j].0) && calc_sync_period::<S>(updates[j].0.attested_header().beacon().slot) == store_period)
            .ok_or_else(|| anyhow!("step {k} needs the period-{store_period} committee rotation and no earlier step carries it"))?;
        let rot = updates[j].0.clone();
        verify_update::<S>(&rot, current_slot, store, genesis_root, forks).map_err(|e| anyhow!("rotation (step {j}) invalid: {e}"))?;
        apply_update::<S>(store, &rot);
        if store.next_sync_committee.is_none() {
            bail!("rotation (step {j}) did not install the next sync committee");
        }
        println!("  step {k}: signed in period {sig_period}, rotation from step {j} applied first");
        rotations.push(rot);
    }
    let fu = fixture_update_to_finality(update.clone())?;
    verify_finality_update::<S>(&fu, current_slot, store, genesis_root, forks).map_err(|e| anyhow!("step {k} invalid: {e}"))?;
    let before = store.finalized_header.beacon().tree_hash_root();
    apply_finality_update::<S>(store, &fu);
    let after = store.finalized_header.beacon().tree_hash_root();
    if after != fu.finalized_header().beacon().tree_hash_root() || after == before {
        bail!("step {k} does not advance the finalized header (participation < 2/3, or not newer)");
    }
    Ok((rotations, fu))
}

fn fixture_inputs(dir: &PathBuf, step: usize) -> Result<Vec<u8>> {
    use ssz::Decode;
    type S = MinimalConsensusSpec;

    #[derive(serde::Deserialize)]
    struct Meta { genesis_validators_root: B256, trusted_block_root: B256 }
    let meta: Meta = serde_yaml::from_str(&std::fs::read_to_string(dir.join("meta.yaml"))?)?;
    let forks = fixture_forks(dir)?;
    let genesis_root = meta.genesis_validators_root;

    let decomp = |name: &str| -> Result<Vec<u8>> {
        let data = std::fs::read(dir.join(name)).with_context(|| name.to_string())?;
        Ok(snap::raw::Decoder::new().decompress_vec(&data)?)
    };
    let bootstrap = Bootstrap::<S>::from_ssz_bytes(&decomp("bootstrap.ssz_snappy")?)
        .map_err(|e| anyhow!("bootstrap ssz: {e:?}"))?;
    verify_bootstrap::<S>(&bootstrap, meta.trusted_block_root, &forks).map_err(|e| anyhow!("bootstrap: {e}"))?;
    let mut store = LightClientStore::<S>::default();
    apply_bootstrap::<S>(&mut store, &bootstrap);

    // process_update steps 0..=step, in order (each with its current_slot)
    let steps: Vec<serde_yaml::Value> = serde_yaml::from_str(&std::fs::read_to_string(dir.join("steps.yaml"))?)?;
    let mut updates: Vec<(Update<S>, u64)> = Vec::new();
    for i in 0..=step {
        let st = steps.get(i).and_then(|s| s["process_update"].as_mapping())
            .ok_or_else(|| anyhow!("step {i} is not a process_update step"))?;
        let name = st["update"].as_str().unwrap();
        let current_slot = st["current_slot"].as_u64().unwrap();
        let u = Update::<S>::from_ssz_bytes(&decomp(&format!("{name}.ssz_snappy"))?).map_err(|e| anyhow!("update ssz: {e:?}"))?;
        updates.push((u, current_slot));
    }

    // Steps before `step` were proven earlier: replay them to reach the store at checkpoint_in.
    for k in 0..step {
        fixture_advance(&mut store, &updates, k, updates[k].1, genesis_root, &forks)?;
    }
    store.best_valid_update = None;
    if store.next_sync_committee.is_some() {
        bail!("store before step {step} carries a next sync committee; the guest refuses that");
    }
    let input_store = store.clone();
    let prev_header = store.finalized_header.beacon().tree_hash_root();
    let prev_committee = store.current_sync_committee.tree_hash_root();

    // Dry run of the step itself (the same checks the guest makes).
    let current_slot = updates[step].1;
    let (sync_committee_updates, finality_update) = fixture_advance(&mut store, &updates, step, current_slot, genesis_root, &forks)?;
    let bits = get_bits::<S>(&finality_update.sync_aggregate().sync_committee_bits);
    println!("fixture {}: step {step}, current_slot {current_slot}, participation {bits}/{}", dir.display(), S::sync_committee_size());
    println!("  expected journal: prev_header {prev_header}  prev_committee {prev_committee}");
    println!("                    new_header  {}  new_committee  {}", store.finalized_header.beacon().tree_hash_root(),
        store.current_sync_committee.tree_hash_root());

    let inputs = ProofInputs::<S> {
        sync_committee_updates,
        finality_update,
        expected_current_slot: current_slot,
        store: input_store,
        genesis_root,
        forks,
        vault_deposits: None,
    };
    Ok(serde_cbor::to_vec(&inputs)?)
}

fn fixture_forks(dir: &PathBuf) -> Result<Forks> {
    use helios_consensus_core::types::Fork;
    let cfg: serde_yaml::Mapping = serde_yaml::from_str(&std::fs::read_to_string(dir.join("config.yaml"))?)?;
    let get = |k: &str| cfg.get(serde_yaml::Value::String(k.into())).cloned();
    let ver = |k: &str| -> Result<alloy_primitives::FixedBytes<4>> {
        let v = get(&format!("{k}_FORK_VERSION")).ok_or_else(|| anyhow!("missing {k}_FORK_VERSION"))?;
        // YAML parses 0x00000001 as an integer; tolerate both spellings.
        let bytes: [u8; 4] = match &v {
            serde_yaml::Value::String(s) => hex::decode(s.trim_start_matches("0x"))?.try_into().map_err(|_| anyhow!("{k} version length"))?,
            serde_yaml::Value::Number(n) => (n.as_u64().ok_or_else(|| anyhow!("{k} version"))? as u32).to_be_bytes(),
            _ => bail!("{k} version has unexpected type"),
        };
        Ok(alloy_primitives::FixedBytes::<4>::from(bytes))
    };
    let epoch = |k: &str| -> u64 {
        get(&format!("{k}_FORK_EPOCH")).and_then(|v| v.as_u64()).unwrap_or(u64::MAX)
    };
    // forks absent from config.yaml are inactive (helios' runner does the same with its fallback table)
    let fallback = |k: &str| -> alloy_primitives::FixedBytes<4> {
        let n: u8 = match k { "ALTAIR" => 1, "BELLATRIX" => 2, "CAPELLA" => 3, "DENEB" => 4, "ELECTRA" => 5, "FULU" => 6, "GLOAS" => 7, _ => 0 };
        alloy_primitives::FixedBytes::<4>::from([n, 0, 0, 1])
    };
    let fork = |k: &str| -> Result<Fork> {
        Ok(Fork { epoch: epoch(k), fork_version: ver(k).unwrap_or_else(|_| fallback(k)) })
    };
    Ok(Forks {
        genesis: Fork { epoch: 0, fork_version: ver("GENESIS")? },
        altair: fork("ALTAIR")?, bellatrix: fork("BELLATRIX")?, capella: fork("CAPELLA")?,
        deneb: fork("DENEB")?, electra: fork("ELECTRA")?, fulu: fork("FULU")?, gloas: fork("GLOAS")?,
    })
}

fn parse_b256(s: &str) -> Result<B256> {
    Ok(B256::from_slice(&hex::decode(s.trim_start_matches("0x")).context("hex")?))
}

#[allow(dead_code)]
fn _assert_spec_bounds<S: ConsensusSpec + Serialize + DeserializeOwned>() {}
