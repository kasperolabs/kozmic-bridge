#![no_main]
risc0_zkvm::guest::entry!(main);
fn main() {
    eth_bridge_guest::run::<helios_consensus_core::consensus_spec::MainnetConsensusSpec>();
}
