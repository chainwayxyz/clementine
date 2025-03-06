use circuits_lib::bridge_circuit_core::{
    structs::{LightClientProof, StorageProof},
    winternitz::WinternitzHandler,
};
use final_spv::spv::SPV;
use header_chain::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::Receipt;

pub struct BridgeCircuitHostParams {
    pub winternitz_details: Vec<WinternitzHandler>,
    pub spv: SPV,
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
    pub headerchain_receipt: Receipt,
    pub light_client_proof: LightClientProof,
    pub lcp_receipt: Receipt,
    pub storage_proof: StorageProof,
    pub num_of_watchtowers: u32,
}
