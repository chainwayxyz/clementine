use circuits_lib::bridge_circuit_core::{
    structs::{LightClientProof, StorageProof},
    winternitz::WinternitzHandler,
};
use risc0_to_bitvm2_core::{header_chain::BlockHeaderCircuitOutput, spv::SPV};
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
