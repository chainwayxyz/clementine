use alloy_rpc_client::RpcClient;
use risc0_to_bitvm2_core::{header_chain::BlockHeaderCircuitOutput, spv::SPV};
use risc0_zkvm::Receipt;

pub struct BridgeCircuitHostParams {
    pub light_client_rpc_client: RpcClient,
    pub citrea_rpc_client: RpcClient,
    pub work_only_groth16_proof_receipt: Receipt,
    pub spv: SPV,
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
}
