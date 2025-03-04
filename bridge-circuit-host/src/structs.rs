use alloy_rpc_client::RpcClient;
use risc0_to_bitvm2_core::spv::SPV;
use risc0_zkvm::Receipt;
pub struct BridgeCircuitHostParams {
    pub light_client_rpc_client: RpcClient,
    pub citrea_rpc_client: RpcClient,
    pub headerchain_proof: Receipt,
    pub spv: SPV,
}
