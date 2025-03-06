use alloy::providers::RootProvider;
use alloy::transports::http::{Client, Http};
use risc0_to_bitvm2_core::spv::SPV;
use risc0_zkvm::Receipt;
pub struct BridgeCircuitHostParams {
    pub light_client_provider: RootProvider<Http<Client>>,
    pub citrea_provider: RootProvider<Http<Client>>,
    pub headerchain_proof: Receipt,
    pub spv: SPV,
}
