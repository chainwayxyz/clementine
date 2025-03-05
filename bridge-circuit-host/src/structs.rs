use circuits_lib::bridge_circuit_core::winternitz::WinternitzHandler;
use risc0_to_bitvm2_core::{header_chain::BlockHeaderCircuitOutput, spv::SPV};

pub struct BridgeCircuitHostParams {
    pub winternitz_details: Vec<WinternitzHandler>,
    pub spv: SPV,
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
}
