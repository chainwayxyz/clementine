#![no_main]
sp1_zkvm::entrypoint!(main);
fn main() {
    circuits_lib::header_chain::header_chain_circuit(&circuits_lib::common::sp1::SP1Guest);
}
