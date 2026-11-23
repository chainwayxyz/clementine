#![cfg(feature = "use-test-vk")]
use circuits_lib::{bridge_circuit::sp1_test_prover, common::sp1::groth16 as sp1};

#[test]
fn development_proofs_use_the_pinned_key() {
    assert_eq!(
        sp1::development::verifying_key(),
        sp1_test_prover::universal_key()
    );
}
