use ark_serialize::CanonicalSerialize;
fn main() {
    let key = circuits_lib::bridge_circuit::sp1_test_prover::universal_key();
    let mut bytes = Vec::new();
    key.serialize_uncompressed(&mut bytes).unwrap();
    std::fs::write(std::env::args().nth(1).expect("Output path"), bytes).unwrap();
}
