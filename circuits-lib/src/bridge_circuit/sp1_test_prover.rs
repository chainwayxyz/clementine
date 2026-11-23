//! Deterministic development Groth16 circuit. Never use this key for production.
//! This tests BitVM plumbing after executing the real SP1 guest in mock mode.
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::sync::LazyLock;

#[derive(Clone)]
struct DevelopmentCircuit {
    program: Fr,
    output: Fr,
}
impl ConstraintSynthesizer<Fr> for DevelopmentCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let program = cs.new_input_variable(|| Ok(self.program))?;
        let output = cs.new_input_variable(|| Ok(self.output))?;
        let product = cs.new_witness_variable(|| Ok(self.program * self.output))?;
        cs.enforce_constraint(lc!() + program, lc!() + output, lc!() + product)
    }
}
static KEY: LazyLock<ProvingKey<Bn254>> = LazyLock::new(|| {
    let mut rng = StdRng::from_seed([0x53; 32]);
    Groth16::<Bn254>::generate_random_parameters_with_reduction(
        DevelopmentCircuit {
            program: Fr::from(1u64),
            output: Fr::from(1u64),
        },
        &mut rng,
    )
    .expect("development setup")
});
pub fn universal_key() -> VerifyingKey<Bn254> {
    KEY.vk.clone()
}
pub fn prove(program: &[u8; 32], output: Fr) -> Result<Proof<Bn254>, &'static str> {
    let program = crate::common::sp1::groth16::scalar_from_bytes(program)?;
    let mut rng = StdRng::from_seed([0x50; 32]);
    Groth16::<Bn254>::create_random_proof_with_reduction(
        DevelopmentCircuit { program, output },
        &KEY,
        &mut rng,
    )
    .map_err(|_| "Development proving failed")
}
