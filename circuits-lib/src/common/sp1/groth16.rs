//! SP1 public-value scalars and development Groth16 verification.
//! Production BitVM key preparation belongs to the host.
use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;

/// Decode a canonical big-endian scalar. Never silently reduce an untrusted key hash.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Fr, &'static str> {
    let scalar = Fr::from_be_bytes_mod_order(bytes);
    if scalar.into_bigint().to_bytes_be() != bytes {
        return Err("Non-canonical BN254 scalar");
    }
    Ok(scalar)
}

/// Fold the fixed first public input into IC[0], leaving exactly one public input.
/// The program hash must come from the trusted guest build, never from a proof.
pub fn specialize_vk(
    mut vk: VerifyingKey<Bn254>,
    program_hash: &[u8; 32],
) -> Result<VerifyingKey<Bn254>, &'static str> {
    if vk.gamma_abc_g1.len() != 3 {
        return Err("Expected an SP1 key with two public inputs");
    }
    let program = scalar_from_bytes(program_hash)?;
    let constant = (vk.gamma_abc_g1[0].into_group()
        + vk.gamma_abc_g1[1].mul_bigint(program.into_bigint()))
    .into_affine();
    vk.gamma_abc_g1 = vec![constant, vk.gamma_abc_g1[2]];
    Ok(vk)
}

/// SP1's SHA-256 public-values digest; the high three bits are cleared, all 253 others kept.
pub fn public_input(public_values: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(&sp1_verifier::hash_public_inputs(public_values))
}

/// SP1's BLAKE3 public-values digest, which the bridge program commits for Bitcoin scripts.
pub fn public_input_blake3(public_values: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(&sp1_verifier::hash_public_inputs_with_fn(
        public_values,
        sp1_verifier::blake3_hash,
    ))
}

/// Deterministic development Groth16 proofs for BitVM integration tests.
/// They do not prove execution and are never accepted by production builds.
pub mod development {
    #[cfg(feature = "use-test-vk")]
    use {
        super::{specialize_vk, Bn254, Fr, VerifyingKey},
        ark_groth16::Proof,
    };

    /// Envelope prefix that distinguishes development seals from SP1's key selector.
    pub const SEAL_PREFIX: [u8; 4] = *b"SP1D";

    /// Development seal: the prefix followed by the points in SP1's Gnark layout.
    pub fn seal(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> Vec<u8> {
        let points =
            crate::bridge_circuit::groth16::CircuitGroth16Proof::new(proof.a, proof.b, proof.c);
        [SEAL_PREFIX.as_slice(), &points.to_gnark_bytes()].concat()
    }

    /// Raw points of a development seal.
    pub fn proof_body(seal: &[u8]) -> Result<&[u8; 256], &'static str> {
        seal.strip_prefix(SEAL_PREFIX.as_slice())
            .and_then(|body| body.try_into().ok())
            .ok_or("Invalid development proof")
    }

    /// The pinned universal development key, before it is bound to a program.
    #[cfg(feature = "use-test-vk")]
    pub fn verifying_key() -> VerifyingKey<Bn254> {
        use ark_serialize::CanonicalDeserialize;
        VerifyingKey::deserialize_uncompressed(
            &include_bytes!("../../bridge_circuit/bin/sp1-development-vk.bin")[..],
        )
        .expect("Pinned development key")
    }

    /// The development key bound to a program, with one public input like the production key.
    #[cfg(feature = "use-test-vk")]
    pub fn program_verifying_key(program: &[u8; 32]) -> Result<VerifyingKey<Bn254>, &'static str> {
        specialize_vk(verifying_key(), program)
    }

    /// Verifies a development proof for `program` over one public input.
    #[cfg(feature = "use-test-vk")]
    pub fn verify(program: &[u8; 32], proof: Proof<Bn254>, public_input: Fr) -> bool {
        program_verifying_key(program).is_ok_and(|vk| {
            ark_groth16::Groth16::<Bn254>::verify_proof(
                &ark_groth16::prepare_verifying_key(&vk),
                &proof,
                &[public_input],
            )
            .unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_std::test_rng;

    #[derive(Clone)]
    struct TwoInputs {
        program: Fr,
        output: Fr,
    }
    impl ConstraintSynthesizer<Fr> for TwoInputs {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let program = cs.new_input_variable(|| Ok(self.program))?;
            let output = cs.new_input_variable(|| Ok(self.output))?;
            let product = cs.new_witness_variable(|| Ok(self.program * self.output))?;
            cs.enforce_constraint(lc!() + program, lc!() + output, lc!() + product)
        }
    }
    fn bytes(value: Fr) -> [u8; 32] {
        value.into_bigint().to_bytes_be().try_into().unwrap()
    }

    #[test]
    fn folding_preserves_verification_and_binds_both_inputs() {
        let mut rng = test_rng();
        let circuit = TwoInputs {
            program: Fr::from(17u64),
            output: public_input(b"bridge output"),
        };
        let pk =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit.clone(), &pk, &mut rng)
                .unwrap();
        assert!(Groth16::<Bn254>::verify_proof(
            &prepare_verifying_key(&pk.vk),
            &proof,
            &[circuit.program, circuit.output]
        )
        .unwrap());
        let folded = specialize_vk(pk.vk.clone(), &bytes(circuit.program)).unwrap();
        assert_eq!(folded.gamma_abc_g1.len(), 2);
        let prepared = prepare_verifying_key(&folded);
        assert!(Groth16::<Bn254>::verify_proof(&prepared, &proof, &[circuit.output]).unwrap());
        assert!(!Groth16::<Bn254>::verify_proof(
            &prepared,
            &proof,
            &[public_input(b"changed output")]
        )
        .unwrap());
        let wrong_program = specialize_vk(pk.vk, &bytes(Fr::from(18u64))).unwrap();
        assert!(!Groth16::<Bn254>::verify_proof(
            &prepare_verifying_key(&wrong_program),
            &proof,
            &[circuit.output]
        )
        .unwrap());
        assert!(Groth16::<Bn254>::verify_proof(
            &prepared,
            &proof,
            &[circuit.program, circuit.output]
        )
        .is_err());
    }

    #[test]
    fn digests_become_scalars_without_reduction_or_dropped_high_bits() {
        for i in 0u32..100 {
            let data = i.to_le_bytes();
            assert_eq!(
                bytes(public_input(&data)),
                sp1_verifier::hash_public_inputs(&data)
            );
            assert_eq!(
                bytes(public_input_blake3(&data)),
                sp1_verifier::hash_public_inputs_with_fn(&data, sp1_verifier::blake3_hash)
            );
        }
        assert!((0u32..100).any(|i| bytes(public_input(&i.to_le_bytes()))[0] != 0));
    }

    #[test]
    fn development_seals_need_the_prefix_and_exact_length() {
        let points = crate::bridge_circuit::groth16::CircuitGroth16Proof::new(
            ark_bn254::G1Affine::generator(),
            ark_bn254::G2Affine::generator(),
            ark_bn254::G1Affine::generator(),
        );
        let mut seal = development::seal(&points.into());
        assert_eq!(development::proof_body(&seal), Ok(&points.to_gnark_bytes()));
        for size in [0, 4, 259] {
            assert!(development::proof_body(&seal[..size]).is_err());
        }
        assert!(development::proof_body(&[seal.as_slice(), &[0]].concat()).is_err());
        seal[0] ^= 1;
        assert!(development::proof_body(&seal).is_err());
    }
}
