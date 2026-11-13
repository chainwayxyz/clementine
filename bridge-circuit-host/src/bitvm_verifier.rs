//! BitVM verifying keys of bridge programs, prepared for Bitcoin's single-public-input
//! verifier from SP1's production Groth16 key or the development key.
use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use circuits_lib::common::sp1::groth16::specialize_vk;

/// BitVM verifying key of a bridge program: the development key with `use-test-vk`,
/// SP1's Groth16 key otherwise. The program is folded in, leaving one public input.
pub fn get_verifying_key(program: &[u8; 32]) -> eyre::Result<VerifyingKey<Bn254>> {
    #[cfg(feature = "use-test-vk")]
    let key = circuits_lib::common::sp1::groth16::development::program_verifying_key(program);
    #[cfg(not(feature = "use-test-vk"))]
    let key = program_verifying_key(program);
    key.map_err(eyre::Report::msg)
}

/// Verifies a bridge proof as Bitcoin does, with the program's BitVM key and one public input.
pub fn verify_bitvm(
    program: &[u8; 32],
    proof: &Proof<Bn254>,
    public_input: Fr,
) -> eyre::Result<()> {
    let key = get_verifying_key(program)?;
    let valid =
        Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&key), proof, &[public_input])
            .map_err(|e| eyre::eyre!("BitVM Groth16 verification failed: {e}"))?;
    eyre::ensure!(valid, "BitVM Groth16 verification failed");
    Ok(())
}

/// Fix v6 metadata to successful execution, the trusted recursion root, and zero nonce.
pub fn fix_sp1_metadata(mut vk: VerifyingKey<Bn254>) -> Result<VerifyingKey<Bn254>, &'static str> {
    if vk.gamma_abc_g1.len() != 6 {
        return Err("Expected five SP1 v6 public inputs");
    }
    let root = Fr::from_be_bytes_mod_order(&*sp1_verifier::VK_ROOT_BYTES);
    vk.gamma_abc_g1[0] = (vk.gamma_abc_g1[0].into_group()
        + vk.gamma_abc_g1[4].mul_bigint(root.into_bigint()))
    .into_affine();
    // Inputs 2 (exit code) and 4 (nonce) are zero; input 3 is the pinned root.
    vk.gamma_abc_g1.truncate(3);
    Ok(vk)
}

/// Load SP1's pinned universal Groth16 key and bind it to a program.
pub fn program_verifying_key(program_hash: &[u8; 32]) -> Result<VerifyingKey<Bn254>, &'static str> {
    let vk =
        sp1_verifier::load_ark_groth16_verifying_key_from_bytes(*sp1_verifier::GROTH16_VK_BYTES)
            .map_err(|_| "Invalid SP1 Groth16 key")?;
    specialize_vk(fix_sp1_metadata(vk)?, program_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_std::test_rng;
    use circuits_lib::common::sp1::groth16::{public_input, scalar_from_bytes};

    fn bytes(value: Fr) -> [u8; 32] {
        value.into_bigint().to_bytes_be().try_into().unwrap()
    }

    #[derive(Clone)]
    struct FiveInputs([Fr; 5]);
    impl ConstraintSynthesizer<Fr> for FiveInputs {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            for value in self.0 {
                let input = cs.new_input_variable(|| Ok(value))?;
                let square = cs.new_witness_variable(|| Ok(value * value))?;
                cs.enforce_constraint(lc!() + input, lc!() + input, lc!() + square)?;
            }
            Ok(())
        }
    }

    #[test]
    fn v6_metadata_folding_rejects_failed_exit_wrong_root_and_nonzero_nonce() {
        let mut rng = test_rng();
        let inputs = [
            Fr::from(17u64),
            public_input(b"output"),
            Fr::from(0u64),
            Fr::from_be_bytes_mod_order(&*sp1_verifier::VK_ROOT_BYTES),
            Fr::from(0u64),
        ];
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            FiveInputs(inputs),
            &mut rng,
        )
        .unwrap();
        let key =
            specialize_vk(fix_sp1_metadata(pk.vk.clone()).unwrap(), &bytes(inputs[0])).unwrap();
        let prepared = prepare_verifying_key(&key);
        assert_eq!(key.gamma_abc_g1.len(), 2);
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(FiveInputs(inputs), &pk, &mut rng)
                .unwrap();
        assert!(Groth16::<Bn254>::verify_proof(&prepared, &proof, &[inputs[1]]).unwrap());
        for index in [0, 1, 2, 3, 4] {
            let mut changed = inputs;
            changed[index] += Fr::from(1u64);
            let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
                FiveInputs(changed),
                &pk,
                &mut rng,
            )
            .unwrap();
            assert!(
                !Groth16::<Bn254>::verify_proof(&prepared, &proof, &[inputs[1]]).unwrap(),
                "input {index} was not bound"
            );
        }
    }

    #[test]
    fn fixed_metadata_and_program_leave_one_public_input() {
        let vk = program_verifying_key(&bytes(Fr::from(17u64))).unwrap();
        assert_eq!(vk.gamma_abc_g1.len(), 2);
        assert!(specialize_vk(vk, &[0; 32]).is_err());
        assert!(scalar_from_bytes(&[255; 32]).is_err());
    }
}
