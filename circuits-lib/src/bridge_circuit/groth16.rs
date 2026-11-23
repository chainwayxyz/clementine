//! # Groth16 Proof Struct
//! This module defines the `CircuitGroth16Proof` struct, which represents a Groth16 proof
//! for the bridge circuit. It includes methods for converting it to and from a compressed
//! format. The proof consists of three components: `a`,
//! `b`, and `c`, which are points on the elliptic curve used in the Groth16 protocol.
//! ## Key Components
//! - **G1 and G2 Points:** The proof consists of points `a` and `c` in G1, and point `b` in G2.
//! - **Serialization/Deserialization:** The proof can be serialized to a compressed format
//!   and deserialized back, allowing for efficient storage and transmission.
//! - **Conversion to Groth16 Proof:** The `CircuitGroth16Proof` can be converted to a Groth16 proof
//!   for use in verification.

use ark_bn254::Bn254;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
type G1 = ark_bn254::G1Affine;
type G2 = ark_bn254::G2Affine;

/// CircuitGroth16Proof represents a Groth16 proof for the circuit.
#[derive(Copy, Clone, Debug)]
pub struct CircuitGroth16Proof {
    a: G1,
    b: G2,
    c: G1,
}

impl CircuitGroth16Proof {
    pub fn new(a: G1, b: G2, c: G1) -> CircuitGroth16Proof {
        CircuitGroth16Proof { a, b, c }
    }

    /// Gnark's uncompressed encoding; G2 stores each imaginary component first.
    pub fn to_gnark_bytes(&self) -> [u8; 256] {
        let mut bytes = [0; 256];
        let coordinates = [
            self.a.x,
            self.a.y,
            self.b.x.c1,
            self.b.x.c0,
            self.b.y.c1,
            self.b.y.c0,
            self.c.x,
            self.c.y,
        ];
        for (chunk, coordinate) in bytes.chunks_exact_mut(32).zip(coordinates) {
            chunk.copy_from_slice(&coordinate.into_bigint().to_bytes_be());
        }
        bytes
    }

    pub fn from_compressed(
        compressed: &[u8; 128],
    ) -> Result<CircuitGroth16Proof, SerializationError> {
        let a_compressed = &compressed[0..32];
        let b_compressed = &compressed[32..96];
        let c_compressed = &compressed[96..128];
        let a = ark_bn254::G1Affine::deserialize_compressed(a_compressed)?;
        let b = ark_bn254::G2Affine::deserialize_compressed(b_compressed)?;
        let c = ark_bn254::G1Affine::deserialize_compressed(c_compressed)?;

        Ok(CircuitGroth16Proof::new(a, b, c))
    }

    pub fn to_compressed(&self) -> Result<[u8; 128], SerializationError> {
        let mut a_compressed = [0u8; 32];
        let mut b_compressed = [0u8; 64];
        let mut c_compressed = [0u8; 32];

        ark_bn254::G1Affine::serialize_with_mode(&self.a, &mut a_compressed[..], Compress::Yes)
            .expect("Serialization should not fail for valid curve points");
        ark_bn254::G2Affine::serialize_with_mode(&self.b, &mut b_compressed[..], Compress::Yes)
            .expect("Serialization should not fail for valid curve points");
        ark_bn254::G1Affine::serialize_with_mode(&self.c, &mut c_compressed[..], Compress::Yes)
            .expect("Serialization should not fail for valid curve points");

        let mut compressed = [0u8; 128];
        compressed[0..32].copy_from_slice(&a_compressed);
        compressed[32..96].copy_from_slice(&b_compressed);
        compressed[96..128].copy_from_slice(&c_compressed);

        Ok(compressed)
    }

    pub fn a(&self) -> &G1 {
        &self.a
    }

    pub fn b(&self) -> &G2 {
        &self.b
    }

    pub fn c(&self) -> &G1 {
        &self.c
    }
}

impl From<Proof<Bn254>> for CircuitGroth16Proof {
    fn from(proof: Proof<Bn254>) -> Self {
        CircuitGroth16Proof::new(proof.a, proof.b, proof.c)
    }
}

impl From<CircuitGroth16Proof> for Proof<Bn254> {
    fn from(g16_seal: CircuitGroth16Proof) -> Self {
        Proof::<Bn254> {
            a: g16_seal.a,
            b: g16_seal.b,
            c: g16_seal.c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    fn random_g1() -> G1 {
        let mut rng = test_rng();
        G1::rand(&mut rng)
    }

    fn random_g2() -> G2 {
        let mut rng = test_rng();
        G2::rand(&mut rng)
    }

    #[test]
    fn test_new_and_accessors() {
        let a = random_g1();
        let b = random_g2();
        let c = random_g1();

        let proof = CircuitGroth16Proof::new(a, b, c);
        assert_eq!(proof.a(), &a);
        assert_eq!(proof.b(), &b);
        assert_eq!(proof.c(), &c);
    }

    #[test]
    fn gnark_encoding_matches_sp1_decoder() {
        let proof = CircuitGroth16Proof::new(random_g1(), random_g2(), random_g1());
        let decoded = sp1_verifier::load_ark_proof_from_bytes(&proof.to_gnark_bytes()).unwrap();
        assert_eq!(proof.a, decoded.a);
        assert_eq!(proof.b, decoded.b);
        assert_eq!(proof.c, decoded.c);
    }

    #[test]
    fn test_to_compressed_and_from_compressed() {
        for _ in 0..16 {
            let proof = CircuitGroth16Proof::new(random_g1(), random_g2(), random_g1());

            let compressed = proof.to_compressed().expect("Compression failed");
            let decompressed_proof =
                CircuitGroth16Proof::from_compressed(&compressed).expect("Decompression failed");

            assert_eq!(proof.a(), decompressed_proof.a());
            assert_eq!(proof.b(), decompressed_proof.b());
            assert_eq!(proof.c(), decompressed_proof.c());
        }
    }

    #[test]
    fn test_conversion_to_proof_bn254() {
        let proof = CircuitGroth16Proof::new(random_g1(), random_g2(), random_g1());
        let groth16_proof: Proof<Bn254> = proof.into();

        assert_eq!(proof.a(), &groth16_proof.a);
        assert_eq!(proof.b(), &groth16_proof.b);
        assert_eq!(proof.c(), &groth16_proof.c);
    }
}
