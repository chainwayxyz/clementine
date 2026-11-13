//! SP1 proof transport and guest I/O. The Borsh layout of [`Receipt`] matches Citrea's
//! SP1 proof envelope.
pub mod groth16;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Journal {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Groth16Proof {
    pub seal: Vec<u8>,
}

/// Compressed SP1 proof, which guests verify with native recursion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CompressedProof {
    /// Program key (`vk.hash_u32()`).
    pub native_vkey: [u32; 8],
    /// Bincode-encoded `SP1Proof::Compressed`. Only the host reads this.
    pub proof: Vec<u8>,
    /// Bincode-encoded `SP1VerifyingKey`. Only the host reads this.
    pub vkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Proof {
    /// SP1 Groth16 proof over the SHA-256 or BLAKE3 public-values digest.
    Groth16(Groth16Proof),
    /// Execution without a proof of the program with key `vk.hash_u32()`. Accepted only where
    /// mocks are explicitly allowed.
    Mock { program: [u32; 8] },
    /// Groth16 proof under the development key, for BitVM integration tests.
    DevelopmentGroth16 {
        program: [u8; 32],
        proof: Groth16Proof,
    },
    /// Wire tag 3 matches Citrea; preserve the three preceding discriminants.
    Compressed(CompressedProof),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Receipt {
    pub inner: Proof,
    pub journal: Journal,
}

/// Validate v6 metadata before discarding it for Bitcoin's raw Groth16 encoding.
/// The verification key fixes successful execution, the pinned recursion root,
/// and a zero proof nonce. These values must never be taken from an untrusted proof.
pub fn production_proof_body(seal: &[u8]) -> eyre::Result<&[u8; 256]> {
    use sha2::{Digest, Sha256};
    eyre::ensure!(seal.len() == 356, "Invalid SP1 v6 proof length");
    eyre::ensure!(
        seal[..4] == Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES)[..4],
        "Invalid SP1 key selector"
    );
    eyre::ensure!(seal[4..36] == [0; 32], "SP1 execution did not succeed");
    eyre::ensure!(
        seal[36..68] == *sp1_verifier::VK_ROOT_BYTES,
        "Invalid SP1 recursion root"
    );
    eyre::ensure!(
        seal[68..100] == [0; 32],
        "Nonzero SP1 proof nonce is not supported by the fixed Bitcoin key"
    );
    Ok(seal[100..].try_into().expect("checked length"))
}

impl Receipt {
    /// Unproven receipt of an executed guest, accepted only where mocks are allowed.
    pub fn mock(program: [u32; 8], public_values: Vec<u8>) -> Self {
        Self {
            inner: Proof::Mock { program },
            journal: Journal {
                bytes: public_values,
            },
        }
    }

    /// Raw points after checking the metadata fixed into the selected Bitcoin key.
    pub fn groth16_body(&self) -> eyre::Result<&[u8; 256]> {
        match &self.inner {
            Proof::Groth16(proof) => production_proof_body(&proof.seal),
            Proof::DevelopmentGroth16 { proof, .. } => {
                crate::common::sp1::groth16::development::proof_body(&proof.seal)
                    .map_err(eyre::Report::msg)
            }
            Proof::Mock { .. } | Proof::Compressed(_) => {
                eyre::bail!("Expected a Groth16 proof");
            }
        }
    }

    /// Groth16 points of a production or development proof, checked to be valid curve points.
    #[cfg(not(target_os = "zkvm"))]
    pub fn groth16_proof(&self) -> eyre::Result<ark_groth16::Proof<ark_bn254::Bn254>> {
        sp1_verifier::load_ark_proof_from_bytes(self.groth16_body()?)
            .map_err(|_| eyre::eyre!("Invalid SP1 Groth16 points"))
    }
}

/// SP1 guest I/O and native recursion.
#[cfg(target_os = "zkvm")]
#[derive(Debug, Clone, Default)]
pub struct SP1Guest;

#[cfg(target_os = "zkvm")]
impl crate::common::zkvm::ZkvmGuest for SP1Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        borsh::from_slice(&sp1_zkvm::io::read_vec()).expect("Failed to deserialize input from host")
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        sp1_zkvm::io::commit_slice(
            &borsh::to_vec(item).expect("Serialization to vec is infallible"),
        );
    }

    /// Defers verification of a compressed proof of `method_id` (SP1's `vk.hash_u32()`)
    /// with public values `journal`. The host supplies the proof; real proving fails without it.
    fn verify<T: BorshSerialize>(&self, method_id: [u32; 8], journal: &T) {
        use sha2::{Digest, Sha256};
        let public_values = borsh::to_vec(journal).expect("Serialization to vec is infallible");
        sp1_zkvm::lib::verify::verify_sp1_proof(&method_id, &Sha256::digest(public_values).into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_proof_metadata_is_fixed_and_checked_before_compression() {
        use sha2::{Digest, Sha256};
        // Point validity is checked by the subsequent Groth16 decoder.
        let mut seal = vec![0; 356];
        seal[..4].copy_from_slice(&Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES)[..4]);
        seal[36..68].copy_from_slice(&*sp1_verifier::VK_ROOT_BYTES);
        assert!(production_proof_body(&seal).is_ok());
        for index in [0, 4, 35, 36, 67, 68, 99] {
            let mut changed = seal.clone();
            changed[index] ^= 1;
            assert!(
                production_proof_body(&changed).is_err(),
                "accepted changed metadata at {index}"
            );
        }
        for size in [0, 4, 100, 260, 355, 357] {
            assert!(production_proof_body(&vec![0; size]).is_err());
        }
        seal[100..].fill(255);
        let receipt = Receipt {
            inner: Proof::Groth16(Groth16Proof { seal }),
            journal: Journal { bytes: vec![] },
        };
        assert!(receipt.groth16_proof().is_err(), "accepted invalid points");
    }

    #[test]
    fn wire_layout_matches_citrea() {
        let mut receipt = Receipt::mock([7; 8], vec![1, 2, 3]);
        let wire = borsh::to_vec(&receipt).unwrap();
        assert_eq!(wire[0], 1);
        assert_eq!(&wire[1..33], &[7, 0, 0, 0].repeat(8));
        assert_eq!(&wire[33..], &[3, 0, 0, 0, 1, 2, 3]);

        let mut native_vkey = [0; 8];
        native_vkey[7] = 7;
        receipt.inner = Proof::Compressed(CompressedProof {
            native_vkey,
            proof: vec![1],
            vkey: vec![2],
        });
        let wire = borsh::to_vec(&receipt).unwrap();
        assert_eq!(
            wire[0], 3,
            "Citrea and Clementine use the same compressed tag"
        );
        assert_eq!(&wire[1..5], &[0; 4]);
        assert_eq!(&wire[29..33], &[7, 0, 0, 0]);
    }
}
