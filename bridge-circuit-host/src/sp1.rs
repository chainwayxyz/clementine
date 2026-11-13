//! SP1 proving: guest execution, compressed proofs for native recursion, and Groth16 proofs
//! for Bitcoin.
use crate::guests::Guest;
use circuits_lib::bridge_circuit::constants::is_test_vk;
use circuits_lib::common::programs::ProgramKey;
#[cfg(any(test, feature = "use-test-vk"))]
use circuits_lib::common::sp1::groth16 as bridge_sp1;
use circuits_lib::common::sp1::{CompressedProof, Groth16Proof, Journal, Proof, Receipt};
use eyre::{eyre, Result};
pub use sp1_host::Backend;
use sp1_host::Host;
use sp1_sdk::{HashableKey, SP1ProofMode, SP1Stdin, SP1VerifyingKey};

/// Development programs require mock execution; production programs require real proofs.
pub fn check_programs(backend: Backend) -> Result<Backend> {
    eyre::ensure!(
        (backend == Backend::Mock) == is_test_vk(),
        "SP1_PROVER {backend:?} does not match the programs; use mock with use-test-vk, or cpu/network without it"
    );
    Ok(backend)
}

/// The proof that [`prove`] produces for a guest, fixed by the guest's consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// Compressed STARK, which other guests verify with native recursion.
    Compressed,
    /// Groth16 over the SHA-256 public-values digest, which the bridge guest verifies.
    Groth16,
    /// Groth16 over the BLAKE3 public-values digest, which BitVM verifies.
    BridgeGroth16,
}

/// Guest input: the Borsh-encoded circuit input and the native recursion witnesses of its
/// assumptions, in the order the guest verifies them.
pub struct GuestInput {
    stdin: SP1Stdin,
    has_mock_assumption: bool,
}

impl GuestInput {
    pub fn new(input: &impl borsh::BorshSerialize) -> Result<Self> {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(input)?);
        Ok(Self {
            stdin,
            has_mock_assumption: false,
        })
    }

    /// Adds a proof that the guest verifies with `ZkvmGuest::verify`. Mock execution does not
    /// check these, so mock receipts need no witness.
    pub fn with_assumption(mut self, receipt: &Receipt) -> Result<Self> {
        ensure_assumption(receipt)?;
        match &receipt.inner {
            Proof::Compressed(proof) => write_native_witness(&mut self.stdin, proof)?,
            _ => self.has_mock_assumption = true,
        }
        Ok(self)
    }
}

/// Ensures that guests can use `receipt` as an assumption. Guests verify only compressed
/// proofs, with native recursion; mock receipts stand in for them in tests.
pub fn ensure_assumption(receipt: &Receipt) -> Result<()> {
    eyre::ensure!(
        matches!(receipt.inner, Proof::Compressed(_) | Proof::Mock { .. }),
        "Assumptions must be compressed or mock receipts"
    );
    Ok(())
}

fn write_native_witness(stdin: &mut SP1Stdin, proof: &CompressedProof) -> Result<()> {
    let vk: sp1_sdk::SP1VerifyingKey = bincode::deserialize(&proof.vkey)?;
    eyre::ensure!(
        vk.hash_u32() == proof.native_vkey,
        "Compressed proof key mismatch"
    );
    let sp1_sdk::SP1Proof::Compressed(inner) = bincode::deserialize(&proof.proof)? else {
        eyre::bail!("Expected a compressed SP1 proof");
    };
    stdin.write_proof(*inner, vk.vk);
    Ok(())
}

/// Runs the guest with mock recursion assumptions. Their proofs are not checked.
#[cfg(test)]
pub async fn execute_with_mock_assumptions(elf: &[u8], input: GuestInput) -> Result<Vec<u8>> {
    sp1_host::execute(elf, input.stdin).await
}

/// Verifies a real SP1 Groth16 or compressed proof of `program` with SP1's verifiers, which
/// accept either public-values digest. With `allow_mock`, it also accepts mock receipts and
/// development Groth16 proofs of `program`.
pub async fn verify(receipt: &Receipt, program: ProgramKey, allow_mock: bool) -> Result<()> {
    let public_values = &receipt.journal.bytes;
    match &receipt.inner {
        Proof::Groth16(proof) => sp1_verifier::Groth16Verifier::verify(
            &proof.seal,
            public_values,
            &format!("0x{}", hex::encode(program.groth16)),
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|e| eyre!("SP1 Groth16 verification failed: {e:?}")),
        Proof::Compressed(proof) => {
            let vk: SP1VerifyingKey = bincode::deserialize(&proof.vkey)?;
            eyre::ensure!(
                vk.hash_u32() == program.recursion && proof.native_vkey == program.recursion,
                "Compressed SP1 program mismatch"
            );
            sp1_host::verify_compressed(bincode::deserialize(&proof.proof)?, public_values, vk)
                .await
        }
        Proof::Mock { program: executed } => {
            eyre::ensure!(
                allow_mock && *executed == program.recursion,
                "Mock SP1 receipt is not allowed or has the wrong program"
            );
            Ok(())
        }
        Proof::DevelopmentGroth16 {
            program: proven, ..
        } => {
            eyre::ensure!(
                allow_mock && *proven == program.groth16,
                "Development proof is not allowed or has the wrong program"
            );
            #[cfg(feature = "use-test-vk")]
            {
                let proof = receipt.groth16_proof()?;
                let digests = [
                    bridge_sp1::public_input(public_values),
                    bridge_sp1::public_input_blake3(public_values),
                ];
                eyre::ensure!(
                    digests.into_iter().any(|public_input| {
                        bridge_sp1::development::verify(
                            &program.groth16,
                            proof.clone(),
                            public_input,
                        )
                    }),
                    "Invalid development proof"
                );
                Ok(())
            }
            #[cfg(not(feature = "use-test-vk"))]
            {
                eyre::bail!("Development verification was not compiled")
            }
        }
    }
}

/// Proves a trusted guest as its [`ProofKind`] and verifies the result against the guest's
/// program key.
///
/// With [`Backend::Mock`], the guest is only executed. Groth16 kinds then carry a development
/// Groth16 proof when compiled with `use-test-vk`, for BitVM integration tests.
pub async fn prove(guest: &Guest, input: GuestInput, backend: Backend) -> Result<Receipt> {
    let kind = guest.kind;
    eyre::ensure!(
        backend == Backend::Mock || !input.has_mock_assumption,
        "Real SP1 proving needs compressed assumptions, not mock receipts"
    );
    let host = Host::get(guest.elf, backend).await?;
    let key = guest.key;
    eyre::ensure!(
        host.program_id()? == key.groth16,
        "Guest ELF does not match its program key"
    );
    let receipt = match backend {
        Backend::Mock => {
            let mut receipt = Receipt::mock(key.recursion, host.execute(input.stdin).await?);
            if kind != ProofKind::Compressed && is_test_vk() {
                receipt.inner = development_groth16(&key.groth16, &receipt.journal.bytes, kind)?;
            }
            receipt
        }
        Backend::Cpu | Backend::Network => prove_real(&host, input.stdin, kind).await?,
    };
    verify(&receipt, key, backend == Backend::Mock).await?;
    Ok(receipt)
}

async fn prove_real(host: &Host, stdin: SP1Stdin, kind: ProofKind) -> Result<Receipt> {
    let mode = match kind {
        ProofKind::Compressed => SP1ProofMode::Compressed,
        ProofKind::Groth16 | ProofKind::BridgeGroth16 => SP1ProofMode::Groth16,
    };
    let proof = host
        .prove(stdin, mode, [0; 4], kind == ProofKind::BridgeGroth16)
        .await?;
    let vk = host.verifying_key();
    Ok(Receipt {
        inner: match kind {
            ProofKind::Compressed => Proof::Compressed(CompressedProof {
                native_vkey: vk.hash_u32(),
                proof: bincode::serialize(&proof.proof)?,
                vkey: bincode::serialize(vk)?,
            }),
            ProofKind::Groth16 | ProofKind::BridgeGroth16 => Proof::Groth16(Groth16Proof {
                seal: groth16_seal(&proof.proof)?,
            }),
        },
        journal: Journal {
            bytes: proof.public_values.to_vec(),
        },
    })
}

/// Encodes a Groth16 proof as `vkey_hash[..4] || proof`, like
/// `SP1ProofWithPublicValues::bytes`. The proof can come from the prover network, so a
/// malformed proof is an error instead of the SDK's panic.
fn groth16_seal(proof: &sp1_sdk::SP1Proof) -> Result<Vec<u8>> {
    let sp1_sdk::SP1Proof::Groth16(proof) = proof else {
        eyre::bail!("Expected an SP1 Groth16 proof");
    };
    let encoded = hex::decode(&proof.encoded_proof)
        .map_err(|e| eyre!("Invalid SP1 Groth16 proof encoding: {e}"))?;
    Ok([&proof.groth16_vkey_hash[..4], encoded.as_slice()].concat())
}

/// Development Groth16 proof over the public values, for BitVM integration tests. It is not
/// a proof of execution.
fn development_groth16(program: &[u8; 32], public_values: &[u8], kind: ProofKind) -> Result<Proof> {
    #[cfg(feature = "use-test-vk")]
    {
        let public_input = match kind {
            ProofKind::BridgeGroth16 => bridge_sp1::public_input_blake3(public_values),
            ProofKind::Groth16 | ProofKind::Compressed => bridge_sp1::public_input(public_values),
        };
        let proof = circuits_lib::bridge_circuit::sp1_test_prover::prove(program, public_input)
            .map_err(eyre::Report::msg)?;
        Ok(Proof::DevelopmentGroth16 {
            program: *program,
            proof: Groth16Proof {
                seal: bridge_sp1::development::seal(&proof),
            },
        })
    }
    #[cfg(not(feature = "use-test-vk"))]
    {
        let _ = (program, public_values, kind);
        Err(eyre!("Development Groth16 proofs require use-test-vk"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program key that no real guest has, with every byte and word set to `n`.
    fn test_key(n: u8) -> ProgramKey {
        ProgramKey {
            recursion: [n.into(); 8],
            groth16: [n; 32],
        }
    }

    #[tokio::test]
    async fn real_proving_rejects_mock_assumptions_before_setup() {
        for backend in [Backend::Cpu, Backend::Network] {
            let input = GuestInput::new(&())
                .unwrap()
                .with_assumption(&Receipt::mock([0; 8], vec![]))
                .unwrap();
            // No valid ELF or network credentials are needed to reject this input.
            let guest = Guest {
                elf: b"",
                key: circuits_lib::common::programs::REGTEST.header_chain,
                kind: ProofKind::Compressed,
            };
            let error = prove(&guest, input, backend).await.unwrap_err();
            assert!(error.to_string().contains("compressed assumptions"));
        }
    }

    #[test]
    fn groth16_seal_matches_sdk_encoding_and_rejects_malformed_proofs() {
        let groth16 = |encoded_proof: &str| {
            sp1_sdk::SP1Proof::Groth16(sp1_verifier::Groth16Bn254Proof {
                public_inputs: Default::default(),
                encoded_proof: encoded_proof.to_string(),
                raw_proof: String::new(),
                groth16_vkey_hash: [7; 32],
            })
        };
        let valid = groth16("00ff");
        let sdk_bytes = sp1_sdk::SP1ProofWithPublicValues::new(
            valid.clone(),
            Default::default(),
            String::new(),
        )
        .bytes();
        assert_eq!(groth16_seal(&valid).unwrap(), sdk_bytes);
        assert!(groth16_seal(&groth16("not hex")).is_err());
        assert!(groth16_seal(&sp1_sdk::SP1Proof::Core(vec![])).is_err());
    }

    #[tokio::test]
    async fn program_keys_match_the_generated_table_and_prove_checks_them() {
        let guests = &crate::guests::REGTEST;
        for guest in [guests.header_chain, guests.work_only, guests.bridge] {
            let host = Host::get(guest.elf, Backend::Mock).await.unwrap();
            assert_eq!(host.program_id().unwrap(), guest.key.groth16);
            assert_eq!(guest.key.recursion, host.verifying_key().hash_u32());
        }

        // The key is checked before execution, so the input is never read.
        let mismatched = Guest {
            key: guests.work_only.key,
            ..guests.header_chain
        };
        let input = GuestInput::new(&()).unwrap();
        let error = prove(&mismatched, input, Backend::Mock).await.unwrap_err();
        assert!(error.to_string().contains("does not match its program key"));
    }

    #[tokio::test]
    async fn mocks_are_explicit_and_bound_to_program() {
        let receipt = Receipt::mock([7; 8], vec![1, 2, 3]);
        assert!(verify(&receipt, test_key(7), false).await.is_err());
        assert!(verify(&receipt, test_key(7), true).await.is_ok());
        assert!(verify(&receipt, test_key(8), true).await.is_err());
    }

    #[tokio::test]
    async fn assumptions_must_be_compressed_or_mock() {
        let mut receipt = Receipt::mock([7; 8], vec![1, 2, 3]);
        let input = || GuestInput::new(&()).unwrap();
        assert!(input().with_assumption(&receipt).is_ok());

        for inner in [
            Proof::Groth16(Groth16Proof { seal: vec![] }),
            Proof::DevelopmentGroth16 {
                program: [7; 32],
                proof: Groth16Proof { seal: vec![] },
            },
        ] {
            receipt.inner = inner;
            assert!(input().with_assumption(&receipt).is_err());
        }

        receipt.inner = Proof::Compressed(CompressedProof {
            native_vkey: [0; 8],
            proof: vec![1],
            vkey: vec![2],
        });
        assert!(verify(&receipt, test_key(0), true).await.is_err());
    }

    #[cfg(feature = "use-test-vk")]
    #[tokio::test]
    async fn development_proofs_require_explicit_opt_in() {
        let program = circuits_lib::common::programs::REGTEST.work_only;
        let journal = b"work-only output".to_vec();
        let proof = circuits_lib::bridge_circuit::sp1_test_prover::prove(
            &program.groth16,
            bridge_sp1::public_input(&journal),
        )
        .unwrap();
        let mut receipt = Receipt {
            inner: Proof::DevelopmentGroth16 {
                program: program.groth16,
                proof: Groth16Proof {
                    seal: bridge_sp1::development::seal(&proof),
                },
            },
            journal: Journal { bytes: journal },
        };
        let other = circuits_lib::common::programs::REGTEST.header_chain;
        assert!(verify(&receipt, program, false).await.is_err());
        assert!(verify(&receipt, program, true).await.is_ok());
        assert!(verify(&receipt, other, true).await.is_err());
        receipt.journal.bytes[0] ^= 1;
        assert!(verify(&receipt, program, true).await.is_err());
    }

    /// Program key the fixture was proven for (tests/fixtures/README.md), independent of the
    /// current guest builds.
    #[cfg(not(feature = "use-test-vk"))]
    const FIXTURE_PROGRAM: [u8; 32] =
        hex_literal::hex!("003d32bf7d76bad6f5d59998dee2727d2abab29017833136c5e6611cbf453642");

    #[cfg(not(feature = "use-test-vk"))]
    #[tokio::test]
    async fn real_bridge_proof_verifies_only_with_its_program_and_public_values() {
        let receipt: Receipt = borsh::from_slice(include_bytes!(
            "../tests/fixtures/regtest-bridge-network.borsh"
        ))
        .unwrap();
        let program = ProgramKey {
            recursion: [0; 8],
            groth16: FIXTURE_PROGRAM,
        };
        let bitvm = |receipt: &Receipt, program: &[u8; 32]| {
            crate::bitvm_verifier::verify_bitvm(
                program,
                &receipt.groth16_proof()?,
                bridge_sp1::public_input_blake3(&receipt.journal.bytes),
            )
        };
        verify(&receipt, program, false).await.unwrap();
        bitvm(&receipt, &FIXTURE_PROGRAM).unwrap();
        assert!(verify(&receipt, test_key(0), false).await.is_err());
        assert!(bitvm(&receipt, &[0; 32]).is_err());

        let mut altered = receipt.clone();
        altered.journal.bytes[0] ^= 1;
        assert!(verify(&altered, program, false).await.is_err());
        assert!(bitvm(&altered, &FIXTURE_PROGRAM).is_err());

        let mut altered = receipt.clone();
        let Proof::Groth16(proof) = &mut altered.inner else {
            panic!("Fixture must be a production Groth16 proof");
        };
        let last = proof.seal.len() - 1;
        proof.seal[last] ^= 1;
        assert!(verify(&altered, program, false).await.is_err());
        assert!(bitvm(&altered, &FIXTURE_PROGRAM).is_err());

        let mock = Receipt::mock(program.recursion, receipt.journal.bytes.clone());
        assert!(verify(&mock, program, false).await.is_err());
    }
}
