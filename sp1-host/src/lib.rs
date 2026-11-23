//! Reusable SP1 SDK adapter, independent of bridge inputs, receipts and Bitcoin policy.
use eyre::{eyre, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    env::{EnvProver, EnvProvingKey},
    Elf, HashableKey, LightProver, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProofMode, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::{
    collections::HashMap,
    env::VarError,
    sync::{Arc, LazyLock, Mutex},
};
use tokio::sync::OnceCell;

/// Proving backend, selected by SP1's standard environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    Mock,
    Cpu,
    Network,
}

impl Backend {
    /// Reads the backend from `SP1_PROVER`, which defaults to `network`.
    pub fn from_env() -> Result<Self> {
        match std::env::var("SP1_PROVER").as_deref() {
            Ok("mock") => Ok(Self::Mock),
            Ok("cpu") => Ok(Self::Cpu),
            Ok("network") | Err(VarError::NotPresent) => Ok(Self::Network),
            Ok(other) => Err(eyre!(
                "Unsupported SP1_PROVER={other}; use mock, cpu or network"
            )),
            Err(VarError::NotUnicode(_)) => Err(eyre!("SP1_PROVER is not valid Unicode")),
        }
    }

    async fn client(self) -> &'static EnvProver {
        static MOCK: OnceCell<EnvProver> = OnceCell::const_new();
        static CPU: OnceCell<EnvProver> = OnceCell::const_new();
        static NETWORK: OnceCell<EnvProver> = OnceCell::const_new();
        match self {
            Self::Mock => {
                MOCK.get_or_init(|| async {
                    EnvProver::Mock(ProverClient::builder().mock().build().await)
                })
                .await
            }
            Self::Cpu => {
                CPU.get_or_init(|| async {
                    EnvProver::Cpu(ProverClient::builder().cpu().build().await)
                })
                .await
            }
            Self::Network => {
                NETWORK
                    .get_or_init(|| async {
                        EnvProver::Network(ProverClient::builder().network().build().await)
                    })
                    .await
            }
        }
    }
}

/// A cached prover and key for one guest and backend.
pub struct Host {
    client: &'static EnvProver,
    key: EnvProvingKey,
}

type HostCell = Arc<OnceCell<Arc<Host>>>;
type HostCache = HashMap<(Backend, [u8; 32]), HostCell>;
static HOSTS: LazyLock<Mutex<HostCache>> = LazyLock::new(Default::default);

/// Execute without preparing a proving key or checking recursion witnesses.
pub async fn execute(elf: &[u8], stdin: SP1Stdin) -> Result<Vec<u8>> {
    run(
        Backend::Mock.client().await,
        Elf::from(elf.to_vec()),
        stdin,
        false,
    )
    .await
    .map(|(values, _, _)| values)
}

/// Verifies a compressed proof of `vk` with public values `public_values`, including the
/// successful exit code, with SP1's full verifier.
///
/// This uses a light prover rather than a backend client: SP1's mock prover accepts every
/// compressed proof without checking it.
pub async fn verify_compressed(
    proof: SP1Proof,
    public_values: &[u8],
    vk: SP1VerifyingKey,
) -> Result<()> {
    static LIGHT: OnceCell<LightProver> = OnceCell::const_new();
    eyre::ensure!(
        matches!(proof, SP1Proof::Compressed(_)),
        "Expected a compressed SP1 proof"
    );
    let prover = LIGHT
        .get_or_init(|| async { ProverClient::builder().light().build().await })
        .await;
    let proof = SP1ProofWithPublicValues::new(
        proof,
        SP1PublicValues::from(public_values),
        prover.version().to_string(),
    );
    // The SDK verifies synchronously, so keep the STARK verification off the async workers.
    tokio::task::spawn_blocking(move || prover.verify(&proof, &vk, None))
        .await
        .map_err(|e| eyre!("Compressed SP1 verification task failed: {e}"))?
        .map_err(|e| eyre!("Compressed SP1 verification failed: {e}"))
}

impl Host {
    /// Concurrent callers share the same setup, without retaining another copy of each ELF.
    pub async fn get(elf: &[u8], backend: Backend) -> Result<Arc<Self>> {
        let digest: [u8; 32] = Sha256::digest(elf).into();
        let cell = HOSTS
            .lock()
            .map_err(|_| eyre!("SP1 host cache poisoned"))?
            .entry((backend, digest))
            .or_default()
            .clone();
        Ok(cell
            .get_or_try_init(|| async {
                let client = backend.client().await;
                let key = client
                    .setup(Elf::from(elf.to_vec()))
                    .await
                    .map_err(|e| eyre!("SP1 setup failed: {e}"))?;
                Ok::<_, eyre::Report>(Arc::new(Self { client, key }))
            })
            .await?
            .clone())
    }

    pub fn verifying_key(&self) -> &SP1VerifyingKey {
        self.key.verifying_key()
    }

    pub fn program_id(&self) -> Result<[u8; 32]> {
        hex::decode(self.verifying_key().bytes32().trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| eyre!("Invalid SP1 program key"))
    }

    /// Execute without verifying recursion witnesses, for explicit mock execution only.
    pub async fn execute(&self, stdin: SP1Stdin) -> Result<Vec<u8>> {
        self.run(stdin, false).await.map(|(values, _, _)| values)
    }

    async fn run(&self, stdin: SP1Stdin, preflight: bool) -> Result<(Vec<u8>, u64, Option<u64>)> {
        run(self.client, self.key.elf().clone(), stdin, preflight).await
    }

    /// Prove with a caller-selected nonce. BLAKE3 network requests need the SDK 6.10
    /// compatibility path below until the network accepts its BLAKE3 simulation hint.
    pub async fn prove(
        &self,
        stdin: SP1Stdin,
        mode: SP1ProofMode,
        nonce: [u32; 4],
        blake3: bool,
    ) -> Result<SP1ProofWithPublicValues> {
        if matches!(self.client, EnvProver::Cpu(_)) {
            tracing::warn!(
                ?mode,
                "Proving on the local CPU (SP1_PROVER=cpu). Large proofs, such as header chain proofs from genesis, can run out of memory"
            );
        }
        if let (true, EnvProver::Network(network), EnvProvingKey::Network { pk, .. }) =
            (blake3, self.client, &self.key)
        {
            // Keep preflight (including deferred proof checks), omit only its incorrect
            // hash hint. Like SDK simulation, use the measured cycles and gas as limits.
            let (expected, cycles, gas) = self.run(stdin.clone(), true).await?;
            let gas = gas.ok_or_else(|| eyre!("SP1 preflight did not calculate gas"))?;
            eyre::ensure!(cycles > 0 && gas > 0, "SP1 preflight reported zero usage");
            let proof = network
                .prove(pk, stdin)
                .mode(mode)
                .with_proof_nonce(nonce)
                .skip_simulation(true)
                .cycle_limit(cycles)
                .gas_limit(gas)
                .await
                .map_err(|e| eyre!("SP1 proving failed: {e}"))?;
            eyre::ensure!(
                proof.public_values.as_slice() == expected,
                "SP1 proof public values differ from local preflight"
            );
            Ok(proof)
        } else {
            self.client
                .prove(&self.key, stdin)
                .mode(mode)
                .with_proof_nonce(nonce)
                .await
                .map_err(|e| eyre!("SP1 proving failed: {e}"))
        }
    }
}

async fn run(
    client: &EnvProver,
    elf: Elf,
    stdin: SP1Stdin,
    preflight: bool,
) -> Result<(Vec<u8>, u64, Option<u64>)> {
    let (stderr_tx, stderr_rx) = tokio::sync::watch::channel(String::new());
    // Keep SP1's default gas calculation: without it, SDK 6.10 reports exit code 0 and no
    // cycles even when the guest panics.
    let (values, report) = client
        .execute(elf, stdin)
        .deferred_proof_verification(preflight)
        .stderr(stderr_tx)
        .await
        .map_err(|e| eyre!("SP1 execution failed: {e}: {}", stderr_rx.borrow().as_str()))?;
    eyre::ensure!(
        report.exit_code == 0,
        "SP1 guest exited with code {}: {}",
        report.exit_code,
        stderr_rx.borrow().as_str()
    );
    Ok((
        values.to_vec(),
        report.total_instruction_count(),
        report.gas(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuits_lib::{
        common::programs::REGTEST,
        header_chain::{
            BlockHeaderCircuitOutput, ChainState, HeaderChainCircuitInput, HeaderChainPrevProofType,
        },
    };

    #[tokio::test]
    async fn shared_setup_and_preflight_preserve_execution_checks() {
        let elf = include_bytes!("../../sp1-circuits/elfs/regtest-header-chain.elf");
        let (first, second) =
            tokio::join!(Host::get(elf, Backend::Mock), Host::get(elf, Backend::Mock));
        let first = first.unwrap();
        assert!(Arc::ptr_eq(&first, &second.unwrap()));
        assert_eq!(first.program_id().unwrap(), REGTEST.header_chain.groth16);
        let input = HeaderChainCircuitInput {
            method_id: REGTEST.header_chain.recursion,
            prev_proof: HeaderChainPrevProofType::GenesisBlock(ChainState::genesis_state()),
            block_headers: vec![],
        };
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).unwrap());
        let (values, cycles, gas) = first.run(stdin.clone(), true).await.unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&values).unwrap();
        assert_eq!(output.method_id, input.method_id);
        assert!(cycles > 0 && gas.unwrap() > 0);
        assert_eq!(values, first.execute(stdin.clone()).await.unwrap());

        // The mock prover's compressed proof is a placeholder that real verification rejects.
        let mock = first
            .prove(stdin.clone(), SP1ProofMode::Compressed, [0; 4], false)
            .await
            .unwrap();
        let vk = first.verifying_key().clone();
        let error = verify_compressed(mock.proof, &values, vk)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .starts_with("Compressed SP1 verification failed"));

        assert_eq!(values, execute(elf, stdin).await.unwrap());
        let mut invalid = SP1Stdin::new();
        invalid.write_vec(vec![0xff]);
        assert!(first.run(invalid, true).await.is_err());
    }
}
