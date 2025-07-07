//! Utility struct to control the actors in the test

use crate::bitvm_client::SECP;
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::get_clients;
use crate::servers::{
    create_aggregator_unix_server, create_operator_unix_server, create_verifier_unix_server,
};
use std::marker::PhantomData;

use tokio::sync::oneshot;
use tonic::transport::Channel;

use super::initialize_database;

#[derive(Debug)]
pub struct TestVerifier<C: CitreaClientT> {
    pub verifier: ClementineVerifierClient<Channel>,
    pub config: BridgeConfig,
    pub shutdown_tx: oneshot::Sender<()>,
    pub socket_path: std::path::PathBuf,
    pub client_type: PhantomData<C>,
}

#[derive(Debug)]
pub struct TestOperator<C: CitreaClientT> {
    pub operator: ClementineOperatorClient<Channel>,
    pub config: BridgeConfig,
    pub shutdown_tx: oneshot::Sender<()>,
    pub socket_path: std::path::PathBuf,
    pub client_type: PhantomData<C>,
}

#[derive(Debug)]
pub struct TestAggregator {
    pub aggregator: ClementineAggregatorClient<Channel>,
    pub config: BridgeConfig,
    pub shutdown_tx: oneshot::Sender<()>,
    pub socket_path: std::path::PathBuf,
}

#[derive(Debug)]
pub struct TestActors<C: CitreaClientT> {
    verifiers: Vec<TestVerifier<C>>,
    operators: Vec<TestOperator<C>>,
    aggregator: TestAggregator,
    /// The total number of verifiers, including deleted ones, to ensure unique numbering
    num_total_verifiers: usize,
    /// The total number of operators, including deleted ones, to ensure unique numbering
    num_total_operators: usize,
    /// The total number of aggregators, including deleted ones, to ensure unique numbering
    num_total_aggregators: usize,
    socket_dir: tempfile::TempDir,
    base_config: BridgeConfig,
}

impl<C: CitreaClientT> TestVerifier<C> {
    /// Create a new TestVerifier instance
    pub async fn new(
        base_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        index: usize,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> eyre::Result<Self> {
        let socket_path = socket_dir.join(format!("verifier_{}.sock", index));
        let mut config_with_new_db = base_config.clone();
        config_with_new_db.db_name += &index.to_string();
        config_with_new_db.secret_key = secret_key;
        initialize_database(&config_with_new_db).await;

        let (socket_path, shutdown_tx) =
            create_verifier_unix_server::<C>(config_with_new_db.clone(), socket_path).await?;

        let verifier_client = get_clients(
            vec![format!("unix://{}", socket_path.display())],
            ClementineVerifierClient::new,
            &config_with_new_db,
            false,
        )
        .await?
        .pop()
        .ok_or_else(|| eyre::eyre!("Failed to connect to verifier"))?;

        Ok(TestVerifier {
            verifier: verifier_client,
            config: config_with_new_db,
            shutdown_tx,
            socket_path,
            client_type: PhantomData,
        })
    }
}

impl<C: CitreaClientT> TestOperator<C> {
    /// Create a new TestOperator instance
    pub async fn new(
        base_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        index: usize,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> eyre::Result<Self> {
        let socket_path = socket_dir.join(format!("operator_{}.sock", index));
        let mut operator_config = base_config.clone();
        operator_config.secret_key = secret_key;

        let (socket_path, shutdown_tx) =
            create_operator_unix_server::<C>(operator_config.clone(), socket_path).await?;

        let operator_client = get_clients(
            vec![format!("unix://{}", socket_path.display())],
            ClementineOperatorClient::new,
            &operator_config,
            false,
        )
        .await?
        .pop()
        .ok_or_else(|| eyre::eyre!("Failed to connect to operator"))?;

        Ok(TestOperator {
            operator: operator_client,
            config: operator_config,
            shutdown_tx,
            socket_path,
            client_type: PhantomData,
        })
    }
}

impl TestAggregator {
    /// Create a new TestAggregator instance, uses the base_config except the verifier and operator endpoints
    pub async fn new(
        base_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        verifier_paths: &[std::path::PathBuf],
        operator_paths: &[std::path::PathBuf],
        socket_suffix: Option<&str>,
    ) -> eyre::Result<Self> {
        let socket_name = match socket_suffix {
            Some(suffix) => format!("aggregator_{}.sock", suffix),
            None => "aggregator.sock".to_string(),
        };
        let aggregator_socket_path = socket_dir.join(socket_name);

        let aggregator_config = BridgeConfig {
            verifier_endpoints: Some(
                verifier_paths
                    .iter()
                    .map(|path| format!("unix://{}", path.display()))
                    .collect(),
            ),
            operator_endpoints: Some(
                operator_paths
                    .iter()
                    .map(|path| format!("unix://{}", path.display()))
                    .collect(),
            ),
            ..base_config.clone()
        };

        let (aggregator_path, aggregator_shutdown_tx) =
            create_aggregator_unix_server(aggregator_config.clone(), aggregator_socket_path)
                .await?;

        let aggregator_client = get_clients(
            vec![format!("unix://{}", aggregator_path.display())],
            ClementineAggregatorClient::new,
            &aggregator_config,
            false,
        )
        .await?
        .pop()
        .ok_or_else(|| eyre::eyre!("Failed to connect to aggregator"))?;

        Ok(TestAggregator {
            aggregator: aggregator_client,
            config: aggregator_config,
            shutdown_tx: aggregator_shutdown_tx,
            socket_path: aggregator_path,
        })
    }
}

impl<C: CitreaClientT> TestActors<C> {
    pub async fn new(config: &BridgeConfig) -> eyre::Result<Self> {
        let all_verifiers_secret_keys = &config.test_params.all_verifiers_secret_keys;
        let all_operators_secret_keys = &config.test_params.all_operators_secret_keys;

        // Create temporary directory for Unix sockets
        let socket_dir = tempfile::tempdir()?;

        // Create verifiers
        let mut verifiers = Vec::new();
        for (i, &secret_key) in all_verifiers_secret_keys.iter().enumerate() {
            let verifier = TestVerifier::new(config, socket_dir.path(), i, secret_key).await?;
            verifiers.push(verifier);
        }

        // Create operators
        let mut operators = Vec::new();
        for (i, &secret_key) in all_operators_secret_keys.iter().enumerate() {
            let base_config = &verifiers[i % verifiers.len()].config;
            let operator = TestOperator::new(base_config, socket_dir.path(), i, secret_key).await?;
            operators.push(operator);
        }

        // Collect paths for aggregator
        let verifier_paths: Vec<_> = verifiers.iter().map(|v| v.socket_path.clone()).collect();
        let operator_paths: Vec<_> = operators.iter().map(|o| o.socket_path.clone()).collect();

        // Create aggregator
        let aggregator = TestAggregator::new(
            &verifiers[0].config,
            socket_dir.path(),
            &verifier_paths,
            &operator_paths,
            None,
        )
        .await?;

        let num_total_verifiers = all_verifiers_secret_keys.len();
        let num_total_operators = all_operators_secret_keys.len();
        let num_total_aggregators = 1;

        Ok(TestActors {
            verifiers,
            operators,
            aggregator,
            num_total_verifiers,
            num_total_operators,
            num_total_aggregators,
            socket_dir,
            base_config: config.clone(),
        })
    }

    pub fn get_operator_by_index(&self, index: usize) -> ClementineOperatorClient<Channel> {
        self.operators[index].operator.clone()
    }

    pub fn get_verifier_by_index(&self, index: usize) -> ClementineVerifierClient<Channel> {
        self.verifiers[index].verifier.clone()
    }

    pub fn get_aggregator(&self) -> ClementineAggregatorClient<Channel> {
        self.aggregator.aggregator.clone()
    }

    pub fn get_num_verifiers(&self) -> usize {
        self.verifiers.len()
    }
    pub fn get_num_operators(&self) -> usize {
        self.operators.len()
    }

    pub fn get_verifiers(&self) -> Vec<ClementineVerifierClient<Channel>> {
        self.verifiers.iter().map(|v| v.verifier.clone()).collect()
    }

    pub fn get_operators(&self) -> Vec<ClementineOperatorClient<Channel>> {
        self.operators.iter().map(|o| o.operator.clone()).collect()
    }

    /// Restart the aggregator by creating a new one with the current verifier and operator endpoints
    pub async fn restart_aggregator(&mut self) -> eyre::Result<()> {
        // Collect current paths for aggregator
        let verifier_paths: Vec<_> = self
            .verifiers
            .iter()
            .map(|v| v.socket_path.clone())
            .collect();
        let operator_paths: Vec<_> = self
            .operators
            .iter()
            .map(|o| o.socket_path.clone())
            .collect();

        // Create new aggregator
        self.num_total_aggregators += 1;
        let suffix = self.num_total_aggregators.to_string();
        let new_aggregator = TestAggregator::new(
            &self.aggregator.config,
            self.socket_dir.path(),
            &verifier_paths,
            &operator_paths,
            Some(&suffix),
        )
        .await?;

        // Update the aggregator field
        self.aggregator = new_aggregator;
        Ok(())
    }

    pub async fn remove_verifier(&mut self, index: usize) -> eyre::Result<()> {
        if index == 0 {
            // cant remove the first verifier as first verifier is used by aggregator
            return Err(eyre::eyre!(
                "Cannot remove the first verifier, its aggregator's verifier"
            ));
        }
        self.verifiers.remove(index);
        self.restart_aggregator().await?;
        Ok(())
    }

    pub async fn remove_operator(&mut self, index: usize) -> eyre::Result<()> {
        self.operators.remove(index);
        self.restart_aggregator().await?;
        Ok(())
    }

    pub async fn add_verifier(
        &mut self,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> eyre::Result<()> {
        let verifier = TestVerifier::new(
            &self.base_config,
            self.socket_dir.path(),
            self.num_total_verifiers,
            secret_key,
        )
        .await?;
        self.verifiers.push(verifier);
        self.num_total_verifiers += 1;
        self.restart_aggregator().await?;
        Ok(())
    }

    pub async fn add_operator(
        &mut self,
        secret_key: bitcoin::secp256k1::SecretKey,
        verifier_index: usize,
    ) -> eyre::Result<()> {
        let base_config = &self.verifiers[verifier_index].config;
        let operator = TestOperator::new(
            base_config,
            self.socket_dir.path(),
            self.num_total_operators,
            secret_key,
        )
        .await?;
        self.operators.push(operator);
        self.num_total_operators += 1;
        self.restart_aggregator().await?;
        Ok(())
    }

    pub async fn get_nofn_aggregated_xonly_pk(&self) -> eyre::Result<bitcoin::XOnlyPublicKey> {
        let verifier_public_keys = self
            .verifiers
            .iter()
            .map(|v| v.config.secret_key.public_key(&SECP))
            .collect::<Vec<_>>();
        let aggregated_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifier_public_keys, None)?;
        Ok(aggregated_pk)
    }
}
