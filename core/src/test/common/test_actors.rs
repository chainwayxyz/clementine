//! Utility struct to control the actors in the test

use crate::bitvm_client::SECP;
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::get_clients;
use crate::servers::{
    create_aggregator_unix_server, create_operator_unix_server, create_verifier_unix_server,
};
use std::collections::BTreeMap;
use std::marker::PhantomData;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, XOnlyPublicKey};
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
    pub secret_key: bitcoin::secp256k1::SecretKey,
}

#[derive(Debug)]
pub struct TestOperator<C: CitreaClientT> {
    pub operator: ClementineOperatorClient<Channel>,
    pub config: BridgeConfig,
    pub shutdown_tx: oneshot::Sender<()>,
    pub socket_path: std::path::PathBuf,
    pub client_type: PhantomData<C>,
    pub secret_key: bitcoin::secp256k1::SecretKey,
    pub verifier_index: usize, // index of the verifier that this operator is associated with
}

#[derive(Debug)]
pub struct TestAggregator {
    pub aggregator: ClementineAggregatorClient<Channel>,
    pub config: BridgeConfig,
    pub shutdown_tx: oneshot::Sender<()>,
    pub socket_path: std::path::PathBuf,
}

/// This struct is used to control the actors in the test.
/// It contains the verifiers, operators, and aggregator.
/// It stores various information on each actor, can add and remove actors.
/// After each actor set change, the aggregator is restarted with the current actor set in it's config.
/// Each verifier and operator is indexes starting from 0, according to their creation order.
/// All gRPC servers are closed if the TestActors instance is dropped.
#[derive(Debug)]
pub struct TestActors<C: CitreaClientT> {
    verifiers: BTreeMap<usize, TestVerifier<C>>,
    operators: BTreeMap<usize, TestOperator<C>>,
    pub aggregator: TestAggregator,
    /// The next unused index for the verifiers, to ensure unique numbering
    pub verifier_next_index: usize,
    /// The next unused index for the operators, to ensure unique numbering
    pub operator_next_index: usize,
    /// The next unused index for the aggregator, to ensure unique numbering
    pub aggregator_next_index: usize,
    socket_dir: tempfile::TempDir,
    base_config: BridgeConfig,
}

impl<C: CitreaClientT> TestVerifier<C> {
    /// Create a new `TestVerifier` instance.
    ///
    /// # Parameters
    /// - `base_config`: The base configuration for all actors. For verifiers, the database name is appended with the index.
    /// - `socket_dir`: The directory to store the Unix sockets.
    /// - `index`: The index of the verifier (its position in `TestActors`).
    /// - `secret_key`: The secret key of the verifier.
    ///
    /// # Returns
    /// Returns a [`Result`](eyre::Result) containing the new [`TestVerifier`] instance on success, or an error if creation fails.
    pub async fn new(
        base_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        index: usize,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> eyre::Result<Self> {
        let socket_path = socket_dir.join(format!("verifier_{index}.sock"));
        let mut config_with_new_db = base_config.clone();
        config_with_new_db.db_name += &index.to_string();
        config_with_new_db.secret_key = secret_key;
        initialize_database(&config_with_new_db).await;

        if config_with_new_db
            .test_params
            .generate_varying_total_works_insufficient_total_work
            || config_with_new_db.test_params.generate_varying_total_works
            || config_with_new_db
                .test_params
                .generate_varying_total_works_first_two_valid
        {
            // Generate a new protocol paramset for each verifier
            // to ensure diverse total works.
            config_with_new_db.time_to_send_watchtower_challenge = config_with_new_db
                .time_to_send_watchtower_challenge
                .checked_add(index as u16)
                .expect("Failed to add time to send watchtower challenge");
        }

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
            secret_key,
        })
    }
}

impl<C: CitreaClientT> TestOperator<C> {
    /// Create a new `TestOperator` instance.
    ///
    /// # Parameters
    /// - `verifier_config`: The configuration of the verifier that this operator belongs to (only the secret key can be changed).
    /// - `socket_dir`: The directory to store the Unix sockets.
    /// - `index`: The index of the operator (its position in `TestActors`).
    /// - `verifier_index`: The index of the verifier that this operator belongs to (index in `TestActors`).
    /// - `secret_key`: The secret key of the operator.
    ///
    /// # Returns
    /// Returns a [`Result`](eyre::Result) containing the new [`TestOperator`] instance on success, or an error if creation fails.
    pub async fn new(
        verifier_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        index: usize,
        verifier_index: usize,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> eyre::Result<Self> {
        let socket_path = socket_dir.join(format!("operator_{index}.sock"));
        let mut operator_config = verifier_config.clone();
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
            secret_key,
            verifier_index,
        })
    }
}

impl TestAggregator {
    /// Create a new `TestAggregator` instance, using the base_config except the verifier and operator endpoints.
    ///
    /// # Parameters
    /// - `base_config`: The base configuration for the aggregator.
    /// - `socket_dir`: The directory to store the Unix sockets.
    /// - `verifier_paths`: The list of Unix socket paths for verifiers.
    /// - `operator_paths`: The list of Unix socket paths for operators.
    /// - `socket_suffix`: Suffix for the aggregator socket filename.
    ///
    /// # Returns
    /// Returns a [`Result`](eyre::Result) containing the new [`TestAggregator`] instance on success, or an error if creation fails.
    pub async fn new(
        base_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        verifier_paths: &[std::path::PathBuf],
        operator_paths: &[std::path::PathBuf],
        socket_suffix: Option<&str>,
    ) -> eyre::Result<Self> {
        let socket_name = match socket_suffix {
            Some(suffix) => format!("aggregator_{suffix}.sock"),
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
    /// Create a new `TestActors` instance.
    /// The verifiers and operators are created according to the secret keys in the config.
    ///
    /// # Parameters
    /// - `config`: The base configuration for all actors.
    ///
    /// # Returns
    /// Returns a [`Result`](eyre::Result) containing the new [`TestActors`] instance on success, or an error if creation fails.
    pub async fn new(config: &BridgeConfig) -> eyre::Result<Self> {
        let all_verifiers_secret_keys = &config.test_params.all_verifiers_secret_keys;
        let all_operators_secret_keys = &config.test_params.all_operators_secret_keys;

        // Create temporary directory for Unix sockets
        let socket_dir = tempfile::tempdir()?;

        // Create verifiers
        let mut verifiers = BTreeMap::new();
        for (i, &secret_key) in all_verifiers_secret_keys.iter().enumerate() {
            let verifier = TestVerifier::new(config, socket_dir.path(), i, secret_key).await?;
            verifiers.insert(i, verifier);
        }

        // Create operators
        let mut operators = BTreeMap::new();
        for (i, &secret_key) in all_operators_secret_keys.iter().enumerate() {
            let base_config = &verifiers[&i].config;
            let operator =
                TestOperator::new(base_config, socket_dir.path(), i, i, secret_key).await?;
            operators.insert(i, operator);
        }

        // Collect paths for aggregator
        let verifier_paths: Vec<_> = verifiers.values().map(|v| v.socket_path.clone()).collect();
        let operator_paths: Vec<_> = operators.values().map(|o| o.socket_path.clone()).collect();

        // Create aggregator
        let aggregator = TestAggregator::new(
            &verifiers[&0].config,
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
            verifier_next_index: num_total_verifiers,
            operator_next_index: num_total_operators,
            aggregator_next_index: num_total_aggregators,
            socket_dir,
            base_config: config.clone(),
        })
    }

    pub fn get_operator_client_by_index(&self, index: usize) -> ClementineOperatorClient<Channel> {
        self.operators[&index].operator.clone()
    }

    pub fn get_verifier_client_by_index(&self, index: usize) -> ClementineVerifierClient<Channel> {
        self.verifiers[&index].verifier.clone()
    }

    pub async fn get_operator_db_and_xonly_pk_by_index(
        &self,
        index: usize,
    ) -> (Database, XOnlyPublicKey) {
        let operator = &self.operators[&index];
        let db = Database::new(&operator.config).await.unwrap();
        let xonly_pk = operator.secret_key.x_only_public_key(&SECP).0;
        (db, xonly_pk)
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

    pub fn get_operator_by_index(&self, index: usize) -> Option<&TestOperator<C>> {
        self.operators.get(&index)
    }

    pub fn get_verifier_by_index(&self, index: usize) -> Option<&TestVerifier<C>> {
        self.verifiers.get(&index)
    }

    pub fn get_verifiers(&self) -> Vec<ClementineVerifierClient<Channel>> {
        self.verifiers
            .values()
            .map(|v| v.verifier.clone())
            .collect()
    }

    pub fn get_operators(&self) -> Vec<ClementineOperatorClient<Channel>> {
        self.operators
            .values()
            .map(|o| o.operator.clone())
            .collect()
    }

    /// Restart the aggregator by creating a new one with the current verifier and operator endpoints
    pub async fn restart_aggregator(&mut self) -> eyre::Result<()> {
        // Collect current paths for aggregator
        let verifier_paths: Vec<_> = self
            .verifiers
            .values()
            .map(|v| v.socket_path.clone())
            .collect();
        let operator_paths: Vec<_> = self
            .operators
            .values()
            .map(|o| o.socket_path.clone())
            .collect();

        // Create new aggregator
        self.aggregator_next_index += 1;
        let suffix = self.aggregator_next_index.to_string();
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

    /// Remove a verifier with the given index and restarts the aggregator with the current actor set.
    /// Returns an error if the verifier is the first verifier (which is used by the aggregator)
    /// or if there is an operator associated with the verifier. If there is an operator associated
    /// with the verifier, the operator needs to be removed first.
    pub async fn remove_verifier(&mut self, index: usize) -> eyre::Result<()> {
        if index == 0 {
            // can't remove the first verifier as first verifier is used by aggregator
            return Err(eyre::eyre!(
                "Cannot remove the first verifier, its aggregator's verifier"
            ));
        }
        if let Some((operator_index, _)) = self
            .operators
            .iter()
            .find(|(_, o)| o.verifier_index == index)
        {
            return Err(eyre::eyre!(
                "Cannot remove verifier, verifier's operator {} is still active",
                operator_index
            ));
        }
        self.verifiers.remove(&index);
        self.restart_aggregator().await?;
        Ok(())
    }

    /// Remove an operator with the given index and restarts the aggregator with the current actor set.
    pub async fn remove_operator(&mut self, index: usize) -> eyre::Result<()> {
        self.operators.remove(&index);
        self.restart_aggregator().await?;
        Ok(())
    }

    /// Add a verifier with the given secret key and restarts the aggregator with the current actor set.
    pub async fn add_verifier(
        &mut self,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> eyre::Result<()> {
        let verifier = TestVerifier::new(
            &self.base_config,
            self.socket_dir.path(),
            self.verifier_next_index,
            secret_key,
        )
        .await?;
        self.verifiers.insert(self.verifier_next_index, verifier);
        self.restart_aggregator().await?;
        self.verifier_next_index += 1;
        Ok(())
    }

    /// Add an operator with the given secret key and verifier index and restarts the aggregator with the current actor set.
    pub async fn add_operator(
        &mut self,
        secret_key: bitcoin::secp256k1::SecretKey,
        verifier_index: usize,
        reimburse_addr: Option<Address<NetworkUnchecked>>,
        collateral_funding_outpoint: Option<OutPoint>,
    ) -> eyre::Result<()> {
        if !self.verifiers.contains_key(&verifier_index) {
            return Err(eyre::eyre!(
                "Cannot add operator with verifier index {}, verifier {} does not exist",
                verifier_index,
                verifier_index
            ));
        }
        let base_config = BridgeConfig {
            operator_reimbursement_address: reimburse_addr,
            operator_collateral_funding_outpoint: collateral_funding_outpoint,
            ..self.verifiers[&verifier_index].config.clone()
        };
        let operator = TestOperator::new(
            &base_config,
            self.socket_dir.path(),
            self.operator_next_index,
            verifier_index,
            secret_key,
        )
        .await?;
        self.operators.insert(self.operator_next_index, operator);
        self.restart_aggregator().await?;
        self.operator_next_index += 1;
        Ok(())
    }

    /// Get the aggregated x-only public key of all current verifiers.
    pub fn get_nofn_aggregated_xonly_pk(&self) -> eyre::Result<bitcoin::XOnlyPublicKey> {
        let verifier_public_keys = self
            .verifiers
            .values()
            .map(|v| v.config.secret_key.public_key(&SECP))
            .collect::<Vec<_>>();
        let aggregated_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifier_public_keys, None)?;
        Ok(aggregated_pk)
    }

    /// Get the secret keys of all current verifiers.
    pub fn get_verifiers_secret_keys(&self) -> Vec<bitcoin::secp256k1::SecretKey> {
        self.verifiers.values().map(|v| v.secret_key).collect()
    }

    /// Get the secret keys of all current operators.
    pub fn get_operators_secret_keys(&self) -> Vec<bitcoin::secp256k1::SecretKey> {
        self.operators.values().map(|o| o.secret_key).collect()
    }

    /// Get the x-only public keys of all current operators.
    pub fn get_operators_xonly_pks(&self) -> Vec<bitcoin::XOnlyPublicKey> {
        self.get_operators_secret_keys()
            .into_iter()
            .map(|o| o.x_only_public_key(&SECP).0)
            .collect()
    }
}
