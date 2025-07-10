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

use bitcoin::XOnlyPublicKey;
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

#[derive(Debug)]
pub struct TestActors<C: CitreaClientT> {
    verifiers: BTreeMap<usize, TestVerifier<C>>,
    operators: BTreeMap<usize, TestOperator<C>>,
    aggregator: TestAggregator,
    /// The total number of verifiers, including deleted ones, to ensure unique numbering
    pub num_total_verifiers: usize,
    /// The total number of operators, including deleted ones, to ensure unique numbering
    pub num_total_operators: usize,
    /// The total number of aggregators, including deleted ones, to ensure unique numbering
    pub num_total_aggregators: usize,
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

        #[cfg(test)]
        {
            use crate::config::protocol::ProtocolParamset;

            if config_with_new_db
                .test_params
                .generate_varying_total_works_insufficient_total_work
                || config_with_new_db.test_params.generate_varying_total_works
            {
                // Generate a new protocol paramset for each verifier
                // to ensure diverse total works.
                let mut paramset = config_with_new_db.protocol_paramset().clone();
                paramset.time_to_send_watchtower_challenge = paramset
                    .time_to_send_watchtower_challenge
                    .checked_add(index as u16)
                    .expect("Failed to add time to send watchtower challenge");
                let paramset_ref: &'static ProtocolParamset = Box::leak(Box::new(paramset));

                config_with_new_db.protocol_paramset = paramset_ref;
            }
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
    /// Create a new TestOperator instance
    pub async fn new(
        base_config: &BridgeConfig,
        socket_dir: &std::path::Path,
        index: usize,
        verifier_index: usize,
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
            secret_key,
            verifier_index,
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
            num_total_verifiers,
            num_total_operators,
            num_total_aggregators,
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

    pub async fn remove_operator(&mut self, index: usize) -> eyre::Result<()> {
        self.operators.remove(&index);
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
        self.verifiers.insert(self.num_total_verifiers, verifier);
        self.num_total_verifiers += 1;
        self.restart_aggregator().await?;
        Ok(())
    }

    pub async fn add_operator(
        &mut self,
        secret_key: bitcoin::secp256k1::SecretKey,
        verifier_index: usize,
    ) -> eyre::Result<()> {
        if !self.verifiers.contains_key(&verifier_index) {
            return Err(eyre::eyre!(
                "Cannot add operator with verifier index {}, verifier {} does not exist",
                verifier_index,
                verifier_index
            ));
        }
        let base_config = &self.verifiers[&verifier_index].config;
        let operator = TestOperator::new(
            base_config,
            self.socket_dir.path(),
            self.num_total_operators,
            verifier_index,
            secret_key,
        )
        .await?;
        self.operators.insert(self.num_total_operators, operator);
        self.num_total_operators += 1;
        self.restart_aggregator().await?;
        Ok(())
    }

    pub fn get_nofn_aggregated_xonly_pk(&self) -> eyre::Result<bitcoin::XOnlyPublicKey> {
        let verifier_public_keys = self
            .verifiers
            .values()
            .map(|v| v.config.secret_key.public_key(&SECP))
            .collect::<Vec<_>>();
        let aggregated_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifier_public_keys, None)?;
        Ok(aggregated_pk)
    }

    pub fn get_verifiers_secret_keys(&self) -> Vec<bitcoin::secp256k1::SecretKey> {
        self.verifiers.values().map(|v| v.secret_key).collect()
    }

    pub fn get_operators_secret_keys(&self) -> Vec<bitcoin::secp256k1::SecretKey> {
        self.operators.values().map(|o| o.secret_key).collect()
    }

    pub fn get_operators_xonly_pks(&self) -> Vec<bitcoin::XOnlyPublicKey> {
        self.get_operators_secret_keys()
            .into_iter()
            .map(|o| o.x_only_public_key(&SECP).0)
            .collect()
    }
}
