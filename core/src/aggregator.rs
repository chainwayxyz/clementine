use std::ops::Deref;
use std::sync::Arc;

use crate::constants::{
    ENTITY_STATUS_POLL_TIMEOUT, OPERATOR_GET_KEYS_TIMEOUT, PUBLIC_KEY_COLLECTION_TIMEOUT,
    VERIFIER_SEND_KEYS_TIMEOUT,
};
use crate::deposit::DepositData;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::entity_status_with_id::StatusResult;
use crate::rpc::clementine::EntityId as RPCEntityId;
use crate::rpc::clementine::{
    self, DepositParams, Empty, EntityStatusWithId, EntityType, OperatorKeysWithDeposit,
};
use crate::task::aggregator_metric_publisher::AGGREGATOR_METRIC_PUBLISHER_POLL_DELAY;
use crate::task::TaskExt;
#[cfg(feature = "automation")]
use crate::tx_sender::TxSenderClient;
use crate::utils::{timed_request, timed_try_join_all};
use crate::{
    builder::{self},
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    musig2::aggregate_partial_signatures,
    rpc::{
        self,
        clementine::{
            clementine_operator_client::ClementineOperatorClient,
            clementine_verifier_client::ClementineVerifierClient,
        },
    },
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Message, PublicKey};
use bitcoin::XOnlyPublicKey;
use eyre::Context;
use futures::future::{join_all, try_join_all};
use secp256k1::musig::{AggregatedNonce, PartialSignature};
use tokio::sync::RwLock;
use tonic::{Request, Status};
use tracing::{debug_span, Instrument};

/// Aggregator struct.
/// This struct is responsible for aggregating partial signatures from the verifiers.
/// It will have in total 3 * num_operator + 1 aggregated nonces.
/// \[0\] -> Aggregated nonce for the move transaction.
/// [1..num_operator + 1] -> Aggregated nonces for the operator_takes transactions.
/// [num_operator + 1..2 * num_operator + 1] -> Aggregated nonces for the slash_or_take transactions.
/// [2 * num_operator + 1..3 * num_operator + 1] -> Aggregated nonces for the burn transactions.
/// For now, we do not have the last bit.
#[derive(Debug, Clone)]
pub struct Aggregator {
    pub(crate) rpc: ExtendedRpc,
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,
    #[cfg(feature = "automation")]
    pub(crate) tx_sender: TxSenderClient,
    operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
    verifier_clients: Vec<ClementineVerifierClient<tonic::transport::Channel>>,
    verifier_keys: Arc<RwLock<Vec<Option<PublicKey>>>>,
    operator_keys: Arc<RwLock<Vec<Option<XOnlyPublicKey>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityId {
    Verifier(VerifierId),
    Operator(OperatorId),
}

/// Wrapper struct that renders the verifier id in the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifierId(pub PublicKey);

/// Wrapper struct that renders the operator id in the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperatorId(pub XOnlyPublicKey);

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityId::Verifier(id) => write!(f, "{}", id),
            EntityId::Operator(id) => write!(f, "{}", id),
        }
    }
}

impl std::fmt::Display for VerifierId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Verifier({})", &self.0.to_string()[..10])
    }
}

impl std::fmt::Display for OperatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operator({})", &self.0.to_string()[..10])
    }
}

/// Wrapper struct that matches verifier clients with their ids.
#[derive(Debug, Clone)]
pub struct ParticipatingVerifiers(
    pub  Vec<(
        ClementineVerifierClient<tonic::transport::Channel>,
        VerifierId,
    )>,
);

impl ParticipatingVerifiers {
    pub fn new(
        verifiers: Vec<(
            ClementineVerifierClient<tonic::transport::Channel>,
            VerifierId,
        )>,
    ) -> Self {
        Self(verifiers)
    }

    pub fn clients(&self) -> Vec<ClementineVerifierClient<tonic::transport::Channel>> {
        self.0.iter().map(|(client, _)| client.clone()).collect()
    }

    pub fn ids(&self) -> Vec<VerifierId> {
        self.0.iter().map(|(_, id)| *id).collect()
    }
}

/// Wrapper struct that matches operator clients with their ids.
#[derive(Debug, Clone)]
pub struct ParticipatingOperators(
    pub  Vec<(
        ClementineOperatorClient<tonic::transport::Channel>,
        OperatorId,
    )>,
);

impl ParticipatingOperators {
    pub fn new(
        operators: Vec<(
            ClementineOperatorClient<tonic::transport::Channel>,
            OperatorId,
        )>,
    ) -> Self {
        Self(operators)
    }

    pub fn clients(&self) -> Vec<ClementineOperatorClient<tonic::transport::Channel>> {
        self.0.iter().map(|(client, _)| client.clone()).collect()
    }

    pub fn ids(&self) -> Vec<OperatorId> {
        self.0.iter().map(|(_, id)| *id).collect()
    }
}

impl Aggregator {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let db = Database::new(&config).await?;

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let verifier_endpoints =
            config
                .verifier_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "No verifier endpoints provided in config".into(),
                ))?;

        let operator_endpoints =
            config
                .operator_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "No operator endpoints provided in config".into(),
                ))?;

        // Create clients to connect to all verifiers
        let verifier_clients = rpc::get_clients(
            verifier_endpoints,
            ClementineVerifierClient::new,
            &config,
            true,
        )
        .await?;

        // Create clients to connect to all operators
        let operator_clients = rpc::get_clients(
            operator_endpoints,
            ClementineOperatorClient::new,
            &config,
            true,
        )
        .await?;

        #[cfg(feature = "automation")]
        let tx_sender = TxSenderClient::new(db.clone(), "aggregator".to_string());

        tracing::info!(
            "Aggregator created with {} verifiers and {} operators",
            verifier_clients.len(),
            operator_clients.len(),
        );

        let operator_keys = Arc::new(RwLock::new(vec![None; operator_clients.len()]));
        let verifier_keys = Arc::new(RwLock::new(vec![None; verifier_clients.len()]));

        Ok(Aggregator {
            rpc,
            db,
            config,
            #[cfg(feature = "automation")]
            tx_sender,
            verifier_clients,
            operator_clients,
            verifier_keys,
            operator_keys,
        })
    }

    pub fn get_verifier_clients(&self) -> &[ClementineVerifierClient<tonic::transport::Channel>] {
        &self.verifier_clients
    }

    /// If all verifier keys are already collected, returns them.
    /// Otherwise, it tries to collect them from the verifiers, saves them and returns them.
    pub async fn fetch_verifier_keys(&self) -> Result<Vec<PublicKey>, BridgeError> {
        // if all verifier keys are not collected, get a write lock and collect them
        if !self.check_verifier_keys_collected().await {
            let mut verifier_keys = self.verifier_keys.write().await;

            let futures = self
                .verifier_clients
                .iter()
                .zip(verifier_keys.iter())
                .filter(|(_, key)| key.is_none())
                .map(|(verifier_client, _)| {
                    let mut client = verifier_client.clone();
                    async move {
                        let mut request = Request::new(Empty {});
                        request.set_timeout(PUBLIC_KEY_COLLECTION_TIMEOUT);
                        let verifier_params = client.get_params(request).await?.into_inner();
                        let public_key = PublicKey::from_slice(&verifier_params.public_key)
                            .map_err(|e| {
                                eyre::eyre!("Failed to parse verifier public key: {}", e)
                            })?;
                        Ok::<_, BridgeError>(public_key)
                    }
                });

            let remaining_keys = try_join_all(futures).await?;

            // now fill in None entries
            let mut new_keys_iter = remaining_keys.into_iter();

            for key in verifier_keys.iter_mut() {
                if key.is_none() {
                    if let Some(new_key) = new_keys_iter.next() {
                        *key = Some(new_key);
                    } else {
                        return Err(eyre::eyre!(
                            "Not enough verifier keys collected, internal logic error"
                        )
                        .into());
                    }
                }
            }
        }
        // just get a read lock and return the keys
        Ok(self
            .verifier_keys
            .read()
            .await
            .iter()
            .enumerate()
            .map(|(idx, key)| key.ok_or(eyre::eyre!("Verifier {} key not collected yet", idx)))
            .collect::<Result<Vec<_>, _>>()?)
    }

    async fn check_verifier_keys_collected(&self) -> bool {
        let verifier_keys = self.verifier_keys.read().await;
        verifier_keys.iter().all(|key| key.is_some())
    }

    async fn check_operator_keys_collected(&self) -> bool {
        let operator_keys = self.operator_keys.read().await;
        operator_keys.iter().all(|key| key.is_some())
    }

    /// If all operator keys are already collected, returns them.
    /// Otherwise, it tries to collect them from the operators, saves them and returns them.
    pub async fn fetch_operator_keys(&self) -> Result<Vec<XOnlyPublicKey>, BridgeError> {
        // if all operator keys are not collected, get a write lock and collect them
        if !self.check_operator_keys_collected().await {
            let mut operator_keys = self.operator_keys.write().await;

            // collect the keys from the operators that we didn't collect from yet
            let futures = self
                .operator_clients
                .iter()
                .zip(operator_keys.iter())
                .filter(|(_, key)| key.is_none())
                .map(|(operator_client, _)| {
                    let mut client = operator_client.clone();
                    async move {
                        let mut request = Request::new(Empty {});
                        request.set_timeout(PUBLIC_KEY_COLLECTION_TIMEOUT);
                        let operator_keys: XOnlyPublicKey = client
                            .get_x_only_public_key(Request::new(Empty {}))
                            .await?
                            .into_inner()
                            .try_into()?;
                        Ok::<_, BridgeError>(operator_keys)
                    }
                });

            let collected_keys = try_join_all(futures).await?;

            // now fill in None entries
            let mut new_keys_iter = collected_keys.into_iter();

            for key in operator_keys.iter_mut() {
                if key.is_none() {
                    if let Some(new_key) = new_keys_iter.next() {
                        *key = Some(new_key);
                    } else {
                        return Err(eyre::eyre!(
                            "Not enough operator keys collected, internal logic error"
                        )
                        .into());
                    }
                }
            }
        }
        // just get a read lock and return the keys
        Ok(self
            .operator_keys
            .read()
            .await
            .iter()
            .enumerate()
            .map(|(idx, key)| key.ok_or(eyre::eyre!("Operator {} key not collected yet", idx)))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_operator_clients(&self) -> &[ClementineOperatorClient<tonic::transport::Channel>] {
        &self.operator_clients
    }

    /// Collects and distributes keys to verifiers from operators and watchtowers for the new deposit
    /// for operators: get bitvm assert winternitz public keys and watchtower challenge ack hashes
    /// for watchtowers: get winternitz public keys for watchtower challenges
    pub async fn collect_and_distribute_keys(
        &self,
        deposit_params: &DepositParams,
    ) -> Result<(), BridgeError> {
        tracing::info!("Starting collect_and_distribute_keys");

        let start_time = std::time::Instant::now();

        let deposit_data: DepositData = deposit_params.clone().try_into()?;

        // Create channels with larger capacity to prevent blocking
        let (operator_keys_tx, operator_keys_rx) =
            tokio::sync::broadcast::channel::<clementine::OperatorKeysWithDeposit>(
                deposit_data.get_num_operators() * deposit_data.get_num_verifiers(),
            );
        let operator_rx_handles = (0..deposit_data.get_num_verifiers())
            .map(|_| operator_keys_rx.resubscribe())
            .collect::<Vec<_>>();

        let operators = self.get_participating_operators(&deposit_data).await?;
        let operator_clients = operators.clients();

        let operator_xonly_pks = deposit_data.get_operators();
        let deposit = deposit_params.clone();

        tracing::info!("Starting operator key collection");
        #[cfg(test)]
        let timeout_params = self.config.test_params.timeout_params;
        #[allow(clippy::unused_enumerate_index)]
        let get_operators_keys_handle = tokio::spawn(timed_try_join_all(
            OPERATOR_GET_KEYS_TIMEOUT,
            "Operator key collection",
            Some(operators.ids()),
            operator_clients
                .into_iter()
                .zip(operator_xonly_pks.into_iter())
                .enumerate()
                .map(move |(_idx, (mut operator_client, operator_xonly_pk))| {
                    let deposit_params = deposit.clone();
                    let tx = operator_keys_tx.clone();
                    async move {
                        #[cfg(test)]
                        timeout_params
                            .hook_timeout_key_collection_operator(_idx)
                            .await;

                        let operator_keys = operator_client
                            .get_deposit_keys(deposit_params.clone())
                            .instrument(
                                debug_span!("get_deposit_keys", id=%OperatorId(operator_xonly_pk)),
                            )
                            .await
                            .wrap_err(Status::internal("Operator key retrieval failed"))?
                            .into_inner();

                        // A send error means that all receivers are closed,
                        // receivers only close if they have an error (while
                        // loop condition)
                        // We don't care about the result of the send, we
                        // only care about the error on the other side.
                        // Ignore this error, and let the other side's error
                        // propagate.
                        let _ = tx.send(OperatorKeysWithDeposit {
                            deposit_params: Some(deposit_params),
                            operator_keys: Some(operator_keys),
                            operator_xonly_pk: operator_xonly_pk.serialize().to_vec(),
                        });

                        Ok(())
                    }
                }),
        ));

        tracing::info!("Starting operator key distribution to verifiers");
        let verifiers = self.get_participating_verifiers(&deposit_data).await?;

        let verifier_clients = verifiers.clients();
        let num_operators = deposit_data.get_num_operators();

        let verifier_ids = verifiers.ids();

        #[cfg(test)]
        let timeout_params = self.config.test_params.timeout_params;
        #[allow(clippy::unused_enumerate_index)]
        let distribute_operators_keys_handle = tokio::spawn(timed_try_join_all(
            VERIFIER_SEND_KEYS_TIMEOUT,
            "Verifier key distribution",
            Some(verifier_ids.clone()),
            verifier_clients
                .into_iter()
                .zip(operator_rx_handles)
                .zip(verifier_ids)
                .enumerate()
                .map(
                    move |(_idx, ((mut verifier, mut rx), verifier_id))| async move {
                        #[cfg(test)]
                        timeout_params
                            .hook_timeout_key_distribution_verifier(_idx)
                            .await;

                        // Only wait for expected number of messages
                        let mut received_keys = std::collections::HashSet::new();
                        while received_keys.len() < num_operators {
                            tracing::debug!(
                                "Waiting for operator key (received {}/{})",
                                received_keys.len(),
                                num_operators
                            );

                            // This will not block forever because of the timeout on the join all.
                            let operator_keys = rx
                            .recv()
                            .instrument(debug_span!("operator_keys_recv"))
                            .await
                            .wrap_err(Status::internal(
                                "Operator broadcast channels closed before all keys were received",
                            ))?;

                            let operator_xonly_pk = operator_keys.operator_xonly_pk.clone();

                            if !received_keys.insert(operator_xonly_pk.clone()) {
                                continue;
                            }

                            timed_request(
                                VERIFIER_SEND_KEYS_TIMEOUT,
                                &format!("Setting operator keys for {}", verifier_id),
                                async {
                                    Ok(verifier
                                        .set_operator_keys(operator_keys)
                                        .await
                                        .wrap_err_with(|| {
                                            Status::internal(format!(
                                                "Failed to set operator keys for {}",
                                                verifier_id
                                            ))
                                        }))
                                },
                            )
                            .await??;
                        }
                        Ok::<_, BridgeError>(())
                    },
                ),
        ));

        // Wait for all tasks to complete
        let (get_operators_keys_result, distribute_operators_keys_result) =
            tokio::try_join!(get_operators_keys_handle, distribute_operators_keys_handle)
                .wrap_err(Status::internal("Task join error in key distribution"))?;

        get_operators_keys_result?;
        distribute_operators_keys_result?;

        tracing::info!(
            "collect_and_distribute_keys completed in {:?}",
            start_time.elapsed()
        );

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn _aggregate_move_partial_sigs(
        &self,
        deposit_data: &mut DepositData,
        agg_nonce: &AggregatedNonce,
        partial_sigs: Vec<PartialSignature>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let tx = builder::transaction::create_move_to_vault_txhandler(
            deposit_data,
            self.config.protocol_paramset(),
        )?;

        let message = Message::from_digest(
            tx.calculate_script_spend_sighash_indexed(0, 0, bitcoin::TapSighashType::Default)?
                .to_byte_array(),
        );

        let verifiers_public_keys = deposit_data.get_verifiers();

        let final_sig = aggregate_partial_signatures(
            verifiers_public_keys,
            None,
            *agg_nonce,
            &partial_sigs,
            message,
        )?;

        Ok(final_sig)
    }

    /// Returns a list of verifier clients that are participating in the deposit.
    pub async fn get_participating_verifiers(
        &self,
        deposit_data: &DepositData,
    ) -> Result<ParticipatingVerifiers, BridgeError> {
        let verifier_keys = self.fetch_verifier_keys().await?;
        let mut participating_verifiers = Vec::new();

        let verifiers = deposit_data.get_verifiers();

        for verifier_pk in verifiers {
            if let Some(pos) = verifier_keys.iter().position(|key| key == &verifier_pk) {
                participating_verifiers
                    .push((self.verifier_clients[pos].clone(), VerifierId(verifier_pk)));
            } else {
                tracing::error!(
                    "Verifier public key not found. Deposit data verifier keys: {:?}, self verifier keys: {:?}",
                    deposit_data.get_verifiers(),
                    self.verifier_keys
                );
                return Err(BridgeError::VerifierNotFound(verifier_pk));
            }
        }

        Ok(ParticipatingVerifiers::new(participating_verifiers))
    }

    /// Returns a list of operator clients that are participating in the deposit.
    pub async fn get_participating_operators(
        &self,
        deposit_data: &DepositData,
    ) -> Result<ParticipatingOperators, BridgeError> {
        let operator_keys = self.fetch_operator_keys().await?;
        let mut participating_operators = Vec::new();

        let operators = deposit_data.get_operators();

        for operator_pk in operators {
            if let Some(pos) = operator_keys.iter().position(|key| key == &operator_pk) {
                participating_operators
                    .push((self.operator_clients[pos].clone(), OperatorId(operator_pk)));
            } else {
                return Err(BridgeError::OperatorNotFound(operator_pk));
            }
        }

        Ok(ParticipatingOperators::new(participating_operators))
    }

    /// Retrieves the status of all entities (operators and verifiers) and restarts background tasks if needed.
    /// Returns a vector of EntityStatusWithId. Only returns an error if restarting tasks fails when requested.
    pub async fn get_entity_statuses(
        &self,
        restart_tasks: bool,
    ) -> Result<Vec<EntityStatusWithId>, BridgeError> {
        tracing::debug!("Getting entities status");

        let operator_clients = self.get_operator_clients();
        let verifier_clients = self.get_verifier_clients();
        tracing::debug!("Operator clients: {:?}", operator_clients.len());

        let operator_status = join_all(
            operator_clients
                .iter()
                .zip(self.fetch_operator_keys().await?.iter())
                .map(|(client, key)| {
                    let mut client = client.clone();
                    async move {
                        tracing::debug!("Getting operator status for {}", key.to_string());
                        let mut request = Request::new(Empty {});
                        request.set_timeout(ENTITY_STATUS_POLL_TIMEOUT);
                        let response = client.get_current_status(request).await;

                        EntityStatusWithId {
                            entity_id: Some(RPCEntityId {
                                kind: EntityType::Operator as i32,
                                id: key.to_string(),
                            }),
                            status_result: match response {
                                Ok(response) => Some(StatusResult::Status(response.into_inner())),
                                Err(e) => Some(StatusResult::Err(clementine::EntityError {
                                    error: e.to_string(),
                                })),
                            },
                        }
                    }
                }),
        )
        .await;

        let verifier_status = join_all(
            verifier_clients
                .iter()
                .zip(self.fetch_verifier_keys().await?.iter())
                .map(|(client, key)| {
                    let mut client = client.clone();
                    async move {
                        let mut request = Request::new(Empty {});
                        request.set_timeout(ENTITY_STATUS_POLL_TIMEOUT);
                        let response = client.get_current_status(request).await;

                        EntityStatusWithId {
                            entity_id: Some(RPCEntityId {
                                kind: EntityType::Verifier as i32,
                                id: key.to_string(),
                            }),
                            status_result: match response {
                                Ok(response) => Some(StatusResult::Status(response.into_inner())),
                                Err(e) => Some(StatusResult::Err(clementine::EntityError {
                                    error: e.to_string(),
                                })),
                            },
                        }
                    }
                }),
        )
        .await;

        // Combine operator and verifier status into a single vector
        let mut entity_statuses = operator_status;
        entity_statuses.extend(verifier_status);

        // try to restart background tasks if needed
        if restart_tasks {
            let operator_tasks = operator_clients.iter().map(|client| {
                let mut client = client.clone();
                async move {
                    client
                        .restart_background_tasks(Request::new(Empty {}))
                        .await
                }
            });

            let verifier_tasks = verifier_clients.iter().map(|client| {
                let mut client = client.clone();
                async move {
                    client
                        .restart_background_tasks(Request::new(Empty {}))
                        .await
                }
            });

            futures::try_join!(
                futures::future::try_join_all(operator_tasks),
                futures::future::try_join_all(verifier_tasks)
            )?;
        }
        Ok(entity_statuses)
    }
}

/// Aggregator server wrapper that manages background tasks.
#[derive(Debug)]
pub struct AggregatorServer {
    pub aggregator: Aggregator,
    background_tasks: crate::task::manager::BackgroundTaskManager,
}

impl AggregatorServer {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let aggregator = Aggregator::new(config.clone()).await?;
        let background_tasks = crate::task::manager::BackgroundTaskManager::default();

        Ok(Self {
            aggregator,
            background_tasks,
        })
    }

    /// Starts the background tasks for the aggregator.
    /// If called multiple times, it will restart only the tasks that are not already running.
    pub async fn start_background_tasks(&self) -> Result<(), BridgeError> {
        // Start the aggregator metric publisher task
        self.background_tasks
            .ensure_task_looping(
                crate::task::aggregator_metric_publisher::AggregatorMetricPublisher::new(
                    self.aggregator.clone(),
                )
                .await?
                .with_delay(AGGREGATOR_METRIC_PUBLISHER_POLL_DELAY),
            )
            .await;

        tracing::info!("Aggregator metric publisher task started");

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        self.background_tasks.graceful_shutdown().await;
    }
}

impl Deref for AggregatorServer {
    type Target = Aggregator;

    fn deref(&self) -> &Self::Target {
        &self.aggregator
    }
}
