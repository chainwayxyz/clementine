use std::ops::Deref;
use std::sync::Arc;

use crate::compatibility::{ActorWithConfig, CompatibilityParams};
use crate::constants::{
    ENTITY_COMP_DATA_POLL_TIMEOUT, ENTITY_STATUS_POLL_TIMEOUT, OPERATOR_GET_KEYS_TIMEOUT,
    PUBLIC_KEY_COLLECTION_TIMEOUT, VERIFIER_SEND_KEYS_TIMEOUT,
};
use crate::deposit::DepositData;
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::rpc::clementine::entity_data_with_id::DataResult;
use crate::rpc::clementine::entity_status_with_id::StatusResult;
use crate::rpc::clementine::{
    self, CompatibilityParamsRpc, DepositParams, Empty, EntityStatusWithId, EntityType,
    OperatorKeysWithDeposit,
};
use crate::rpc::clementine::{EntityDataWithId, EntityId as RPCEntityId};
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
use futures::future::join_all;
use secp256k1::musig::{AggregatedNonce, PartialSignature};
use std::future::Future;
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
    pub(crate) rpc: ExtendedBitcoinRpc,
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
    Aggregator,
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
            EntityId::Aggregator => write!(f, "Aggregator"),
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

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
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
            crate::rpc::verifier_client_builder(&config),
            &config,
            true,
        )
        .await?;

        // Create clients to connect to all operators
        let operator_clients = rpc::get_clients(
            operator_endpoints,
            crate::rpc::operator_client_builder(&config),
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

    /// Generic helper function to fetch keys from clients
    async fn fetch_pubkeys_from_entities<T, C, F, Fut>(
        &self,
        clients: &[C],
        keys_storage: &RwLock<Vec<Option<T>>>,
        pubkey_fetcher: F,
        key_type_name: &str,
    ) -> Result<Vec<T>, BridgeError>
    where
        T: Clone + Send + Sync,
        C: Clone + Send + Sync,
        F: Fn(C) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, BridgeError>> + Send,
    {
        // Check if all keys are collected
        let all_collected = {
            let keys = keys_storage.read().await;
            keys.iter().all(|key| key.is_some())
        };

        if !all_collected {
            // get a write lock early, so that only one thread can try to collect keys
            let mut keys = keys_storage.write().await;

            // sanity check because we directly use indexes below
            if keys.len() != clients.len() {
                return Err(eyre::eyre!(
                    "Keys storage length does not match clients length, should not happen, keys length: {}, clients length: {}",
                    keys.len(),
                    clients.len()
                )
                .into());
            }

            let key_collection_futures = clients
                .iter()
                .zip(keys.iter().enumerate())
                .filter_map(|(client, (idx, key))| {
                    if key.is_none() {
                        Some((idx, pubkey_fetcher(client.clone())))
                    } else {
                        None
                    }
                })
                .map(|(idx, fut)| async move { (idx, fut.await) });

            let collected_keys = join_all(key_collection_futures).await;
            let mut missing_keys = Vec::new();

            // Fill in keys with the results of the futures
            for (idx, new_key) in collected_keys {
                match new_key {
                    Ok(new_key) => keys[idx] = Some(new_key),
                    Err(e) => {
                        tracing::debug!(
                            "Failed to collect {} {} (order in config) key: {}",
                            key_type_name,
                            idx,
                            e
                        );
                        missing_keys.push(idx);
                    }
                }
            }

            // if not all keys were collected, return an error
            if keys.iter().any(|key| key.is_none()) {
                return Err(eyre::eyre!(
                    "Not all {} keys were able to be collected, missing keys at indices: {:?}",
                    key_type_name,
                    missing_keys
                )
                .into());
            }
        }

        // return all keys if they were all collected
        Ok(keys_storage
            .read()
            .await
            .iter()
            .map(|key| key.clone().expect("should all be collected"))
            .collect())
    }

    /// If all verifier keys are already collected, returns them.
    /// Otherwise, it tries to collect them from the verifiers, saves them and returns them.
    pub async fn fetch_verifier_keys(&self) -> Result<Vec<PublicKey>, BridgeError> {
        self.fetch_pubkeys_from_entities(
            &self.verifier_clients,
            &self.verifier_keys,
            |mut client| async move {
                let mut request = Request::new(Empty {});
                request.set_timeout(PUBLIC_KEY_COLLECTION_TIMEOUT);
                let verifier_params = client.get_params(request).await?.into_inner();
                let public_key = PublicKey::from_slice(&verifier_params.public_key)
                    .map_err(|e| eyre::eyre!("Failed to parse verifier public key: {}", e))?;
                Ok::<_, BridgeError>(public_key)
            },
            "verifier",
        )
        .await
    }

    /// If all operator keys are already collected, returns them.
    /// Otherwise, it tries to collect them from the operators, saves them and returns them.
    pub async fn fetch_operator_keys(&self) -> Result<Vec<XOnlyPublicKey>, BridgeError> {
        self.fetch_pubkeys_from_entities(
            &self.operator_clients,
            &self.operator_keys,
            |mut client| async move {
                let mut request = Request::new(Empty {});
                request.set_timeout(PUBLIC_KEY_COLLECTION_TIMEOUT);
                let operator_xonly_pk: XOnlyPublicKey = client
                    .get_x_only_public_key(request)
                    .await?
                    .into_inner()
                    .try_into()?;
                Ok::<_, BridgeError>(operator_xonly_pk)
            },
            "operator",
        )
        .await
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

    /// Helper function to fetch keys for both operators and verifiers.
    /// Returns (operator_keys, verifier_keys) without failing if some entities are unreachable.
    async fn fetch_all_entity_keys(&self) -> (Vec<Option<XOnlyPublicKey>>, Vec<Option<PublicKey>>) {
        // Try to reach all operators and verifiers to collect keys, but do not return err if some can't be reached
        let _ = self.fetch_operator_keys().await;
        let _ = self.fetch_verifier_keys().await;

        let operator_keys = self.operator_keys.read().await.clone();
        let verifier_keys = self.verifier_keys.read().await.clone();

        (operator_keys, verifier_keys)
    }

    /// Helper function to add error entries for entities where keys couldn't be collected.
    fn add_unreachable_entity_errors<T, F>(
        results: &mut Vec<T>,
        operator_keys: &[Option<XOnlyPublicKey>],
        verifier_keys: &[Option<PublicKey>],
        error_constructor: F,
    ) where
        F: Fn(EntityType, String, String) -> T,
    {
        for (index, key) in operator_keys.iter().enumerate() {
            if key.is_none() {
                results.push(error_constructor(
                    EntityType::Operator,
                    format!("Index {} in config (0-based)", index),
                    "Operator key was not able to be collected".to_string(),
                ));
            }
        }
        for (index, key) in verifier_keys.iter().enumerate() {
            if key.is_none() {
                results.push(error_constructor(
                    EntityType::Verifier,
                    format!("Index {} in config (0-based)", index),
                    "Verifier key was not able to be collected".to_string(),
                ));
            }
        }
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

        let (operator_keys, verifier_keys) = self.fetch_all_entity_keys().await;

        // Query operators for status
        let operator_status = join_all(
            operator_clients
                .iter()
                .zip(operator_keys.iter())
                .filter_map(|(client, key)| key.as_ref().map(|k| (client, k)))
                .map(|(client, key)| {
                    let mut client = client.clone();
                    let key = *key;
                    async move {
                        tracing::debug!("Getting operator status for {:?}", key);
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

        // Query verifiers for status
        let verifier_status = join_all(
            verifier_clients
                .iter()
                .zip(verifier_keys.iter())
                .filter_map(|(client, key)| key.as_ref().map(|k| (client, k)))
                .map(|(client, key)| {
                    let mut client = client.clone();
                    let key = *key;
                    async move {
                        tracing::debug!("Getting verifier status for {:?}", key);
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

        // Combine results
        let mut entity_statuses = operator_status;
        entity_statuses.extend(verifier_status);

        // Restart background tasks if requested
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

        // Add error entries for unreachable entities
        Self::add_unreachable_entity_errors(
            &mut entity_statuses,
            &operator_keys,
            &verifier_keys,
            |entity_type, id, error_msg| EntityStatusWithId {
                entity_id: Some(RPCEntityId {
                    kind: entity_type as i32,
                    id,
                }),
                status_result: Some(StatusResult::Err(clementine::EntityError {
                    error: error_msg,
                })),
            },
        );

        Ok(entity_statuses)
    }

    pub async fn get_compatibility_data_from_entities(
        &self,
    ) -> Result<Vec<EntityDataWithId>, BridgeError> {
        let operator_clients = self.get_operator_clients();
        let verifier_clients = self.get_verifier_clients();

        let (operator_keys, verifier_keys) = self.fetch_all_entity_keys().await;

        // Query operators for compatibility data
        let operator_comp_data = join_all(
            operator_clients
                .iter()
                .zip(operator_keys.iter())
                .filter_map(|(client, key)| key.as_ref().map(|k| (client, k)))
                .map(|(client, key)| {
                    let mut client = client.clone();
                    let key = *key;
                    async move {
                        tracing::debug!("Getting operator compatibility data for {:?}", key);
                        let mut request = Request::new(Empty {});
                        request.set_timeout(ENTITY_COMP_DATA_POLL_TIMEOUT);
                        let response = client.get_compatibility_params(request).await;

                        EntityDataWithId {
                            entity_id: Some(RPCEntityId {
                                kind: EntityType::Operator as i32,
                                id: key.to_string(),
                            }),
                            data_result: match response {
                                Ok(response) => Some(DataResult::Data(response.into_inner())),
                                Err(e) => Some(DataResult::Error(e.to_string())),
                            },
                        }
                    }
                }),
        )
        .await;

        // Query verifiers for compatibility data
        let verifier_comp_data = join_all(
            verifier_clients
                .iter()
                .zip(verifier_keys.iter())
                .filter_map(|(client, key)| key.as_ref().map(|k| (client, k)))
                .map(|(client, key)| {
                    let mut client = client.clone();
                    let key = *key;
                    async move {
                        tracing::debug!("Getting verifier compatibility data for {:?}", key);
                        let mut request = Request::new(Empty {});
                        request.set_timeout(ENTITY_COMP_DATA_POLL_TIMEOUT);
                        let response = client.get_compatibility_params(request).await;

                        EntityDataWithId {
                            entity_id: Some(RPCEntityId {
                                kind: EntityType::Verifier as i32,
                                id: key.to_string(),
                            }),
                            data_result: match response {
                                Ok(response) => Some(DataResult::Data(response.into_inner())),
                                Err(e) => Some(DataResult::Error(e.to_string())),
                            },
                        }
                    }
                }),
        )
        .await;

        // Combine results
        let mut entities_comp_data = operator_comp_data;
        entities_comp_data.extend(verifier_comp_data);

        // add aggregators own data
        let aggregator_comp_data = EntityDataWithId {
            entity_id: Some(RPCEntityId {
                kind: EntityType::Aggregator as i32,
                id: "Aggregator".to_string(),
            }),
            data_result: {
                let compatibility_params: Result<CompatibilityParamsRpc, eyre::Report> =
                    self.get_compatibility_params()?.try_into();
                match compatibility_params {
                    Ok(compatibility_params) => Some(DataResult::Data(compatibility_params)),
                    Err(e) => Some(DataResult::Error(e.to_string())),
                }
            },
        };

        entities_comp_data.push(aggregator_comp_data);

        // Add error entries for unreachable entities
        Self::add_unreachable_entity_errors(
            &mut entities_comp_data,
            &operator_keys,
            &verifier_keys,
            |entity_type, id, error_msg| EntityDataWithId {
                entity_id: Some(RPCEntityId {
                    kind: entity_type as i32,
                    id,
                }),
                data_result: Some(DataResult::Error(error_msg)),
            },
        );

        Ok(entities_comp_data)
    }

    /// Checks compatibility with other actors.
    /// Returns an error if aggregator is not compatible with any of the other actors, or any other actor returns an error.
    pub async fn check_compatibility_with_actors(
        &self,
        verifiers_included: bool,
        operators_included: bool,
    ) -> Result<(), BridgeError> {
        let mut other_errors = Vec::new();
        let mut actors_compat_params = Vec::new();

        if operators_included {
            let operator_keys = self.fetch_operator_keys().await?;
            for (operator_id, operator_client) in operator_keys
                .into_iter()
                .map(OperatorId)
                .zip(self.operator_clients.iter())
            {
                let mut operator_client = operator_client.clone();

                let res = {
                    let compatibility_params: CompatibilityParams = operator_client
                        .get_compatibility_params(Empty {})
                        .await?
                        .into_inner()
                        .try_into()?;
                    actors_compat_params.push((operator_id.to_string(), compatibility_params));
                    Ok::<_, BridgeError>(())
                };
                if let Err(e) = res {
                    other_errors.push(format!(
                        "{} error while retrieving compatibility params: {}",
                        operator_id, e
                    ));
                }
            }
        }

        if verifiers_included {
            let verifier_keys = self.fetch_verifier_keys().await?;
            for (verifier_id, verifier_client) in verifier_keys
                .into_iter()
                .map(VerifierId)
                .zip(self.verifier_clients.iter())
            {
                let mut verifier_client = verifier_client.clone();

                let res = {
                    let compatibility_params: CompatibilityParams = verifier_client
                        .get_compatibility_params(Empty {})
                        .await?
                        .into_inner()
                        .try_into()?;
                    actors_compat_params.push((verifier_id.to_string(), compatibility_params));
                    Ok::<_, BridgeError>(())
                };
                if let Err(e) = res {
                    other_errors.push(format!(
                        "{} error while retrieving compatibility params: {}",
                        verifier_id, e
                    ));
                }
            }
        }

        // return both compatibility error and other errors (ex: connection)
        let is_compatible = self.is_compatible(actors_compat_params);
        if let Err(e) = is_compatible {
            if other_errors.is_empty() {
                return Err(e);
            } else {
                return Err(eyre::eyre!(
                    "Clementine not compatible with some actors: {}. Actors returned errors while retrieving compatibility params: {}",
                    e,
                    other_errors.join(", ")
                ).into());
            }
        }
        if !other_errors.is_empty() {
            return Err(eyre::eyre!(
                "Actors returned errors while retrieving compatibility params: {}",
                other_errors.join(", ")
            )
            .into());
        }

        Ok(())
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
