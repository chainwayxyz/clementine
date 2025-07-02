use crate::constants::{OPERATOR_GET_KEYS_TIMEOUT, VERIFIER_SEND_KEYS_TIMEOUT};
use crate::deposit::DepositData;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::{DepositParams, OperatorKeysWithDeposit};
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
use secp256k1::musig::{AggregatedNonce, PartialSignature};
use tonic::Status;
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
    verifier_keys: Vec<PublicKey>,
    operator_keys: Vec<XOnlyPublicKey>,
}

/// Wrapper struct that renders the verifier id in the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifierId(PublicKey);

/// Wrapper struct that renders the operator id in the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperatorId(XOnlyPublicKey);

impl std::fmt::Display for VerifierId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Verifier({}...)", &self.0.to_string()[..10])
    }
}

impl std::fmt::Display for OperatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operator({}...)", &self.0.to_string()[..10])
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

        let operator_keys =
            Aggregator::collect_operator_xonly_public_keys_with_clients(&operator_clients).await?;

        let (_, verifier_keys) =
            Aggregator::collect_verifier_public_keys_with_clients(&verifier_clients).await?;

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

    pub fn get_verifier_keys(&self) -> Vec<PublicKey> {
        self.verifier_keys.clone()
    }

    pub fn get_operator_keys(&self) -> Vec<XOnlyPublicKey> {
        self.operator_keys.clone()
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
            tokio::sync::broadcast::channel::<crate::rpc::clementine::OperatorKeysWithDeposit>(
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
        let verifier_keys = self.get_verifier_keys();
        let mut participating_verifiers = Vec::new();

        let verifiers = deposit_data.get_verifiers();

        for verifier_pk in verifiers {
            if let Some(pos) = verifier_keys.iter().position(|key| key == &verifier_pk) {
                participating_verifiers
                    .push((self.verifier_clients[pos].clone(), VerifierId(verifier_pk)));
            } else {
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
        let operator_keys = self.get_operator_keys();
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
}
