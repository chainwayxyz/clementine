use crate::deposit::DepositData;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::{DepositParams, OperatorKeysWithDeposit};
#[cfg(feature = "automation")]
use crate::tx_sender::TxSenderClient;
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
use futures_util::future::try_join_all;
use secp256k1::musig::{AggregatedNonce, PartialSignature};
use tonic::Status;

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
    ) -> Result<(), Status> {
        use tokio::time::{timeout, Duration};
        const OPERATION_TIMEOUT: Duration = Duration::from_secs(500);

        tracing::info!("Starting collect_and_distribute_keys");
        let start_time = std::time::Instant::now();

        let deposit_data: DepositData = deposit_params.clone().try_into()?;

        // Create channels with larger capacity to prevent blocking
        let (operator_keys_tx, operator_keys_rx) = tokio::sync::broadcast::channel(
            deposit_data.get_num_operators() * deposit_data.get_num_verifiers(),
        );
        let operator_rx_handles = (0..deposit_data.get_num_verifiers())
            .map(|_| operator_keys_rx.resubscribe())
            .collect::<Vec<_>>();

        let mut operators = self.get_participating_operators(&deposit_data).await?;
        let operator_xonly_pks = deposit_data.get_operators();
        let num_operators = deposit_data.get_num_operators();
        let deposit = deposit_params.clone();

        tracing::info!("Starting operator key collection");
        let get_operators_keys_handle = tokio::spawn(async move {
            let operator_futures = operators.iter_mut().zip(operator_xonly_pks.iter()).map(
                |(operator_client, operator_xonly_pk)| {
                    let deposit_params = deposit.clone();
                    let tx = operator_keys_tx.clone();
                    async move {
                        tracing::debug!("Requesting keys from operator {}", operator_xonly_pk);
                        let start = std::time::Instant::now();
                        let operator_keys = timeout(
                            OPERATION_TIMEOUT,
                            operator_client.get_deposit_keys(deposit_params.clone()),
                        )
                        .await
                        .map_err(|_| {
                            Status::deadline_exceeded("Operator key retrieval timed out")
                        })??
                        .into_inner();
                        tracing::debug!(
                            "Got keys from operator {} in {:?}",
                            operator_xonly_pk,
                            start.elapsed()
                        );

                        tx.send(OperatorKeysWithDeposit {
                            deposit_params: Some(deposit_params),
                            operator_keys: Some(operator_keys),
                            operator_xonly_pk: operator_xonly_pk.serialize().to_vec(),
                        })
                        .map_err(|_| Status::internal("Failed to send operator keys"))?;
                        Ok::<_, Status>(())
                    }
                },
            );
            try_join_all(operator_futures).await
        });

        tracing::info!("Starting operator key distribution to verifiers");
        let mut verifiers = self.get_participating_verifiers(&deposit_data).await?;
        let distribute_operators_keys_handle = tokio::spawn(async move {
            let distribution_futures = verifiers.iter_mut().zip(operator_rx_handles).map(
                |(verifier, mut rx)| async move {
                    // Only wait for expected number of messages
                    let mut received_keys = std::collections::HashSet::new();
                    while received_keys.len() < num_operators {
                        tracing::debug!(
                            "Waiting for operator key (received {}/{})",
                            received_keys.len(),
                            num_operators
                        );
                        let start = std::time::Instant::now();
                        match timeout(OPERATION_TIMEOUT, rx.recv()).await {
                            Ok(Ok(operator_keys)) => {
                                let operator_xonly_pk = operator_keys.operator_xonly_pk.clone();
                                if received_keys.insert(operator_xonly_pk.clone()) {
                                    tracing::debug!(
                                        "Received operator key {:?} in {:?}",
                                        operator_xonly_pk,
                                        start.elapsed()
                                    );
                                    timeout(
                                        OPERATION_TIMEOUT,
                                        verifier.set_operator_keys(operator_keys),
                                    )
                                    .await
                                    .map_err(|_| {
                                        Status::deadline_exceeded("Setting operator keys timed out")
                                    })??;
                                }
                            }
                            Ok(Err(_)) => break, // Channel closed
                            Err(_) => {
                                return Err(Status::deadline_exceeded(
                                    "Timeout waiting for operator keys",
                                ))
                            }
                        }
                    }
                    Ok::<_, Status>(())
                },
            );
            try_join_all(distribution_futures).await
        });

        // Wait for all tasks with a timeout
        let result = match timeout(
            OPERATION_TIMEOUT,
            try_join_all(vec![
                get_operators_keys_handle,
                distribute_operators_keys_handle,
            ]),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(Status::internal(format!(
                "Failed to collect and distribute keys: {:?}",
                e
            ))),
            Err(_) => Err(Status::deadline_exceeded(
                "Overall key collection and distribution timed out",
            )),
        };

        tracing::info!(
            "collect_and_distribute_keys completed in {:?}",
            start_time.elapsed()
        );

        result
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn aggregate_move_partial_sigs(
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
            &verifiers_public_keys,
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
    ) -> Result<Vec<ClementineVerifierClient<tonic::transport::Channel>>, BridgeError> {
        let verifier_keys = self.get_verifier_keys();
        let mut participating_verifiers = Vec::new();

        let verifiers = deposit_data.get_verifiers();

        for verifier_pk in verifiers {
            if let Some(pos) = verifier_keys.iter().position(|key| key == &verifier_pk) {
                participating_verifiers.push(self.verifier_clients[pos].clone());
            } else {
                return Err(BridgeError::VerifierNotFound(verifier_pk));
            }
        }

        Ok(participating_verifiers)
    }

    /// Returns a list of operator clients that are participating in the deposit.
    pub async fn get_participating_operators(
        &self,
        deposit_data: &DepositData,
    ) -> Result<Vec<ClementineOperatorClient<tonic::transport::Channel>>, BridgeError> {
        let operator_keys = self.get_operator_keys();
        let mut participating_operators = Vec::new();

        let operators = deposit_data.get_operators();

        for operator_pk in operators {
            if let Some(pos) = operator_keys.iter().position(|key| key == &operator_pk) {
                participating_operators.push(self.operator_clients[pos].clone());
            } else {
                return Err(BridgeError::OperatorNotFound(operator_pk));
            }
        }

        Ok(participating_operators)
    }
}
