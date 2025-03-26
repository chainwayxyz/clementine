use crate::builder::transaction::DepositData;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::{DepositParams, OperatorKeysWithDeposit};
use crate::tx_sender::TxSenderClient;
use crate::verifier::NofN;
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
use bitcoin::secp256k1::{schnorr, Message};
use eyre::eyre;
use futures_util::future::try_join_all;
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature};
use std::sync::Arc;
use tonic::Status;

/// Aggregator struct.
/// This struct is responsible for aggregating partial signatures from the verifiers.
/// It will have in total 3 * num_operator + 1 aggregated nonces.
/// [0] -> Aggregated nonce for the move transaction.
/// [1..num_operator + 1] -> Aggregated nonces for the operator_takes transactions.
/// [num_operator + 1..2 * num_operator + 1] -> Aggregated nonces for the slash_or_take transactions.
/// [2 * num_operator + 1..3 * num_operator + 1] -> Aggregated nonces for the burn transactions.
/// For now, we do not have the last bit.
#[derive(Debug, Clone)]
pub struct Aggregator {
    pub(crate) rpc: ExtendedRpc,
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,
    pub(crate) nofn: Arc<tokio::sync::RwLock<Option<NofN>>>,
    pub(crate) tx_sender: TxSenderClient,
    pub(crate) verifier_clients: Vec<ClementineVerifierClient<tonic::transport::Channel>>,
    pub(crate) operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
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
                    "Couldn't find verifier endpoints in config file!".to_string(),
                ))?;
        let verifier_clients =
            rpc::get_clients(verifier_endpoints, ClementineVerifierClient::new).await?;

        let operator_endpoints =
            config
                .operator_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let operator_clients =
            rpc::get_clients(operator_endpoints, ClementineOperatorClient::new).await?;

        let tx_sender = TxSenderClient::new(db.clone(), "aggregator".to_string());

        tracing::info!(
            "Aggregator created with {} verifiers and {} operators",
            verifier_clients.len(),
            operator_clients.len(),
        );

        let nofn = Arc::new(tokio::sync::RwLock::new(None));

        Ok(Aggregator {
            rpc,
            db,
            config,
            nofn,
            tx_sender,
            verifier_clients,
            operator_clients,
        })
    }

    /// collects and distributes keys to verifiers from operators and watchtowers for the new deposit
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

        // Create channels with larger capacity to prevent blocking
        let (operator_keys_tx, operator_keys_rx) =
            tokio::sync::broadcast::channel(self.config.num_operators * self.config.num_verifiers);
        let operator_rx_handles = (0..self.config.num_verifiers)
            .map(|_| operator_keys_rx.resubscribe())
            .collect::<Vec<_>>();

        let mut operators = self.operator_clients.clone();
        let num_operators = operators.len();
        let deposit = deposit_params.clone();

        tracing::info!("Starting operator key collection");
        let get_operators_keys_handle = tokio::spawn(async move {
            let operator_futures =
                operators
                    .iter_mut()
                    .enumerate()
                    .map(|(idx, operator_client)| {
                        let deposit_params = deposit.clone();
                        let tx = operator_keys_tx.clone();
                        async move {
                            tracing::debug!("Requesting keys from operator {}", idx);
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
                                idx,
                                start.elapsed()
                            );

                            tx.send(OperatorKeysWithDeposit {
                                deposit_params: Some(deposit_params),
                                operator_keys: Some(operator_keys),
                                operator_idx: idx as u32,
                            })
                            .map_err(|_| Status::internal("Failed to send operator keys"))?;
                            Ok::<_, Status>(())
                        }
                    });
            try_join_all(operator_futures).await
        });

        tracing::info!("Starting operator key distribution to verifiers");
        let mut verifiers = self.verifier_clients.clone();
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
                                let operator_idx = operator_keys.operator_idx;
                                if received_keys.insert(operator_idx) {
                                    tracing::debug!(
                                        "Received operator key {} in {:?}",
                                        operator_idx,
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
    fn aggregate_move_partial_sigs(
        &self,
        deposit_data: DepositData,
        agg_nonce: &MusigAggNonce,
        partial_sigs: Vec<MusigPartialSignature>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let tx = builder::transaction::create_move_to_vault_txhandler(
            deposit_data,
            self.config.protocol_paramset(),
        )?;
        // println!("MOVE_TX: {:?}", tx);
        // println!("MOVE_TXID: {:?}", tx.tx.compute_txid());
        let message = Message::from_digest(
            tx.calculate_script_spend_sighash_indexed(0, 0, bitcoin::TapSighashType::Default)?
                .to_byte_array(),
        );

        let verifiers_public_keys = self
            .nofn
            .try_read()
            .map_err(|_| eyre!("Verifier index not set, yet"))?
            .clone()
            .ok_or(eyre!("Verifier index not set, yet"))?
            .public_keys;

        let final_sig = aggregate_partial_signatures(
            &verifiers_public_keys,
            None,
            *agg_nonce,
            &partial_sigs,
            message,
        )?;

        Ok(final_sig)
    }
}
