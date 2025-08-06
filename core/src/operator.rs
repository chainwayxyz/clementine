use ark_ff::PrimeField;
use circuits_lib::common::constants::{FIRST_FIVE_OUTPUTS, NUMBER_OF_ASSERT_TXS};
use std::collections::HashMap;

use crate::actor::{Actor, TweakCache, WinternitzDerivationPath};
use crate::bitvm_client::{ClementineBitVMPublicKeys, SECP};
use crate::builder::script::extract_winternitz_commits;
use crate::builder::sighash::{create_operator_sighash_stream, PartialSignatureInfo};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::builder::transaction::{
    create_burn_unused_kickoff_connectors_txhandler, create_round_nth_txhandler,
    create_round_txhandlers, ContractContext, KickoffWinternitzKeys, TransactionType, TxHandler,
};
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::database::DatabaseTransaction;
use crate::deposit::{DepositData, KickoffData, OperatorData};
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::header_chain_prover::HeaderChainProver;
use crate::metrics::L1SyncStatusProvider;
use crate::rpc::clementine::EntityStatus;
use crate::task::entity_metric_publisher::{
    EntityMetricPublisher, ENTITY_METRIC_PUBLISHER_INTERVAL,
};
use crate::task::manager::BackgroundTaskManager;
use crate::task::payout_checker::{PayoutCheckerTask, PAYOUT_CHECKER_POLL_DELAY};
use crate::task::TaskExt;
use crate::utils::{Last20Bytes, ScriptBufExt};
use crate::utils::{NamedEntity, TxMetadata};
use crate::{builder, constants, UTXO};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::{Address, Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut};
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::RpcApi;
use bitvm::chunk::api::generate_assertions;
use bitvm::signatures::winternitz;
use bridge_circuit_host::bridge_circuit_host::{
    create_spv, prove_bridge_circuit, MAINNET_BRIDGE_CIRCUIT_ELF, REGTEST_BRIDGE_CIRCUIT_ELF,
    REGTEST_BRIDGE_CIRCUIT_ELF_TEST, SIGNET_BRIDGE_CIRCUIT_ELF, TESTNET4_BRIDGE_CIRCUIT_ELF,
};
use bridge_circuit_host::structs::{BridgeCircuitHostParams, WatchtowerContext};
use eyre::{Context, OptionExt};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

#[cfg(feature = "automation")]
use crate::{
    states::StateManager,
    task::IntoTask,
    tx_sender::{ActivatedWithOutpoint, ActivatedWithTxid, TxSenderClient},
    utils::FeePayingType,
};
#[cfg(feature = "automation")]
use bitcoin::Witness;

pub type SecretPreimage = [u8; 20];
pub type PublicHash = [u8; 20];

/// Round index is used to represent the round index safely.
/// Collateral represents the collateral utxo.
/// Round(index) represents the rounds of the bridge operators, index is 0-indexed.
/// As a single u32, collateral is represented as 0 and rounds are represented starting from 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Ord, PartialOrd,
)]
pub enum RoundIndex {
    Collateral,
    Round(usize), // 0-indexed
}

impl RoundIndex {
    /// Converts the round to a 0-indexed index.
    pub fn to_index(&self) -> usize {
        match self {
            RoundIndex::Collateral => 0,
            RoundIndex::Round(index) => *index + 1,
        }
    }

    /// Converts a 0-indexed index to a RoundIndex.
    /// Use this only when dealing with 0-indexed data. Currently these are data coming from the database and rpc.
    pub fn from_index(index: usize) -> Self {
        if index == 0 {
            RoundIndex::Collateral
        } else {
            RoundIndex::Round(index - 1)
        }
    }

    /// Returns the next RoundIndex.
    pub fn next_round(&self) -> Self {
        match self {
            RoundIndex::Collateral => RoundIndex::Round(0),
            RoundIndex::Round(index) => RoundIndex::Round(*index + 1),
        }
    }

    /// Creates an iterator over rounds from 0 to num_rounds (exclusive)
    /// Only iterates actual rounds, collateral is not included.
    pub fn iter_rounds(num_rounds: usize) -> impl Iterator<Item = RoundIndex> {
        Self::iter_rounds_range(0, num_rounds)
    }

    /// Creates an iterator over rounds from start to end (exclusive)
    /// Only iterates actual rounds, collateral is not included.
    pub fn iter_rounds_range(start: usize, end: usize) -> impl Iterator<Item = RoundIndex> {
        (start..end).map(RoundIndex::Round)
    }
}

pub struct OperatorServer<C: CitreaClientT> {
    pub operator: Operator<C>,
    background_tasks: BackgroundTaskManager,
}

#[derive(Debug, Clone)]
pub struct Operator<C: CitreaClientT> {
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub signer: Actor,
    pub config: BridgeConfig,
    pub collateral_funding_outpoint: OutPoint,
    pub(crate) reimburse_addr: Address,
    #[cfg(feature = "automation")]
    pub tx_sender: TxSenderClient,
    #[cfg(feature = "automation")]
    pub header_chain_prover: HeaderChainProver,
    pub citrea_client: C,
}

impl<C> OperatorServer<C>
where
    C: CitreaClientT,
{
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let operator = Operator::new(config.clone()).await?;
        let background_tasks = BackgroundTaskManager::default();

        Ok(Self {
            operator,
            background_tasks,
        })
    }

    /// Starts the background tasks for the operator.
    /// If called multiple times, it will restart only the tasks that are not already running.
    pub async fn start_background_tasks(&self) -> Result<(), BridgeError> {
        // initialize and run state manager
        #[cfg(feature = "automation")]
        {
            let paramset = self.operator.config.protocol_paramset();
            let state_manager =
                StateManager::new(self.operator.db.clone(), self.operator.clone(), paramset)
                    .await?;

            let should_run_state_mgr = {
                #[cfg(test)]
                {
                    self.operator.config.test_params.should_run_state_manager
                }
                #[cfg(not(test))]
                {
                    true
                }
            };

            if should_run_state_mgr {
                self.background_tasks
                    .ensure_task_looping(state_manager.block_fetcher_task().await?)
                    .await;
                self.background_tasks
                    .ensure_task_looping(state_manager.into_task())
                    .await;
            }
        }

        // run payout checker task
        self.background_tasks
            .ensure_task_looping(
                PayoutCheckerTask::new(self.operator.db.clone(), self.operator.clone())
                    .with_delay(PAYOUT_CHECKER_POLL_DELAY),
            )
            .await;

        self.background_tasks
            .ensure_task_looping(
                EntityMetricPublisher::<Operator<C>>::new(
                    self.operator.db.clone(),
                    self.operator.rpc.clone(),
                )
                .with_delay(ENTITY_METRIC_PUBLISHER_INTERVAL),
            )
            .await;

        tracing::info!("Payout checker task started");

        // track the operator's round state
        #[cfg(feature = "automation")]
        {
            // Will not start a new state machine if one for the operator already exists.
            self.operator.track_rounds().await?;
            tracing::info!("Operator round state tracked");
        }

        Ok(())
    }

    pub async fn get_current_status(&self) -> Result<EntityStatus, BridgeError> {
        let stopped_tasks = self.background_tasks.get_stopped_tasks().await?;
        // Determine if automation is enabled
        let automation_enabled = cfg!(feature = "automation");

        let sync_status =
            Operator::<C>::get_l1_status(&self.operator.db, &self.operator.rpc).await?;

        Ok(EntityStatus {
            automation: automation_enabled,
            wallet_balance: format!("{} BTC", sync_status.wallet_balance.to_btc()),
            tx_sender_synced_height: sync_status.tx_sender_synced_height.unwrap_or(0),
            finalized_synced_height: sync_status.finalized_synced_height.unwrap_or(0),
            hcp_last_proven_height: sync_status.hcp_last_proven_height.unwrap_or(0),
            rpc_tip_height: sync_status.rpc_tip_height,
            bitcoin_syncer_synced_height: sync_status.btc_syncer_synced_height.unwrap_or(0),
            stopped_tasks: Some(stopped_tasks),
            state_manager_next_height: sync_status.state_manager_next_height.unwrap_or(0),
        })
    }

    pub async fn shutdown(&mut self) {
        self.background_tasks.graceful_shutdown().await;
    }
}

impl<C> Operator<C>
where
    C: CitreaClientT,
{
    /// Creates a new `Operator`.
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );

        let db = Database::new(&config).await?;
        let rpc = ExtendedRpc::connect_with_retry(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await?;

        #[cfg(feature = "automation")]
        let tx_sender = TxSenderClient::new(db.clone(), Self::TX_SENDER_CONSUMER_ID.to_string());

        if config.operator_withdrawal_fee_sats.is_none() {
            return Err(eyre::eyre!("Operator withdrawal fee is not set").into());
        }

        // check if we store our collateral outpoint already in db
        let mut dbtx = db.begin_transaction().await?;
        let op_data = db
            .get_operator(Some(&mut dbtx), signer.xonly_public_key)
            .await?;
        let (collateral_funding_outpoint, reimburse_addr) = match op_data {
            Some(operator_data) => {
                // Operator data is already set in db, we don't actually need to do anything.
                // set_operator_checked will give error if the values set in config and db doesn't match.
                (
                    operator_data.collateral_funding_outpoint,
                    operator_data.reimburse_addr,
                )
            }
            None => {
                // Operator data is not set in db, then we check if any collateral outpoint and reimbursement address is set in config.
                // If so we create a new operator using those data, otherwise we generate new collateral outpoint and reimbursement address.
                let reimburse_addr = match &config.operator_reimbursement_address {
                    Some(reimburse_addr) => {
                        reimburse_addr
                            .to_owned()
                            .require_network(config.protocol_paramset().network)
                            .wrap_err(format!("Invalid operator reimbursement address provided in config: {:?} for network: {:?}", reimburse_addr, config.protocol_paramset().network))?
                    }
                    None => {
                        rpc
                        .client
                        .get_new_address(Some("OperatorReimbursement"), Some(AddressType::Bech32m))
                        .await
                        .wrap_err("Failed to get new address")?
                        .require_network(config.protocol_paramset().network)
                        .wrap_err(format!("Invalid operator reimbursement address generated for the network in config: {:?}
                                Possibly the provided rpc's network and network given in config doesn't match", config.protocol_paramset().network))?
                    }
                };
                let outpoint = match &config.operator_collateral_funding_outpoint {
                    Some(outpoint) => {
                        // check if outpoint exists on chain and has exactly collateral funding amount
                        let collateral_tx = rpc
                            .get_tx_of_txid(&outpoint.txid)
                            .await
                            .wrap_err("Failed to get collateral funding tx")?;
                        let collateral_txout = collateral_tx
                            .output
                            .get(outpoint.vout as usize)
                            .ok_or_eyre("Invalid vout index for collateral funding tx")?;
                        if collateral_txout.value
                            != config.protocol_paramset().collateral_funding_amount
                        {
                            return Err(eyre::eyre!("Operator collateral funding outpoint given in config has a different amount than the one specified in config..
                                Bridge collateral funding amount: {:?}, Amount in given outpoint: {:?}", config.protocol_paramset().collateral_funding_amount, collateral_txout.value).into());
                        }
                        if collateral_txout.script_pubkey != signer.address.script_pubkey() {
                            return Err(eyre::eyre!("Operator collateral funding outpoint given in config has a different script pubkey than the pubkey matching to the operator's   secret key. Script pubkey should correspond to taproot address with no scripts and internal key equal to the operator's xonly public key.
                                Script pubkey in given outpoint: {:?}, Script pubkey should be: {:?}", collateral_txout.script_pubkey, signer.address.script_pubkey()).into());
                        }
                        *outpoint
                    }
                    None => {
                        // create a new outpoint that has collateral funding amount
                        rpc.send_to_address(
                            &signer.address,
                            config.protocol_paramset().collateral_funding_amount,
                        )
                        .await?
                    }
                };
                (outpoint, reimburse_addr)
            }
        };

        db.set_operator(
            Some(&mut dbtx),
            signer.xonly_public_key,
            &reimburse_addr,
            collateral_funding_outpoint,
        )
        .await?;
        dbtx.commit().await?;
        let citrea_client = C::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            None,
            config.citrea_request_timeout,
        )
        .await?;

        tracing::info!(
            "Operator xonly pk: {:?}, db created with name: {:?}",
            signer.xonly_public_key,
            config.db_name
        );

        #[cfg(feature = "automation")]
        let header_chain_prover = HeaderChainProver::new(&config, rpc.clone()).await?;

        Ok(Operator {
            rpc,
            db: db.clone(),
            signer,
            config,
            collateral_funding_outpoint,
            #[cfg(feature = "automation")]
            tx_sender,
            citrea_client,
            #[cfg(feature = "automation")]
            header_chain_prover,
            reimburse_addr,
        })
    }

    #[cfg(feature = "automation")]
    pub async fn send_initial_round_tx(&self, round_tx: &Transaction) -> Result<(), BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .insert_try_to_send(
                &mut dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::Round,
                    operator_xonly_pk: None,
                    round_idx: Some(RoundIndex::Round(0)),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                round_tx,
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .await?;
        dbtx.commit().await?;
        Ok(())
    }

    /// Returns an operator's winternitz public keys and challenge ackpreimages
    /// & hashes.
    ///
    /// # Returns
    ///
    /// - [`mpsc::Receiver`]: A [`tokio`] data channel with a type of
    ///   [`winternitz::PublicKey`] and size of operator's winternitz public
    ///   keys count
    /// - [`mpsc::Receiver`]: A [`tokio`] data channel with a type of
    ///   [`PublicHash`] and size of operator's challenge ack preimages & hashes
    ///   count
    ///
    pub async fn get_params(
        &self,
    ) -> Result<
        (
            mpsc::Receiver<winternitz::PublicKey>,
            mpsc::Receiver<schnorr::Signature>,
        ),
        BridgeError,
    > {
        tracing::info!("Generating operator params");
        tracing::info!("Generating kickoff winternitz pubkeys");
        let wpks = self.generate_kickoff_winternitz_pubkeys()?;
        tracing::info!("Kickoff winternitz pubkeys generated");
        let (wpk_tx, wpk_rx) = mpsc::channel(wpks.len());
        let kickoff_wpks = KickoffWinternitzKeys::new(
            wpks,
            self.config.protocol_paramset().num_kickoffs_per_round,
            self.config.protocol_paramset().num_round_txs,
        );
        tracing::info!("Starting to generate unspent kickoff signatures");
        let kickoff_sigs = self.generate_unspent_kickoff_sigs(&kickoff_wpks)?;
        tracing::info!("Unspent kickoff signatures generated");
        let wpks = kickoff_wpks.keys;
        let (sig_tx, sig_rx) = mpsc::channel(kickoff_sigs.len());

        tokio::spawn(async move {
            for wpk in wpks {
                wpk_tx
                    .send(wpk)
                    .await
                    .wrap_err("Failed to send winternitz public key")?;
            }

            for sig in kickoff_sigs {
                sig_tx
                    .send(sig)
                    .await
                    .wrap_err("Failed to send kickoff signature")?;
            }

            Ok::<(), BridgeError>(())
        });

        Ok((wpk_rx, sig_rx))
    }

    pub async fn deposit_sign(
        &self,
        mut deposit_data: DepositData,
    ) -> Result<mpsc::Receiver<schnorr::Signature>, BridgeError> {
        self.citrea_client
            .check_nofn_correctness(deposit_data.get_nofn_xonly_pk()?)
            .await?;

        let mut tweak_cache = TweakCache::default();
        let (sig_tx, sig_rx) = mpsc::channel(constants::DEFAULT_CHANNEL_SIZE);

        let deposit_blockhash = self
            .rpc
            .get_blockhash_of_tx(&deposit_data.get_deposit_outpoint().txid)
            .await?;

        let mut sighash_stream = Box::pin(create_operator_sighash_stream(
            self.db.clone(),
            self.signer.xonly_public_key,
            self.config.clone(),
            deposit_data,
            deposit_blockhash,
        ));

        let signer = self.signer.clone();
        tokio::spawn(async move {
            while let Some(sighash) = sighash_stream.next().await {
                // None because utxos that operators need to sign do not have scripts
                let (sighash, sig_info) = sighash?;
                let sig = signer.sign_with_tweak_data(
                    sighash,
                    sig_info.tweak_data,
                    Some(&mut tweak_cache),
                )?;

                if sig_tx.send(sig).await.is_err() {
                    break;
                }
            }

            Ok::<(), BridgeError>(())
        });

        Ok(sig_rx)
    }

    /// Creates the round state machine by adding a system event to the database
    #[cfg(feature = "automation")]
    pub async fn track_rounds(&self) -> Result<(), BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;
        // set operators own kickoff winternitz public keys before creating the round state machine
        // as round machine needs kickoff keys to create the first round tx
        self.db
            .set_operator_kickoff_winternitz_public_keys(
                Some(&mut dbtx),
                self.signer.xonly_public_key,
                self.generate_kickoff_winternitz_pubkeys()?,
            )
            .await?;

        StateManager::<Operator<C>>::dispatch_new_round_machine(
            self.db.clone(),
            &mut dbtx,
            self.data(),
        )
        .await?;
        dbtx.commit().await?;
        Ok(())
    }

    /// Checks if the withdrawal amount is within the acceptable range.
    fn is_profitable(
        input_amount: Amount,
        withdrawal_amount: Amount,
        bridge_amount_sats: Amount,
        operator_withdrawal_fee_sats: Amount,
    ) -> bool {
        // Use checked_sub to safely handle potential underflow
        let withdrawal_diff = match withdrawal_amount
            .to_sat()
            .checked_sub(input_amount.to_sat())
        {
            Some(diff) => diff,
            None => return false, // If underflow occurs, it's not profitable
        };

        if withdrawal_diff > bridge_amount_sats.to_sat() {
            return false;
        }

        // Calculate net profit after the withdrawal using checked_sub to prevent panic
        let net_profit = match bridge_amount_sats.checked_sub(withdrawal_amount) {
            Some(profit) => profit,
            None => return false, // If underflow occurs, it's not profitable
        };

        // Net profit must be bigger than withdrawal fee.
        net_profit >= operator_withdrawal_fee_sats
    }

    /// Prepares a withdrawal by:
    ///
    /// 1. Checking if the withdrawal has been made on Citrea
    /// 2. Verifying the given signature
    /// 3. Checking if the withdrawal is profitable or not
    /// 4. Funding the withdrawal transaction using TxSender RBF option
    ///
    /// # Parameters
    ///
    /// - `withdrawal_idx`: Citrea withdrawal UTXO index
    /// - `in_signature`: User's signature that is going to be used for signing
    ///   withdrawal transaction input
    /// - `in_outpoint`: User's input for the payout transaction
    /// - `out_script_pubkey`: User's script pubkey which will be used
    ///   in the payout transaction's output
    /// - `out_amount`: Payout transaction output's value
    ///
    /// # Returns
    ///
    /// - Ok(()) if the withdrawal checks are successful and a payout transaction is added to the TxSender
    /// - Err(BridgeError) if the withdrawal checks fail
    #[cfg(feature = "automation")]
    pub async fn withdraw(
        &self,
        withdrawal_index: u32,
        in_signature: schnorr::Signature,
        in_outpoint: OutPoint,
        out_script_pubkey: ScriptBuf,
        out_amount: Amount,
    ) -> Result<(), BridgeError> {
        tracing::info!(
            "Withdrawing with index: {}, in_signature: {}, in_outpoint: {:?}, out_script_pubkey: {}, out_amount: {}",
            withdrawal_index,
            in_signature.to_string(),
            in_outpoint,
            out_script_pubkey.to_string(),
            out_amount
        );

        // Prepare input and output of the payout transaction.
        let input_prevout = self.rpc.get_txout_from_outpoint(&in_outpoint).await?;
        let input_utxo = UTXO {
            outpoint: in_outpoint,
            txout: input_prevout,
        };
        let output_txout = TxOut {
            value: out_amount,
            script_pubkey: out_script_pubkey,
        };

        // Check Citrea for the withdrawal state.
        let withdrawal_utxo = self
            .db
            .get_withdrawal_utxo_from_citrea_withdrawal(None, withdrawal_index)
            .await?;

        if withdrawal_utxo != input_utxo.outpoint {
            return Err(eyre::eyre!("Input UTXO does not match withdrawal UTXO from Citrea: Input Outpoint: {0}, Withdrawal Outpoint (from Citrea): {1}", input_utxo.outpoint, withdrawal_utxo).into());
        }

        let operator_withdrawal_fee_sats =
            self.config
                .operator_withdrawal_fee_sats
                .ok_or(BridgeError::ConfigError(
                    "Operator withdrawal fee sats is not specified in configuration file"
                        .to_string(),
                ))?;
        if !Self::is_profitable(
            input_utxo.txout.value,
            output_txout.value,
            self.config.protocol_paramset().bridge_amount,
            operator_withdrawal_fee_sats,
        ) {
            return Err(eyre::eyre!("Not enough fee for operator").into());
        }

        let user_xonly_pk = &input_utxo
            .txout
            .script_pubkey
            .try_get_taproot_pk()
            .wrap_err("Input utxo script pubkey is not a valid taproot script")?;

        let payout_txhandler = builder::transaction::create_payout_txhandler(
            input_utxo,
            output_txout,
            self.signer.xonly_public_key,
            in_signature,
            self.config.protocol_paramset().network,
        )?;

        // tracing::info!("Payout txhandler: {:?}", hex::encode(bitcoin::consensus::serialize(&payout_txhandler.get_cached_tx())));

        let sighash = payout_txhandler
            .calculate_sighash_txin(0, bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)?;

        SECP.verify_schnorr(
            &in_signature,
            &Message::from_digest(*sighash.as_byte_array()),
            user_xonly_pk,
        )
        .wrap_err("Failed to verify signature received from user for payout txin")?;

        // send payout tx using RBF
        let payout_tx = payout_txhandler.get_cached_tx();
        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .add_tx_to_queue(
                &mut dbtx,
                TransactionType::Payout,
                payout_tx,
                &[],
                Some(TxMetadata {
                    tx_type: TransactionType::Payout,
                    operator_xonly_pk: Some(self.signer.xonly_public_key),
                    round_idx: None,
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                &self.config,
                None,
            )
            .await?;
        dbtx.commit().await?;

        Ok(())
    }

    /// Generates Winternitz public keys for every  BitVM assert tx for a deposit.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public keys for
    ///   `watchtower index` row and `BitVM assert tx index` column.
    pub fn generate_assert_winternitz_pubkeys(
        &self,
        deposit_outpoint: bitcoin::OutPoint,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        tracing::debug!("Generating assert winternitz pubkeys");
        let bitvm_pks = self
            .signer
            .generate_bitvm_pks_for_deposit(deposit_outpoint, self.config.protocol_paramset())?;

        let flattened_wpks = bitvm_pks.to_flattened_vec();

        Ok(flattened_wpks)
    }
    /// Generates Winternitz public keys for every blockhash commit to be used in kickoff utxos.
    /// Unique for each kickoff utxo of operator.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public keys for
    ///   `round_index` row and `kickoff_idx` column.
    pub fn generate_kickoff_winternitz_pubkeys(
        &self,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let mut winternitz_pubkeys =
            Vec::with_capacity(self.config.get_num_kickoff_winternitz_pks());

        // we need num_round_txs + 1 because the last round includes reimburse generators of previous round
        for round_idx in RoundIndex::iter_rounds(self.config.protocol_paramset().num_round_txs + 1)
        {
            for kickoff_idx in 0..self.config.protocol_paramset().num_kickoffs_per_round {
                let path = WinternitzDerivationPath::Kickoff(
                    round_idx,
                    kickoff_idx as u32,
                    self.config.protocol_paramset(),
                );
                winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
            }
        }

        if winternitz_pubkeys.len() != self.config.get_num_kickoff_winternitz_pks() {
            return Err(eyre::eyre!(
                "Expected {} number of kickoff winternitz pubkeys, but got {}",
                self.config.get_num_kickoff_winternitz_pks(),
                winternitz_pubkeys.len()
            )
            .into());
        }

        Ok(winternitz_pubkeys)
    }

    pub fn generate_unspent_kickoff_sigs(
        &self,
        kickoff_wpks: &KickoffWinternitzKeys,
    ) -> Result<Vec<Signature>, BridgeError> {
        let mut tweak_cache = TweakCache::default();
        let mut sigs: Vec<Signature> =
            Vec::with_capacity(self.config.get_num_unspent_kickoff_sigs());
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        let operator_data = OperatorData {
            xonly_pk: self.signer.xonly_public_key,
            collateral_funding_outpoint: self.collateral_funding_outpoint,
            reimburse_addr: self.reimburse_addr.clone(),
        };
        for round_idx in RoundIndex::iter_rounds(self.config.protocol_paramset().num_round_txs) {
            let txhandlers = create_round_txhandlers(
                self.config.protocol_paramset(),
                round_idx,
                &operator_data,
                kickoff_wpks,
                prev_ready_to_reimburse.as_ref(),
            )?;
            for txhandler in txhandlers {
                if let TransactionType::UnspentKickoff(kickoff_idx) =
                    txhandler.get_transaction_type()
                {
                    let partial = PartialSignatureInfo {
                        operator_idx: 0, // dummy value
                        round_idx,
                        kickoff_utxo_idx: kickoff_idx,
                    };
                    let sighashes = txhandler
                        .calculate_shared_txins_sighash(EntityType::OperatorSetup, partial)?;
                    let signed_sigs: Result<Vec<_>, _> = sighashes
                        .into_iter()
                        .map(|(sighash, sig_info)| {
                            self.signer.sign_with_tweak_data(
                                sighash,
                                sig_info.tweak_data,
                                Some(&mut tweak_cache),
                            )
                        })
                        .collect();
                    sigs.extend(signed_sigs?);
                }
                if let TransactionType::ReadyToReimburse = txhandler.get_transaction_type() {
                    prev_ready_to_reimburse = Some(txhandler);
                }
            }
        }
        if sigs.len() != self.config.get_num_unspent_kickoff_sigs() {
            return Err(eyre::eyre!(
                "Expected {} number of unspent kickoff sigs, but got {}",
                self.config.get_num_unspent_kickoff_sigs(),
                sigs.len()
            )
            .into());
        }
        Ok(sigs)
    }

    pub fn generate_challenge_ack_preimages_and_hashes(
        &self,
        deposit_data: &DepositData,
    ) -> Result<Vec<PublicHash>, BridgeError> {
        let mut hashes = Vec::with_capacity(self.config.get_num_challenge_ack_hashes(deposit_data));

        for watchtower_idx in 0..deposit_data.get_num_watchtowers() {
            let path = WinternitzDerivationPath::ChallengeAckHash(
                watchtower_idx as u32,
                deposit_data.get_deposit_outpoint(),
                self.config.protocol_paramset(),
            );
            let hash = self.signer.generate_public_hash_from_path(path)?;
            hashes.push(hash);
        }

        if hashes.len() != self.config.get_num_challenge_ack_hashes(deposit_data) {
            return Err(eyre::eyre!(
                "Expected {} number of challenge ack hashes, but got {}",
                self.config.get_num_challenge_ack_hashes(deposit_data),
                hashes.len()
            )
            .into());
        }

        Ok(hashes)
    }

    pub async fn handle_finalized_payout<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        deposit_outpoint: OutPoint,
        payout_tx_blockhash: BlockHash,
    ) -> Result<bitcoin::Txid, BridgeError> {
        let (deposit_id, _) = self
            .db
            .get_deposit_data(Some(dbtx), deposit_outpoint)
            .await?
            .ok_or(BridgeError::DatabaseError(sqlx::Error::RowNotFound))?;

        // get unused kickoff connector
        let (round_idx, kickoff_idx) = self
            .db
            .get_unused_and_signed_kickoff_connector(
                Some(dbtx),
                deposit_id,
                self.signer.xonly_public_key,
            )
            .await?
            .ok_or(BridgeError::DatabaseError(sqlx::Error::RowNotFound))?;

        let current_round_index = self
            .db
            .get_current_round_index(Some(dbtx))
            .await?
            .ok_or(BridgeError::DatabaseError(sqlx::Error::RowNotFound))?;

        #[cfg(feature = "automation")]
        if current_round_index != round_idx {
            // we currently have no free kickoff connectors in the current round, so we need to end round first
            // if current_round_index should only be smaller than round_idx, and should not be smaller by more than 1
            // so sanity check:
            if current_round_index + 1 != round_idx {
                return Err(eyre::eyre!(
                    "Internal error: Expected the current round ({}) to be equal to or 1 less than the round of the first available kickoff for deposit reimbursement ({}) for deposit {:?}. If the round is less than the current round, there is an issue with the logic of the fn that gets the first available kickoff. If the round is greater, that means the next round do not have any kickoff connectors available for reimbursement, which should not be possible.",
                    current_round_index, round_idx, deposit_outpoint
                ).into());
            }
            // start the next round to be able to get reimbursement for the payout
            self.end_round(dbtx).await?;
        }

        let round_idx = RoundIndex::from_index(round_idx as usize);

        // get signed txs,
        let kickoff_data = KickoffData {
            operator_xonly_pk: self.signer.xonly_public_key,
            round_idx,
            kickoff_idx,
        };

        let transaction_data = TransactionRequestData {
            deposit_outpoint,
            kickoff_data,
        };

        let payout_tx_blockhash = payout_tx_blockhash.as_byte_array().last_20_bytes();

        #[cfg(test)]
        let payout_tx_blockhash = self
            .config
            .test_params
            .maybe_disrupt_payout_tx_block_hash_commit(payout_tx_blockhash);

        let signed_txs = create_and_sign_txs(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            transaction_data,
            Some(payout_tx_blockhash),
            Some(dbtx),
        )
        .await?;

        let tx_metadata = Some(TxMetadata {
            tx_type: TransactionType::Dummy, // will be replaced in add_tx_to_queue
            operator_xonly_pk: Some(self.signer.xonly_public_key),
            round_idx: Some(round_idx),
            kickoff_idx: Some(kickoff_idx),
            deposit_outpoint: Some(deposit_outpoint),
        });

        // try to send them
        for (tx_type, signed_tx) in &signed_txs {
            match *tx_type {
                TransactionType::Kickoff
                | TransactionType::OperatorChallengeAck(_)
                | TransactionType::WatchtowerChallengeTimeout(_)
                | TransactionType::ChallengeTimeout
                | TransactionType::DisproveTimeout
                | TransactionType::Reimburse => {
                    #[cfg(feature = "automation")]
                    self.tx_sender
                        .add_tx_to_queue(
                            dbtx,
                            *tx_type,
                            signed_tx,
                            &signed_txs,
                            tx_metadata,
                            &self.config,
                            None,
                        )
                        .await?;
                }
                _ => {}
            }
        }

        let kickoff_txid = signed_txs
            .iter()
            .find_map(|(tx_type, tx)| {
                if let TransactionType::Kickoff = tx_type {
                    Some(tx.compute_txid())
                } else {
                    None
                }
            })
            .ok_or(eyre::eyre!(
                "Couldn't find kickoff tx in signed_txs".to_string(),
            ))?;

        // mark the kickoff connector as used
        self.db
            .set_kickoff_connector_as_used(Some(dbtx), round_idx, kickoff_idx, Some(kickoff_txid))
            .await?;

        Ok(kickoff_txid)
    }

    #[cfg(feature = "automation")]
    async fn start_first_round(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        kickoff_wpks: KickoffWinternitzKeys,
    ) -> Result<(), BridgeError> {
        // try to send the first round tx
        let (mut first_round_tx, _) = create_round_nth_txhandler(
            self.signer.xonly_public_key,
            self.collateral_funding_outpoint,
            self.config.protocol_paramset().collateral_funding_amount,
            RoundIndex::Round(0),
            &kickoff_wpks,
            self.config.protocol_paramset(),
        )?;

        self.signer
            .tx_sign_and_fill_sigs(&mut first_round_tx, &[], None)?;

        self.tx_sender
            .insert_try_to_send(
                dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::Round,
                    operator_xonly_pk: None,
                    round_idx: Some(RoundIndex::Round(0)),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                first_round_tx.get_cached_tx(),
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .await?;

        // update current round index to 1
        self.db
            .update_current_round_index(Some(dbtx), RoundIndex::Round(0))
            .await?;

        Ok(())
    }

    #[cfg(feature = "automation")]
    pub async fn end_round<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
    ) -> Result<(), BridgeError> {
        // get current round index
        let current_round_index = self.db.get_current_round_index(Some(dbtx)).await?;
        let current_round_index = current_round_index.unwrap_or(0);

        let mut activation_prerequisites = Vec::new();

        let operator_winternitz_public_keys = self
            .db
            .get_operator_kickoff_winternitz_public_keys(None, self.signer.xonly_public_key)
            .await?;
        let kickoff_wpks = KickoffWinternitzKeys::new(
            operator_winternitz_public_keys,
            self.config.protocol_paramset().num_kickoffs_per_round,
            self.config.protocol_paramset().num_round_txs,
        );

        let current_round = RoundIndex::from_index(current_round_index as usize);

        // if we are at round 0, which is just the collateral, we need to start the first round
        if current_round == RoundIndex::Collateral {
            return self.start_first_round(dbtx, kickoff_wpks).await;
        }

        let (current_round_txhandler, mut ready_to_reimburse_txhandler) =
            create_round_nth_txhandler(
                self.signer.xonly_public_key,
                self.collateral_funding_outpoint,
                self.config.protocol_paramset().collateral_funding_amount,
                current_round,
                &kickoff_wpks,
                self.config.protocol_paramset(),
            )?;

        let (mut next_round_txhandler, _) = create_round_nth_txhandler(
            self.signer.xonly_public_key,
            self.collateral_funding_outpoint,
            self.config.protocol_paramset().collateral_funding_amount,
            current_round.next_round(),
            &kickoff_wpks,
            self.config.protocol_paramset(),
        )?;

        let mut tweak_cache = TweakCache::default();

        // sign ready to reimburse tx
        self.signer.tx_sign_and_fill_sigs(
            &mut ready_to_reimburse_txhandler,
            &[],
            Some(&mut tweak_cache),
        )?;

        // sign next round tx
        self.signer.tx_sign_and_fill_sigs(
            &mut next_round_txhandler,
            &[],
            Some(&mut tweak_cache),
        )?;

        let current_round_txid = current_round_txhandler.get_cached_tx().compute_txid();
        let ready_to_reimburse_tx = ready_to_reimburse_txhandler.get_cached_tx();
        let next_round_tx = next_round_txhandler.get_cached_tx();

        let ready_to_reimburse_txid = ready_to_reimburse_tx.compute_txid();

        let mut unspent_kickoff_connector_indices = Vec::new();

        // get kickoff txid for used kickoff connector
        for kickoff_connector_idx in
            0..self.config.protocol_paramset().num_kickoffs_per_round as u32
        {
            let kickoff_txid = self
                .db
                .get_kickoff_txid_for_used_kickoff_connector(
                    Some(dbtx),
                    current_round,
                    kickoff_connector_idx,
                )
                .await?;
            match kickoff_txid {
                Some(kickoff_txid) => {
                    activation_prerequisites.push(ActivatedWithOutpoint {
                        outpoint: OutPoint {
                            txid: kickoff_txid,
                            vout: 1, // Kickoff finalizer output index
                        },
                        relative_block_height: self.config.protocol_paramset().finality_depth,
                    });
                }
                None => {
                    let unspent_kickoff_connector = OutPoint {
                        txid: current_round_txid,
                        vout: kickoff_connector_idx + 1, // add 1 since the first output is collateral
                    };
                    unspent_kickoff_connector_indices.push(kickoff_connector_idx as usize);
                    self.db
                        .set_kickoff_connector_as_used(
                            Some(dbtx),
                            current_round,
                            kickoff_connector_idx,
                            None,
                        )
                        .await?;
                    activation_prerequisites.push(ActivatedWithOutpoint {
                        outpoint: unspent_kickoff_connector,
                        relative_block_height: self.config.protocol_paramset().finality_depth,
                    });
                }
            }
        }

        // Burn unused kickoff connectors
        let mut burn_unspent_kickoff_connectors_tx =
            create_burn_unused_kickoff_connectors_txhandler(
                &current_round_txhandler,
                &unspent_kickoff_connector_indices,
                &self.signer.address,
                self.config.protocol_paramset(),
            )?;

        // sign burn unused kickoff connectors tx
        self.signer.tx_sign_and_fill_sigs(
            &mut burn_unspent_kickoff_connectors_tx,
            &[],
            Some(&mut tweak_cache),
        )?;

        self.tx_sender
            .insert_try_to_send(
                dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::BurnUnusedKickoffConnectors,
                    operator_xonly_pk: Some(self.signer.xonly_public_key),
                    round_idx: Some(current_round),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                burn_unspent_kickoff_connectors_tx.get_cached_tx(),
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .await?;

        // send ready to reimburse tx
        self.tx_sender
            .insert_try_to_send(
                dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::ReadyToReimburse,
                    operator_xonly_pk: Some(self.signer.xonly_public_key),
                    round_idx: Some(current_round),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                ready_to_reimburse_tx,
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[],
                &activation_prerequisites,
            )
            .await?;

        // send next round tx
        self.tx_sender
            .insert_try_to_send(
                dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::Round,
                    operator_xonly_pk: Some(self.signer.xonly_public_key),
                    round_idx: Some(current_round.next_round()),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                next_round_tx,
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[ActivatedWithTxid {
                    txid: ready_to_reimburse_txid,
                    relative_block_height: self
                        .config
                        .protocol_paramset()
                        .operator_reimburse_timelock
                        as u32,
                }],
                &[],
            )
            .await?;

        // update current round index
        self.db
            .update_current_round_index(Some(dbtx), current_round.next_round())
            .await?;

        Ok(())
    }

    #[cfg(feature = "automation")]
    async fn send_asserts(
        &self,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        watchtower_challenges: HashMap<usize, Transaction>,
        _payout_blockhash: Witness,
        latest_blockhash: Witness,
    ) -> Result<(), BridgeError> {
        use bridge_circuit_host::utils::{get_verifying_key, is_dev_mode};

        let context = ContractContext::new_context_for_kickoff(
            kickoff_data,
            deposit_data.clone(),
            self.config.protocol_paramset(),
        );
        let mut db_cache = crate::builder::transaction::ReimburseDbCache::from_context(
            self.db.clone(),
            &context,
            None,
        );
        let txhandlers = builder::transaction::create_txhandlers(
            TransactionType::Kickoff,
            context,
            &mut crate::builder::transaction::TxHandlerCache::new(),
            &mut db_cache,
        )
        .await?;
        let move_txid = txhandlers
            .get(&TransactionType::MoveToVault)
            .ok_or(eyre::eyre!(
                "Move to vault txhandler not found in send_asserts"
            ))?
            .get_cached_tx()
            .compute_txid();
        let kickoff_tx = txhandlers
            .get(&TransactionType::Kickoff)
            .ok_or(eyre::eyre!("Kickoff txhandler not found in send_asserts"))?
            .get_cached_tx();

        let (payout_op_xonly_pk_opt, payout_block_hash, payout_txid, deposit_idx) = self
            .db
            .get_payout_info_from_move_txid(None, move_txid)
            .await
            .wrap_err("Failed to get payout info from db during sending asserts.")?
            .ok_or_eyre(format!(
                "Payout info not found in db while sending asserts for move txid: {}",
                move_txid
            ))?;

        let payout_op_xonly_pk = payout_op_xonly_pk_opt.ok_or_eyre(format!(
            "Payout operator xonly pk not found in payout info DB while sending asserts for deposit move txid: {}",
            move_txid
        ))?;

        tracing::info!("Sending asserts for deposit_idx: {:?}", deposit_idx);

        if payout_op_xonly_pk != kickoff_data.operator_xonly_pk {
            return Err(eyre::eyre!(
                "Payout operator xonly pk does not match kickoff operator xonly pk in send_asserts"
            )
            .into());
        }

        let (payout_block_height, payout_block) = self
            .db
            .get_full_block_from_hash(None, payout_block_hash)
            .await?
            .ok_or_eyre(format!(
                "Payout block {:?} {:?} not found in db",
                payout_op_xonly_pk, payout_block_hash
            ))?;

        let payout_tx_index = payout_block
            .txdata
            .iter()
            .position(|tx| tx.compute_txid() == payout_txid)
            .ok_or_eyre(format!(
                "Payout txid {:?} not found in block {:?} {:?}",
                payout_txid, payout_op_xonly_pk, payout_block_hash
            ))?;
        let payout_tx = &payout_block.txdata[payout_tx_index];
        tracing::debug!("Calculated payout tx in send_asserts: {:?}", payout_tx);

        let (light_client_proof, lcp_receipt, l2_height) = self
            .citrea_client
            .get_light_client_proof(payout_block_height as u64)
            .await
            .wrap_err("Failed to get light client proof for payout block height")?
            .ok_or_eyre("Light client proof is not available for payout block height")?;
        tracing::info!("Got light client proof in send_asserts");

        let storage_proof = self
            .citrea_client
            .get_storage_proof(l2_height, deposit_idx as u32)
            .await
            .wrap_err(format!(
                "Failed to get storage proof for move txid {:?}, l2 height {}, deposit_idx {}",
                move_txid, l2_height, deposit_idx
            ))?;

        tracing::debug!("Got storage proof in send_asserts {:?}", storage_proof);

        // get committed latest blockhash
        let wt_derive_path = ClementineBitVMPublicKeys::get_latest_blockhash_derivation(
            deposit_data.get_deposit_outpoint(),
            self.config.protocol_paramset(),
        );
        let commits = extract_winternitz_commits(
            latest_blockhash,
            &[wt_derive_path],
            self.config.protocol_paramset(),
        )?;

        let latest_blockhash_last_20: [u8; 20] = commits
            .first()
            .ok_or_eyre("Failed to get latest blockhash in send_asserts")?
            .to_owned()
            .try_into()
            .map_err(|_| eyre::eyre!("Committed latest blockhash is not 20 bytes long"))?;

        #[cfg(test)]
        let latest_blockhash_last_20 = self
            .config
            .test_params
            .maybe_disrupt_latest_block_hash_commit(latest_blockhash_last_20);

        let rpc_current_finalized_height = self
            .rpc
            .get_current_chain_height()
            .await?
            .saturating_sub(self.config.protocol_paramset().finality_depth);

        // update headers in case the sync (state machine handle_finalized_block) is behind
        self.db
            .fetch_and_save_missing_blocks(
                &self.rpc,
                self.config.protocol_paramset().genesis_height,
                rpc_current_finalized_height + 1,
            )
            .await?;

        let current_height = self
            .db
            .get_latest_finalized_block_height(None)
            .await?
            .ok_or_eyre("Failed to get current finalized block height")?;

        let block_hashes = self
            .db
            .get_block_info_from_range(
                None,
                self.config.protocol_paramset().genesis_height as u64,
                current_height,
            )
            .await?;

        // find out which blockhash is latest_blockhash (only last 20 bytes is committed to Witness)
        let latest_blockhash_index = block_hashes
            .iter()
            .position(|(block_hash, _)| {
                block_hash.as_byte_array().last_20_bytes() == latest_blockhash_last_20
            })
            .ok_or_eyre("Failed to find latest blockhash in send_asserts")?;

        let latest_blockhash = block_hashes[latest_blockhash_index].0;

        let (current_hcp, _hcp_height) = self
            .header_chain_prover
            .prove_till_hash(latest_blockhash)
            .await?;

        #[cfg(test)]
        let mut total_works: Vec<[u8; 16]> = Vec::with_capacity(watchtower_challenges.len());

        #[cfg(test)]
        {
            use bridge_circuit_host::utils::total_work_from_wt_tx;
            for (_, tx) in watchtower_challenges.iter() {
                let total_work = total_work_from_wt_tx(tx);
                total_works.push(total_work);
            }
            tracing::debug!("Total works: {:?}", total_works);
        }

        #[cfg(test)]
        let current_hcp = self
            .config
            .test_params
            .maybe_override_current_hcp(
                current_hcp,
                payout_block_hash,
                &block_hashes,
                &self.header_chain_prover,
                total_works.clone(),
            )
            .await?;

        tracing::info!("Got header chain proof in send_asserts");

        let blockhashes_serialized: Vec<[u8; 32]> = block_hashes
            .iter()
            .take(latest_blockhash_index + 1)
            .map(|(h, _)| h.to_byte_array())
            .collect();

        #[cfg(test)]
        let blockhashes_serialized = self
            .config
            .test_params
            .maybe_override_blockhashes_serialized(
                blockhashes_serialized,
                payout_block_height,
                self.config.protocol_paramset().genesis_height,
                total_works,
            );

        tracing::debug!(
            "Genesis height - Before SPV: {},",
            self.config.protocol_paramset().genesis_height
        );

        let spv = create_spv(
            payout_tx.clone(),
            &blockhashes_serialized,
            payout_block.clone(),
            payout_block_height,
            self.config.protocol_paramset().genesis_height,
            payout_tx_index as u32,
        )?;
        tracing::info!("Calculated spv proof in send_asserts");

        let mut wt_contexts = Vec::new();
        for (_, tx) in watchtower_challenges.iter() {
            wt_contexts.push(WatchtowerContext {
                watchtower_tx: tx.clone(),
                prevout_txs: self.rpc.get_prevout_txs(tx).await?,
            });
        }

        #[cfg(test)]
        {
            if self.config.test_params.operator_forgot_watchtower_challenge {
                tracing::info!("Disrupting watchtower challenges in send_asserts");
                wt_contexts.pop();
            }
        }

        let watchtower_challenge_connector_start_idx =
            (FIRST_FIVE_OUTPUTS + NUMBER_OF_ASSERT_TXS) as u16;

        let bridge_circuit_host_params = BridgeCircuitHostParams::new_with_wt_tx(
            kickoff_tx.clone(),
            spv,
            current_hcp,
            light_client_proof,
            lcp_receipt,
            storage_proof,
            self.config.protocol_paramset().network,
            &wt_contexts,
            watchtower_challenge_connector_start_idx,
        )
        .wrap_err("Failed to create bridge circuit host params in send_asserts")?;

        let bridge_circuit_elf = match self.config.protocol_paramset().network {
            bitcoin::Network::Bitcoin => MAINNET_BRIDGE_CIRCUIT_ELF,
            bitcoin::Network::Testnet4 => TESTNET4_BRIDGE_CIRCUIT_ELF,
            bitcoin::Network::Signet => SIGNET_BRIDGE_CIRCUIT_ELF,
            bitcoin::Network::Regtest => {
                if cfg!(test) {
                    REGTEST_BRIDGE_CIRCUIT_ELF_TEST
                } else {
                    REGTEST_BRIDGE_CIRCUIT_ELF
                }
            }
            _ => {
                return Err(eyre::eyre!(
                    "Unsupported network {:?} in send_asserts",
                    self.config.protocol_paramset().network
                )
                .into())
            }
        };
        tracing::info!("Starting proving bridge circuit to send asserts");

        #[cfg(test)]
        self.config
            .test_params
            .maybe_dump_bridge_circuit_params_to_file(&bridge_circuit_host_params)?;

        #[cfg(test)]
        self.config
            .test_params
            .maybe_dump_bridge_circuit_params_to_file(&bridge_circuit_host_params)?;

        let (g16_proof, g16_output, public_inputs) =
            prove_bridge_circuit(bridge_circuit_host_params, bridge_circuit_elf)?;

        tracing::info!("Proved bridge circuit in send_asserts");
        let public_input_scalar = ark_bn254::Fr::from_be_bytes_mod_order(&g16_output);

        #[cfg(test)]
        let mut public_inputs = public_inputs;

        #[cfg(test)]
        {
            if self
                .config
                .test_params
                .disrupt_challenge_sending_watchtowers_commit
            {
                tracing::info!("Disrupting challenge sending watchtowers commit in send_asserts");
                public_inputs.challenge_sending_watchtowers[0] ^= 0x01;
                tracing::info!(
                    "Disrupted challenge sending watchtowers commit: {:?}",
                    public_inputs.challenge_sending_watchtowers
                );
            }
        }

        tracing::info!(
            "Challenge sending watchtowers commit: {:?}",
            public_inputs.challenge_sending_watchtowers
        );

        let asserts = tokio::task::spawn_blocking(move || {
            let vk = get_verifying_key();

            generate_assertions(g16_proof, vec![public_input_scalar], &vk).map_err(|e| {
                eyre::eyre!(
                    "Failed to generate {}assertions: {}",
                    if cfg!(test) && is_dev_mode() {
                        "dev mode "
                    } else {
                        ""
                    },
                    e
                )
            })
        })
        .await
        .wrap_err("Generate assertions thread failed with error")??;

        tracing::warn!("Generated assertions in send_asserts");

        #[cfg(test)]
        let asserts = self.config.test_params.maybe_corrupt_asserts(asserts);

        let assert_txs = self
            .create_assert_commitment_txs(
                TransactionRequestData {
                    kickoff_data,
                    deposit_outpoint: deposit_data.get_deposit_outpoint(),
                },
                ClementineBitVMPublicKeys::get_assert_commit_data(
                    asserts,
                    &public_inputs.challenge_sending_watchtowers,
                ),
                None,
            )
            .await?;

        let mut dbtx = self.db.begin_transaction().await?;
        for (tx_type, tx) in assert_txs {
            self.tx_sender
                .add_tx_to_queue(
                    &mut dbtx,
                    tx_type,
                    &tx,
                    &[],
                    Some(TxMetadata {
                        tx_type,
                        operator_xonly_pk: Some(self.signer.xonly_public_key),
                        round_idx: Some(kickoff_data.round_idx),
                        kickoff_idx: Some(kickoff_data.kickoff_idx),
                        deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                    }),
                    &self.config,
                    None,
                )
                .await?;
        }
        dbtx.commit().await?;
        Ok(())
    }

    #[cfg(feature = "automation")]
    fn data(&self) -> OperatorData {
        OperatorData {
            xonly_pk: self.signer.xonly_public_key,
            collateral_funding_outpoint: self.collateral_funding_outpoint,
            reimburse_addr: self.reimburse_addr.clone(),
        }
    }

    #[cfg(feature = "automation")]
    async fn send_latest_blockhash(
        &self,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        latest_blockhash: BlockHash,
    ) -> Result<(), BridgeError> {
        tracing::warn!("Operator sending latest blockhash");
        let deposit_outpoint = deposit_data.get_deposit_outpoint();
        let (tx_type, tx) = self
            .create_latest_blockhash_tx(
                TransactionRequestData {
                    deposit_outpoint,
                    kickoff_data,
                },
                latest_blockhash,
                None,
            )
            .await?;
        if tx_type != TransactionType::LatestBlockhash {
            return Err(eyre::eyre!("Latest blockhash tx type is not LatestBlockhash").into());
        }
        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .add_tx_to_queue(
                &mut dbtx,
                tx_type,
                &tx,
                &[],
                Some(TxMetadata {
                    tx_type,
                    operator_xonly_pk: Some(self.signer.xonly_public_key),
                    round_idx: Some(kickoff_data.round_idx),
                    kickoff_idx: Some(kickoff_data.kickoff_idx),
                    deposit_outpoint: Some(deposit_outpoint),
                }),
                &self.config,
                None,
            )
            .await?;
        dbtx.commit().await?;
        Ok(())
    }
}

impl<C> NamedEntity for Operator<C>
where
    C: CitreaClientT,
{
    const ENTITY_NAME: &'static str = "operator";
    // operators use their verifier's tx sender
    const TX_SENDER_CONSUMER_ID: &'static str = "verifier_tx_sender";
    const FINALIZED_BLOCK_CONSUMER_ID: &'static str = "operator_finalized_block_fetcher";
}

#[cfg(feature = "automation")]
mod states {
    use super::*;
    use crate::builder::transaction::{
        create_txhandlers, ContractContext, ReimburseDbCache, TransactionType, TxHandler,
        TxHandlerCache,
    };
    use crate::states::context::DutyResult;
    use crate::states::{block_cache, Duty, Owner, StateManager};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[tonic::async_trait]
    impl<C> Owner for Operator<C>
    where
        C: CitreaClientT,
    {
        async fn handle_duty(&self, duty: Duty) -> Result<DutyResult, BridgeError> {
            match duty {
                Duty::NewReadyToReimburse {
                    round_idx,
                    operator_xonly_pk,
                    used_kickoffs,
                } => {
                    tracing::info!("Operator {:?} called new ready to reimburse with round_idx: {:?}, operator_xonly_pk: {:?}, used_kickoffs: {:?}",
                    self.signer.xonly_public_key, round_idx, operator_xonly_pk, used_kickoffs);
                    Ok(DutyResult::Handled)
                }
                Duty::WatchtowerChallenge { .. } => Ok(DutyResult::Handled),
                Duty::SendOperatorAsserts {
                    kickoff_data,
                    deposit_data,
                    watchtower_challenges,
                    payout_blockhash,
                    latest_blockhash,
                } => {
                    tracing::warn!("Operator {:?} called send operator asserts with kickoff_data: {:?}, deposit_data: {:?}, watchtower_challenges: {:?}",
                    self.signer.xonly_public_key, kickoff_data, deposit_data, watchtower_challenges.len());
                    self.send_asserts(
                        kickoff_data,
                        deposit_data,
                        watchtower_challenges,
                        payout_blockhash,
                        latest_blockhash,
                    )
                    .await?;
                    Ok(DutyResult::Handled)
                }
                Duty::VerifierDisprove { .. } => Ok(DutyResult::Handled),
                Duty::SendLatestBlockhash {
                    kickoff_data,
                    deposit_data,
                    latest_blockhash,
                } => {
                    tracing::warn!("Operator {:?} called send latest blockhash with kickoff_id: {:?}, deposit_data: {:?}, latest_blockhash: {:?}", self.signer.xonly_public_key, kickoff_data, deposit_data, latest_blockhash);
                    self.send_latest_blockhash(kickoff_data, deposit_data, latest_blockhash)
                        .await?;
                    Ok(DutyResult::Handled)
                }
                Duty::CheckIfKickoff {
                    txid,
                    block_height,
                    witness,
                    challenged_before: _,
                } => {
                    tracing::debug!(
                        "Operator {:?} called check if kickoff with txid: {:?}, block_height: {:?}",
                        self.signer.xonly_public_key,
                        txid,
                        block_height,
                    );
                    let kickoff_data = self
                        .db
                        .get_deposit_data_with_kickoff_txid(None, txid)
                        .await?;
                    if let Some((deposit_data, kickoff_data)) = kickoff_data {
                        let mut dbtx = self.db.begin_transaction().await?;
                        StateManager::<Self>::dispatch_new_kickoff_machine(
                            self.db.clone(),
                            &mut dbtx,
                            kickoff_data,
                            block_height,
                            deposit_data,
                            witness,
                        )
                        .await?;
                        dbtx.commit().await?;
                    }
                    Ok(DutyResult::Handled)
                }
            }
        }

        async fn create_txhandlers(
            &self,
            tx_type: TransactionType,
            contract_context: ContractContext,
        ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
            let mut db_cache =
                ReimburseDbCache::from_context(self.db.clone(), &contract_context, None);
            let txhandlers = create_txhandlers(
                tx_type,
                contract_context,
                &mut TxHandlerCache::new(),
                &mut db_cache,
            )
            .await?;
            Ok(txhandlers)
        }

        async fn handle_finalized_block(
            &self,
            _dbtx: DatabaseTransaction<'_, '_>,
            _block_id: u32,
            _block_height: u32,
            _block_cache: Arc<block_cache::BlockCache>,
            _light_client_proof_wait_interval_secs: Option<u32>,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::operator::Operator;
    use crate::test::common::citrea::MockCitreaClient;
    use crate::test::common::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};

    // #[tokio::test]
    // async fn set_funding_utxo() {
    //     let mut config = create_test_config_with_thread_name().await;
    //     let rpc = ExtendedRpc::connect_with_retry(
    //         config.bitcoin_rpc_url.clone(),
    //         config.bitcoin_rpc_user.clone(),
    //         config.bitcoin_rpc_password.clone(),
    //         None,
    //     )
    //     .await;

    //     let operator = Operator::new(config, rpc).await.unwrap();

    //     let funding_utxo = UTXO {
    //         outpoint: OutPoint {
    //             txid: Txid::all_zeros(),
    //             vout: 0x45,
    //         },
    //         txout: TxOut {
    //             value: Amount::from_sat(0x1F),
    //             script_pubkey: ScriptBuf::new(),
    //         },
    //     };

    //     operator
    //         .set_funding_utxo(funding_utxo.clone())
    //         .await
    //         .unwrap();

    //     let db_funding_utxo = operator.db.get_funding_utxo(None).await.unwrap().unwrap();

    //     assert_eq!(funding_utxo, db_funding_utxo);
    // }

    // #[tokio::test]
    // async fn is_profitable() {
    //     let mut config = create_test_config_with_thread_name().await;
    //     let rpc = ExtendedRpc::connect_with_retry(
    //         config.bitcoin_rpc_url.clone(),
    //         config.bitcoin_rpc_user.clone(),
    //         config.bitcoin_rpc_password.clone(),
    //         None,
    //     )
    //     .await;

    //     config.protocol_paramset().bridge_amount = Amount::from_sat(0x45);
    //     config.operator_withdrawal_fee_sats = Some(Amount::from_sat(0x1F));

    //     let operator = Operator::new(config.clone(), rpc).await.unwrap();

    //     // Smaller input amount must not cause a panic.
    //     operator.is_profitable(Amount::from_sat(3), Amount::from_sat(1));
    //     // Bigger input amount must not cause a panic.
    //     operator.is_profitable(Amount::from_sat(6), Amount::from_sat(9));

    //     // False because difference between input and withdrawal amount is
    //     // bigger than `config.protocol_paramset().bridge_amount`.
    //     assert!(!operator.is_profitable(Amount::from_sat(6), Amount::from_sat(90)));

    //     // False because net profit is smaller than
    //     // `config.operator_withdrawal_fee_sats`.
    //     assert!(!operator.is_profitable(Amount::from_sat(0), config.protocol_paramset().bridge_amount));

    //     // True because net profit is bigger than
    //     // `config.operator_withdrawal_fee_sats`.
    //     assert!(operator.is_profitable(
    //         Amount::from_sat(0),
    //         config.operator_withdrawal_fee_sats.unwrap() - Amount::from_sat(1)
    //     ));
    // }

    #[tokio::test]
    #[ignore = "Design changes in progress"]
    async fn get_winternitz_public_keys() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let operator = Operator::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();

        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 2,
        };

        let winternitz_public_key = operator
            .generate_assert_winternitz_pubkeys(deposit_outpoint)
            .unwrap();
        assert_eq!(
            winternitz_public_key.len(),
            config.protocol_paramset().num_round_txs
                * config.protocol_paramset().num_kickoffs_per_round
        );
    }

    #[tokio::test]
    async fn operator_get_params() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let operator = Operator::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();
        let actual_wpks = operator.generate_kickoff_winternitz_pubkeys().unwrap();

        let (mut wpk_rx, _) = operator.get_params().await.unwrap();
        let mut idx = 0;
        while let Some(wpk) = wpk_rx.recv().await {
            assert_eq!(actual_wpks[idx], wpk);
            idx += 1;
        }
        assert_eq!(idx, actual_wpks.len());
    }
}
