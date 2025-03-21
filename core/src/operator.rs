use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use crate::actor::{Actor, WinternitzDerivationPath};
use crate::bitvm_client::SECP;
use crate::builder::sighash::{create_operator_sighash_stream, PartialSignatureInfo};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::builder::transaction::{
    create_burn_unused_kickoff_connectors_txhandler, create_round_nth_txhandler,
    create_round_txhandlers, create_txhandlers, ContractContext, DepositData,
    KickoffWinternitzKeys, OperatorData, ReimburseDbCache, TransactionType, TxHandler,
    TxHandlerCache,
};
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::database::DatabaseTransaction;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::KickoffId;
use crate::states::{block_cache, Duty, Owner, StateManager};
use crate::task::manager::BackgroundTaskManager;
use crate::task::payout_checker::{PayoutCheckerTask, PAYOUT_CHECKER_POLL_DELAY};
use crate::task::{IntoTask, TaskExt};
use crate::tx_sender::TxSenderClient;
use crate::tx_sender::{ActivatedWithOutpoint, ActivatedWithTxid, FeePayingType, TxMetadata};
use crate::{builder, UTXO};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::{
    Address, Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::RpcApi;
use bitvm::signatures::winternitz;
use eyre::Context;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

pub type SecretPreimage = [u8; 20];
pub type PublicHash = [u8; 20]; // TODO: Make sure these are 20 bytes and maybe do this a struct?

pub struct OperatorServer<C: CitreaClientT> {
    pub operator: Operator<C>,
    background_tasks: BackgroundTaskManager<Operator<C>>,
}

#[derive(Debug, Clone)]
pub struct Operator<C: CitreaClientT> {
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub signer: Actor,
    pub config: BridgeConfig,
    pub nofn_xonly_pk: XOnlyPublicKey,
    pub collateral_funding_outpoint: OutPoint,
    pub idx: usize,
    pub(crate) reimburse_addr: Address,
    pub tx_sender: TxSenderClient,
    pub citrea_client: C,
}

impl<C> OperatorServer<C>
where
    C: CitreaClientT,
{
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let paramset = config.protocol_paramset();
        let operator = Operator::new(config.clone()).await?;
        let mut background_tasks = BackgroundTaskManager::default();

        // initialize and run state manager
        let state_manager =
            StateManager::new(operator.db.clone(), operator.clone(), paramset).await?;

        let should_run_state_mgr = {
            #[cfg(test)]
            {
                config.test_params.should_run_state_manager
            }
            #[cfg(not(test))]
            {
                true
            }
        };

        if should_run_state_mgr {
            background_tasks.loop_and_monitor(state_manager.block_fetcher_task().await?);
            background_tasks.loop_and_monitor(state_manager.into_task());
        }

        // run payout checker task
        background_tasks.loop_and_monitor(
            PayoutCheckerTask::new(operator.db.clone(), operator.clone())
                .with_delay(PAYOUT_CHECKER_POLL_DELAY),
        );

        // track the operator's round state
        operator.track_rounds().await?;

        Ok(Self {
            operator,
            background_tasks,
        })
    }

    pub async fn shutdown(&mut self) {
        self.background_tasks
            .graceful_shutdown_with_timeout(Duration::from_secs(10))
            .await;
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
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let nofn_xonly_pk =
            XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)?;
        let idx = config
            .operators_xonly_pks
            .iter()
            .position(|xonly_pk| xonly_pk == &signer.xonly_public_key)
            .ok_or_else(|| eyre::eyre!("Operator's key not found in list of operator x-only public keys, operator's key: {0}", signer.xonly_public_key))?;

        let tx_sender = TxSenderClient::new(db.clone(), format!("operator_{}", idx).to_string());

        if config.operator_withdrawal_fee_sats.is_none() {
            return Err(eyre::eyre!("Operator withdrawal fee is not set").into());
        }

        // TODO: Fix this where the config will only have one address. also check??
        let reimburse_addr = rpc
            .client
            .get_new_address(Some("OperatorReimbursement"), Some(AddressType::Bech32m))
            .await
            .wrap_err("Failed to get new address")?
            .assume_checked();

        // check if we store our collateral outpoint already in db
        let mut dbtx = db.begin_transaction().await?;
        let op_data = db.get_operator(Some(&mut dbtx), idx as i32).await?;
        let collateral_funding_outpoint = match op_data {
            Some(op_data) => op_data.collateral_funding_outpoint,
            None => {
                let outpoint = rpc
                    .send_to_address(
                        &signer.address,
                        config.protocol_paramset().collateral_funding_amount,
                    )
                    .await?;
                db.set_operator(
                    Some(&mut dbtx),
                    idx as i32,
                    signer.xonly_public_key,
                    reimburse_addr.to_string(),
                    outpoint,
                )
                .await?;
                outpoint
            }
        };
        dbtx.commit().await?;

        let citrea_client = C::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            None,
        )
        .await?;

        tracing::debug!(
            "Operator idx: {:?}, db created with name: {:?}",
            idx,
            config.db_name
        );

        Ok(Operator {
            rpc,
            db: db.clone(),
            signer,
            config,
            nofn_xonly_pk,
            idx,
            collateral_funding_outpoint,
            tx_sender,
            citrea_client,
            reimburse_addr,
        })
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
        let wpks = self.generate_kickoff_winternitz_pubkeys()?;
        let (wpk_tx, wpk_rx) = mpsc::channel(wpks.len());
        let kickoff_wpks = KickoffWinternitzKeys::new(
            wpks,
            self.config.protocol_paramset().num_kickoffs_per_round,
        );
        let kickoff_sigs = self.generate_unspent_kickoff_sigs(&kickoff_wpks)?;
        let wpks = kickoff_wpks.keys.clone();
        let (sig_tx, sig_rx) = mpsc::channel(kickoff_sigs.len());

        // try to send the first round tx
        let (mut first_round_tx, _) = create_round_nth_txhandler(
            self.signer.xonly_public_key,
            self.collateral_funding_outpoint,
            self.config.protocol_paramset().collateral_funding_amount,
            0, // index 0 for the first round
            &kickoff_wpks,
            self.config.protocol_paramset(),
        )?;

        self.signer
            .tx_sign_and_fill_sigs(&mut first_round_tx, &[])?;

        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .insert_try_to_send(
                &mut dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::Round,
                    operator_idx: Some(self.idx as u32),
                    verifier_idx: None,
                    round_idx: Some(0),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                first_round_tx.get_cached_tx(),
                FeePayingType::CPFP,
                &[],
                &[],
                &[],
                &[],
            )
            .await?;
        dbtx.commit().await?;

        tokio::spawn(async move {
            for wpk in wpks {
                wpk_tx
                    .send(wpk)
                    .await
                    .map_err(|e| BridgeError::SendError("winternitz public key", e.to_string()))?;
            }

            for sig in kickoff_sigs {
                sig_tx
                    .send(sig)
                    .await
                    .map_err(|e| BridgeError::SendError("kickoff signature", e.to_string()))?;
            }

            Ok::<(), BridgeError>(())
        });

        Ok((wpk_rx, sig_rx))
    }

    pub async fn deposit_sign(
        &self,
        deposit_data: DepositData,
    ) -> Result<mpsc::Receiver<schnorr::Signature>, BridgeError> {
        let (sig_tx, sig_rx) = mpsc::channel(1280);

        let deposit_blockhash = self
            .rpc
            .get_blockhash_of_tx(&deposit_data.get_deposit_outpoint().txid)
            .await?;

        let mut sighash_stream = Box::pin(create_operator_sighash_stream(
            self.db.clone(),
            self.idx,
            self.config.clone(),
            deposit_data,
            deposit_blockhash,
        ));

        let operator = self.clone();
        tokio::spawn(async move {
            while let Some(sighash) = sighash_stream.next().await {
                // None because utxos that operators need to sign do not have scripts
                let sig = operator.signer.sign_with_tweak(sighash?.0, None)?;

                if sig_tx.send(sig).await.is_err() {
                    break;
                }
            }

            Ok::<(), BridgeError>(())
        });

        Ok(sig_rx)
    }

    /// Creates the round state machine by adding a system event to the database
    pub async fn track_rounds(&self) -> Result<(), BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;
        StateManager::<Operator<C>>::dispatch_new_round_machine(
            self.db.clone(),
            &mut dbtx,
            self.data(),
            self.idx as u32,
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
        if withdrawal_amount
            .to_sat()
            .wrapping_sub(input_amount.to_sat())
            > bridge_amount_sats.to_sat()
        {
            return false;
        }

        // Calculate net profit after the withdrawal.
        let net_profit = bridge_amount_sats - withdrawal_amount;

        // Net profit must be bigger than withdrawal fee.
        net_profit >= operator_withdrawal_fee_sats
    }

    /// Prepares a withdrawal by:
    ///
    /// 1. Checking if the withdrawal has been made on Citrea
    /// 2. Verifying the given signature
    /// 3. Checking if the withdrawal is profitable or not
    /// 4. Funding the witdhrawal transaction
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
    /// - [`Txid`]: Payout transaction's txid
    pub async fn withdraw(
        &self,
        withdrawal_index: u32,
        in_signature: schnorr::Signature,
        in_outpoint: OutPoint,
        out_script_pubkey: ScriptBuf,
        out_amount: Amount,
    ) -> Result<Txid, BridgeError> {
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

        match withdrawal_utxo {
            Some(withdrawal_utxo) => {
                if withdrawal_utxo != input_utxo.outpoint {
                    return Err(eyre::eyre!("Input UTXO does not match withdrawal UTXO from Citrea: Input Outpoint: {0}, Withdrawal Outpoint (from Citrea): {1}", input_utxo.outpoint, withdrawal_utxo).into());
                }
            }
            None => {
                return Err(eyre::eyre!(
                    "User's withdrawal UTXO is not set for withdrawal index: {0}",
                    withdrawal_index
                )
                .into());
            }
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

        let user_xonly_pk =
            XOnlyPublicKey::from_slice(&input_utxo.txout.script_pubkey.as_bytes()[2..34])
                .wrap_err("Failed to extract xonly public key from input utxo script pubkey")?;

        let payout_txhandler = builder::transaction::create_payout_txhandler(
            input_utxo,
            output_txout,
            self.idx,
            in_signature,
            self.config.protocol_paramset().network,
        )?;

        let sighash = payout_txhandler
            .calculate_sighash_txin(0, bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)?;

        SECP.verify_schnorr(
            &in_signature,
            &Message::from_digest(*sighash.as_byte_array()),
            &user_xonly_pk,
        )
        .wrap_err("Failed to verify signature received from user for payout txin")?;

        let funded_tx = self
            .rpc
            .client
            .fund_raw_transaction(
                payout_txhandler.get_cached_tx(),
                Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
                    add_inputs: Some(true),
                    change_address: None,
                    change_position: Some(1),
                    change_type: None,
                    include_watching: None,
                    lock_unspents: None,
                    fee_rate: None,
                    subtract_fee_from_outputs: None,
                    replaceable: None,
                    conf_target: None,
                    estimate_mode: None,
                }),
                None,
            )
            .await
            .wrap_err("Failed to fund raw transaction")?
            .hex;

        let signed_tx: Transaction = deserialize(
            &self
                .rpc
                .client
                .sign_raw_transaction_with_wallet(&funded_tx, None, None)
                .await
                .wrap_err("Failed to sign funded tx through bitcoin RPC")?
                .hex,
        )
        .wrap_err("Failed to deserialize signed tx")?;

        Ok(self
            .rpc
            .client
            .send_raw_transaction(&signed_tx)
            .await
            .wrap_err("Failed to send transaction to signed tx")?)
    }

    /// Generates Winternitz public keys for every  BitVM assert tx for a deposit.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public keys for
    ///   `watchtower index` row and `BitVM assert tx index` column.
    pub fn generate_assert_winternitz_pubkeys(
        &self,
        deposit_txid: Txid,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        tracing::debug!("Generating assert winternitz pubkeys");
        let bitvm_pks = self
            .signer
            .generate_bitvm_pks_for_deposit(deposit_txid, self.config.protocol_paramset())?;
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
        for round_idx in 0..self.config.protocol_paramset().num_round_txs + 1 {
            for kickoff_idx in 0..self.config.protocol_paramset().num_kickoffs_per_round {
                let path = WinternitzDerivationPath::Kickoff(
                    round_idx as u32,
                    kickoff_idx as u32,
                    self.config.protocol_paramset(),
                );
                winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
            }
        }

        if winternitz_pubkeys.len() != self.config.get_num_kickoff_winternitz_pks() {
            return Err(BridgeError::Error(format!(
                "Expected {} number of kickoff winternitz pubkeys, but got {}",
                self.config.get_num_kickoff_winternitz_pks(),
                winternitz_pubkeys.len()
            )));
        }

        Ok(winternitz_pubkeys)
    }

    pub fn generate_unspent_kickoff_sigs(
        &self,
        kickoff_wpks: &KickoffWinternitzKeys,
    ) -> Result<Vec<Signature>, BridgeError> {
        let mut sigs: Vec<Signature> =
            Vec::with_capacity(self.config.get_num_unspent_kickoff_sigs());
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        let operator_data = OperatorData {
            xonly_pk: self.signer.xonly_public_key,
            collateral_funding_outpoint: self.collateral_funding_outpoint,
            reimburse_addr: self.reimburse_addr.clone(),
        };
        for idx in 0..self.config.protocol_paramset().num_round_txs {
            let txhandlers = create_round_txhandlers(
                self.config.protocol_paramset(),
                idx,
                &operator_data,
                kickoff_wpks,
                prev_ready_to_reimburse.as_ref(),
            )?;
            for txhandler in txhandlers {
                if let TransactionType::UnspentKickoff(kickoff_idx) =
                    txhandler.get_transaction_type()
                {
                    let partial = PartialSignatureInfo {
                        operator_idx: self.idx,
                        round_idx: idx,
                        kickoff_utxo_idx: kickoff_idx,
                    };
                    let sighashes = txhandler
                        .calculate_shared_txins_sighash(EntityType::OperatorSetup, partial)?;
                    sigs.extend(
                        sighashes
                            .into_iter()
                            .map(|sighash| self.signer.sign(sighash.0)),
                    );
                }
                if let TransactionType::ReadyToReimburse = txhandler.get_transaction_type() {
                    prev_ready_to_reimburse = Some(txhandler);
                }
            }
        }
        if sigs.len() != self.config.get_num_unspent_kickoff_sigs() {
            return Err(BridgeError::Error(format!(
                "Expected {} number of unspent kickoff sigs, but got {}",
                self.config.get_num_unspent_kickoff_sigs(),
                sigs.len()
            )));
        }
        Ok(sigs)
    }

    pub fn generate_challenge_ack_preimages_and_hashes(
        &self,
        deposit_txid: Txid,
    ) -> Result<Vec<PublicHash>, BridgeError> {
        let mut hashes = Vec::with_capacity(self.config.get_num_challenge_ack_hashes());

        for watchtower_idx in 0..self.config.protocol_paramset().num_watchtowers {
            let path = WinternitzDerivationPath::ChallengeAckHash(
                watchtower_idx as u32,
                deposit_txid,
                self.config.protocol_paramset(),
            );
            let hash = self.signer.generate_public_hash_from_path(path)?;
            hashes.push(hash);
        }

        if hashes.len() != self.config.get_num_challenge_ack_hashes() {
            return Err(BridgeError::Error(format!(
                "Expected {} number of challenge ack hashes, but got {}",
                self.config.get_num_challenge_ack_hashes(),
                hashes.len()
            )));
        }

        Ok(hashes)
    }

    pub async fn handle_finalized_payout<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        deposit_outpoint: OutPoint,
        payout_tx_blockhash: BlockHash,
    ) -> Result<bitcoin::Txid, BridgeError> {
        let (deposit_id, deposit_data) = self
            .db
            .get_deposit_data(Some(dbtx), deposit_outpoint)
            .await?
            .ok_or(BridgeError::DatabaseError(sqlx::Error::RowNotFound))?;

        // get unused kickoff connector
        let (round_idx, kickoff_idx) = self
            .db
            .get_unused_and_signed_kickoff_connector(Some(dbtx), deposit_id)
            .await?
            .ok_or(BridgeError::DatabaseError(sqlx::Error::RowNotFound))?;

        // get signed txs,
        let kickoff_id = KickoffId {
            operator_idx: self.idx as u32,
            round_idx,
            kickoff_idx,
        };

        let transaction_data = TransactionRequestData {
            deposit_data,
            kickoff_id,
        };
        let signed_txs = create_and_sign_txs(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            transaction_data,
            Some(
                payout_tx_blockhash.as_byte_array()[12..] // TODO: Make a helper function for this
                    .try_into()
                    .expect("length statically known"),
            ),
        )
        .await?;

        let tx_metadata = Some(TxMetadata {
            tx_type: TransactionType::Dummy, // will be replaced in add_tx_to_queue
            operator_idx: Some(self.idx as u32),
            verifier_idx: None,
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
                    self.tx_sender
                        .add_tx_to_queue(
                            dbtx,
                            *tx_type,
                            signed_tx,
                            &signed_txs,
                            tx_metadata,
                            &self.config,
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
            .ok_or(BridgeError::Error(
                "Couldn't find kickoff tx in signed_txs".to_string(),
            ))?;

        // mark the kickoff connector as used
        self.db
            .set_kickoff_connector_as_used(Some(dbtx), round_idx, kickoff_idx, Some(kickoff_txid))
            .await?;

        Ok(kickoff_txid)
    }

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
            .get_operator_kickoff_winternitz_public_keys(None, self.idx as u32)
            .await?;
        let kickoff_wpks = KickoffWinternitzKeys::new(
            operator_winternitz_public_keys,
            self.config.protocol_paramset().num_kickoffs_per_round,
        );
        let (current_round_txhandler, mut ready_to_reimburse_txhandler) =
            create_round_nth_txhandler(
                self.signer.xonly_public_key,
                self.collateral_funding_outpoint,
                Amount::from_sat(200_000_000), // TODO: Get this from protocol constants config
                current_round_index as usize,
                &kickoff_wpks,
                self.config.protocol_paramset(),
            )?;

        let (mut next_round_txhandler, _) = create_round_nth_txhandler(
            self.signer.xonly_public_key,
            self.collateral_funding_outpoint,
            Amount::from_sat(200_000_000), // TODO: Get this from protocol constants config
            current_round_index as usize + 1,
            &kickoff_wpks,
            self.config.protocol_paramset(),
        )?;

        // sign ready to reimburse tx
        self.signer
            .tx_sign_and_fill_sigs(&mut ready_to_reimburse_txhandler, &[])?;

        // sign next round tx
        self.signer
            .tx_sign_and_fill_sigs(&mut next_round_txhandler, &[])?;

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
                    current_round_index,
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
                            current_round_index,
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
            )?;

        // sign burn unused kickoff connectors tx
        self.signer
            .tx_sign_and_fill_sigs(&mut burn_unspent_kickoff_connectors_tx, &[])?;

        self.tx_sender
            .insert_try_to_send(
                dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::BurnUnusedKickoffConnectors,
                    operator_idx: Some(self.idx as u32),
                    verifier_idx: None,
                    round_idx: Some(current_round_index),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                burn_unspent_kickoff_connectors_tx.get_cached_tx(),
                FeePayingType::CPFP,
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
                    operator_idx: Some(self.idx as u32),
                    verifier_idx: None,
                    round_idx: Some(current_round_index),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                ready_to_reimburse_tx,
                FeePayingType::CPFP,
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
                    operator_idx: Some(self.idx as u32),
                    verifier_idx: None,
                    round_idx: Some(current_round_index + 1),
                    kickoff_idx: None,
                    deposit_outpoint: None,
                }),
                next_round_tx,
                FeePayingType::CPFP,
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
            .update_current_round_index(Some(dbtx), current_round_index + 1)
            .await?;

        Ok(())
    }

    async fn send_asserts(
        &self,
        kickoff_id: KickoffId,
        deposit_data: DepositData,
        _watchtower_challenges: HashMap<usize, Transaction>,
        _payout_blockhash: Witness,
    ) -> Result<(), BridgeError> {
        let assert_txs = self
            .create_assert_commitment_txs(TransactionRequestData {
                kickoff_id,
                deposit_data: deposit_data.clone(),
            })
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
                        operator_idx: Some(self.idx as u32),
                        verifier_idx: None,
                        round_idx: Some(kickoff_id.round_idx),
                        kickoff_idx: Some(kickoff_id.kickoff_idx),
                        deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                    }),
                    &self.config,
                )
                .await?;
        }
        dbtx.commit().await?;
        Ok(())
    }

    fn data(&self) -> OperatorData {
        OperatorData {
            xonly_pk: self.signer.xonly_public_key,
            collateral_funding_outpoint: self.collateral_funding_outpoint,
            reimburse_addr: self.reimburse_addr.clone(),
        }
    }
}

#[tonic::async_trait]
impl<C> Owner for Operator<C>
where
    C: CitreaClientT,
{
    const OWNER_TYPE: &'static str = "operator";
    async fn handle_duty(&self, duty: Duty) -> Result<(), BridgeError> {
        match duty {
            Duty::NewReadyToReimburse {
                round_idx,
                operator_idx,
                used_kickoffs,
            } => {
                tracing::info!("Operator {} called new ready to reimburse with round_idx: {}, operator_idx: {}, used_kickoffs: {:?}", self.idx, round_idx, operator_idx, used_kickoffs);
            }
            Duty::WatchtowerChallenge {
                kickoff_id,
                deposit_data,
            } => {
                tracing::info!(
                    "Operator {} called watchtower challenge with kickoff_id: {:?}, deposit_data: {:?}",
                    self.idx, kickoff_id, deposit_data
                );
            }
            Duty::SendOperatorAsserts {
                kickoff_id,
                deposit_data,
                watchtower_challenges,
                payout_blockhash,
            } => {
                tracing::warn!("Operator {} called send operator asserts with kickoff_id: {:?}, deposit_data: {:?}, watchtower_challenges: {:?}", self.idx, kickoff_id, deposit_data, watchtower_challenges.len());
                self.send_asserts(
                    kickoff_id,
                    deposit_data,
                    watchtower_challenges,
                    payout_blockhash,
                )
                .await?;
            }
            Duty::VerifierDisprove {
                kickoff_id,
                deposit_data,
                operator_asserts,
                operator_acks,
                payout_blockhash,
            } => {
                tracing::info!("Operator {} called verifier disprove with kickoff_id: {:?}, deposit_data: {:?}, operator_asserts: {:?}, operator_acks: {:?}
                payout_blockhash: {:?}", self.idx, kickoff_id, deposit_data, operator_asserts.len(), operator_acks.len(), payout_blockhash.len());
            }
            Duty::CheckIfKickoff {
                txid,
                block_height,
                witness,
            } => {
                tracing::info!(
                    "Operator {} called check if kickoff with txid: {:?}, block_height: {:?}",
                    self.idx,
                    txid,
                    block_height,
                );
                let kickoff_data = self
                    .db
                    .get_deposit_signatures_with_kickoff_txid(None, txid)
                    .await?;
                if let Some((deposit_data, kickoff_id, _)) = kickoff_data {
                    // add kickoff machine if there is a new kickoff
                    let mut dbtx = self.db.begin_transaction().await?;
                    StateManager::<Self>::dispatch_new_kickoff_machine(
                        self.db.clone(),
                        &mut dbtx,
                        kickoff_id,
                        block_height,
                        deposit_data,
                        witness,
                    )
                    .await?;
                    dbtx.commit().await?;
                }
            }
        }
        Ok(())
    }

    async fn create_txhandlers(
        &self,
        tx_type: TransactionType,
        contract_context: ContractContext,
    ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
        let mut db_cache =
            ReimburseDbCache::from_context(self.db.clone(), contract_context.clone());
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

#[cfg(test)]
mod tests {
    use crate::citrea::mock::MockCitreaClient;
    use crate::operator::Operator;
    use crate::test::common::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    // #[tokio::test]
    // async fn set_funding_utxo() {
    //     let mut config = create_test_config_with_thread_name().await;
    //     let rpc = ExtendedRpc::connect(
    //         config.bitcoin_rpc_url.clone(),
    //         config.bitcoin_rpc_user.clone(),
    //         config.bitcoin_rpc_password.clone(),
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
    //     let rpc = ExtendedRpc::connect(
    //         config.bitcoin_rpc_url.clone(),
    //         config.bitcoin_rpc_user.clone(),
    //         config.bitcoin_rpc_password.clone(),
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

        let winternitz_public_key = operator
            .generate_assert_winternitz_pubkeys(Txid::all_zeros())
            .unwrap();
        assert_eq!(
            winternitz_public_key.len(),
            config.protocol_paramset().num_round_txs
                * config.protocol_paramset().num_kickoffs_per_round
        );
    }

    #[tokio::test]
    async fn test_generate_preimages_and_hashes() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let operator = Operator::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();

        let preimages = operator
            .generate_challenge_ack_preimages_and_hashes(Txid::all_zeros())
            .unwrap();
        assert_eq!(preimages.len(), config.protocol_paramset().num_watchtowers);
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
