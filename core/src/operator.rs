use ark_ff::PrimeField;
use circuits_lib::common::constants::{FIRST_FIVE_OUTPUTS, NUMBER_OF_ASSERT_TXS};
use risc0_zkvm::is_dev_mode;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use crate::actor::{Actor, TweakCache, WinternitzDerivationPath};
use crate::bitvm_client::{ClementineBitVMPublicKeys, SECP};
use crate::builder::script::extract_winternitz_commits;
use crate::builder::sighash::{create_operator_sighash_stream, PartialSignatureInfo};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::builder::transaction::{
    create_burn_unused_kickoff_connectors_txhandler, create_round_nth_txhandler,
    create_round_txhandlers, create_txhandlers, ContractContext, DepositData, KickoffData,
    KickoffWinternitzKeys, OperatorData, ReimburseDbCache, TransactionType, TxHandler,
    TxHandlerCache,
};
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::database::DatabaseTransaction;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::header_chain_prover::HeaderChainProver;
use crate::states::context::DutyResult;
use crate::states::{block_cache, Duty, Owner, StateManager};
use crate::task::manager::BackgroundTaskManager;
use crate::task::payout_checker::{PayoutCheckerTask, PAYOUT_CHECKER_POLL_DELAY};
use crate::task::{IntoTask, TaskExt};
use crate::tx_sender::TxSenderClient;
use crate::tx_sender::{ActivatedWithOutpoint, ActivatedWithTxid, FeePayingType, TxMetadata};
use crate::utils::Last20Bytes;
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
use bitvm::chunk::api::{generate_assertions, Assertions};
use bitvm::signatures::winternitz;
use bridge_circuit_host::bridge_circuit_host::{
    create_spv, prove_bridge_circuit, MAINNET_BRIDGE_CIRCUIT_ELF, REGTEST_BRIDGE_CIRCUIT_ELF,
    SIGNET_BRIDGE_CIRCUIT_ELF, TESTNET4_BRIDGE_CIRCUIT_ELF,
};
use bridge_circuit_host::structs::{BridgeCircuitHostParams, WatchtowerContext};
use bridge_circuit_host::utils::{get_ark_verifying_key, get_ark_verifying_key_dev_mode_bridge};
use eyre::{Context, OptionExt};
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
    pub collateral_funding_outpoint: OutPoint,
    pub(crate) reimburse_addr: Address,
    pub tx_sender: TxSenderClient,
    pub header_chain_prover: HeaderChainProver,
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

        tracing::info!("State manager created");

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
            tracing::info!("State manager tasks started");
        }

        // run payout checker task
        background_tasks.loop_and_monitor(
            PayoutCheckerTask::new(operator.db.clone(), operator.clone())
                .with_delay(PAYOUT_CHECKER_POLL_DELAY),
        );

        tracing::info!("Payout checker task started");

        // track the operator's round state
        operator.track_rounds().await?;
        tracing::info!("Operator round state tracked");

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

        let tx_sender = TxSenderClient::new(
            db.clone(),
            format!("operator_{:?}", signer.xonly_public_key).to_string(),
        );

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
                        let collateral_value = collateral_tx
                            .output
                            .get(outpoint.vout as usize)
                            .ok_or_eyre("Invalid vout index for collateral funding tx")?
                            .value;
                        if collateral_value != config.protocol_paramset().collateral_funding_amount
                        {
                            return Err(eyre::eyre!("Operator collateral funding outpoint given in config has a different amount than the one specified in config..
                                Bridge collateral funnding amount: {:?}, Amount in given outpoint: {:?}", config.protocol_paramset().collateral_funding_amount, collateral_value).into());
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
        )
        .await?;

        tracing::info!(
            "Operator xonly pk: {:?}, db created with name: {:?}",
            signer.xonly_public_key,
            config.db_name
        );

        let header_chain_prover = HeaderChainProver::new(&config, rpc.clone()).await?;

        Ok(Operator {
            rpc,
            db: db.clone(),
            signer,
            config,
            collateral_funding_outpoint,
            tx_sender,
            citrea_client,
            header_chain_prover,
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
            .clone()
            .tx_sign_and_fill_sigs(&mut first_round_tx, &[], None)?;

        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .insert_try_to_send(
                &mut dbtx,
                Some(TxMetadata {
                    tx_type: TransactionType::Round,
                    operator_xonly_pk: None,
                    round_idx: Some(0),
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
        dbtx.commit().await?;

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
        let (sig_tx, sig_rx) = mpsc::channel(1280);

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
        let mut tweak_cache = TweakCache::default();
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
                        operator_idx: 0, // dummy value, doesn't
                        round_idx: idx,
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
            return Err(BridgeError::Error(format!(
                "Expected {} number of challenge ack hashes, but got {}",
                self.config.get_num_challenge_ack_hashes(deposit_data),
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

        let payout_tx_blockhash: [u8; 20] = payout_tx_blockhash.as_byte_array().last_20_bytes();

        #[cfg(test)]
        let mut payout_tx_blockhash = payout_tx_blockhash;

        #[cfg(test)]
        {
            if self.config.test_params.disrupt_payout_tx_block_hash_commit {
                tracing::info!("Disrupting latest blockhash for testing purposes",);
                payout_tx_blockhash[19] ^= 0x01;
            }
        }

        let signed_txs = create_and_sign_txs(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            transaction_data,
            Some(payout_tx_blockhash),
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
            .get_operator_kickoff_winternitz_public_keys(None, self.signer.xonly_public_key)
            .await?;
        let kickoff_wpks = KickoffWinternitzKeys::new(
            operator_winternitz_public_keys,
            self.config.protocol_paramset().num_kickoffs_per_round,
        );
        let (current_round_txhandler, mut ready_to_reimburse_txhandler) =
            create_round_nth_txhandler(
                self.signer.xonly_public_key,
                self.collateral_funding_outpoint,
                self.config.protocol_paramset().collateral_funding_amount,
                current_round_index as usize,
                &kickoff_wpks,
                self.config.protocol_paramset(),
            )?;

        let (mut next_round_txhandler, _) = create_round_nth_txhandler(
            self.signer.xonly_public_key,
            self.collateral_funding_outpoint,
            self.config.protocol_paramset().collateral_funding_amount,
            current_round_index as usize + 1,
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
                    round_idx: Some(current_round_index),
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
                    round_idx: Some(current_round_index),
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
                    round_idx: Some(current_round_index + 1),
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
            .update_current_round_index(Some(dbtx), current_round_index + 1)
            .await?;

        Ok(())
    }

    async fn send_asserts(
        &self,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        watchtower_challenges: HashMap<usize, Transaction>,
        _payout_blockhash: Witness,
        latest_blockhash: Witness,
    ) -> Result<(), BridgeError> {
        let context = ContractContext::new_context_for_kickoffs(
            kickoff_data,
            deposit_data.clone(),
            self.config.protocol_paramset(),
        );
        let mut db_cache = ReimburseDbCache::from_context(self.db.clone(), &context);
        let txhandlers = create_txhandlers(
            TransactionType::Kickoff,
            context,
            &mut TxHandlerCache::new(),
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

        let latest_blockhash = commits
            .first()
            .ok_or_eyre("Failed to get latest blockhash in send_asserts")?
            .to_owned();

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

        #[cfg(test)]
        let mut latest_blockhash = latest_blockhash;

        #[cfg(test)]
        {
            if self.config.test_params.disrupt_latest_block_hash_commit {
                tracing::info!("Correcting latest blockhash for testing purposes",);
                latest_blockhash[19] ^= 0x01;
            }
        }

        // find out which blockhash is latest_blockhash (only last 20 bytes is commited to Witness)
        let latest_blockhash_index = block_hashes
            .iter()
            .position(|(block_hash, _)| {
                block_hash.to_byte_array()[12..].to_vec() == latest_blockhash
            })
            .ok_or_eyre("Failed to find latest blockhash in send_asserts")?;

        let latest_blockhash = block_hashes[latest_blockhash_index].0;

        let (current_hcp, hcp_height) = self
            .header_chain_prover
            .prove_till_hash(latest_blockhash)
            .await?;
        tracing::info!("Got header chain proof in send_asserts");

        let blockhashes_serialized: Vec<[u8; 32]> = block_hashes
            .iter()
            .take(hcp_height as usize + 1) // height 0 included
            .map(|(block_hash, _)| block_hash.to_byte_array())
            .collect::<Vec<_>>();

        let spv = create_spv(
            payout_tx.clone(),
            &blockhashes_serialized,
            payout_block.clone(),
            payout_block_height,
            self.config.protocol_paramset().genesis_height,
            payout_tx_index as u32,
        );
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
            bitcoin::Network::Regtest => REGTEST_BRIDGE_CIRCUIT_ELF,
            _ => {
                return Err(eyre::eyre!(
                    "Unsupported network {:?} in send_asserts",
                    self.config.protocol_paramset().network
                )
                .into())
            }
        };
        tracing::info!("Starting proving bridge circuit to send asserts");
        let (g16_proof, g16_output, public_inputs) =
            prove_bridge_circuit(bridge_circuit_host_params, bridge_circuit_elf);
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

        // let mut asserts: Assertions = ([[0u8; 32]; 1], [[0u8; 32]; 14], [[0u8; 16]; 363]);
        let mut asserts: Assertions;

        #[cfg(test)]
        {
            if self
                .config
                .test_params
                .disrupt_challenge_sending_watchtowers_commit
                || self.config.test_params.disrupt_latest_block_hash_commit
                || self.config.test_params.disrupt_payout_tx_block_hash_commit
                || self.config.test_params.operator_forgot_watchtower_challenge
            {
                asserts = (
                    [[
                        0, 178, 51, 243, 229, 205, 245, 50, 69, 243, 148, 88, 21, 74, 247, 23, 49,
                        176, 135, 57, 96, 234, 230, 81, 64, 202, 83, 42, 148, 106, 162, 88,
                    ]],
                    [
                        [
                            146, 150, 19, 97, 196, 159, 27, 18, 73, 237, 172, 165, 7, 143, 95, 109,
                            216, 58, 77, 199, 204, 92, 166, 72, 141, 90, 73, 191, 254, 21, 96, 138,
                        ],
                        [
                            82, 93, 130, 87, 188, 20, 209, 48, 163, 61, 151, 254, 176, 71, 9, 82,
                            235, 36, 153, 252, 103, 246, 229, 125, 121, 120, 131, 3, 104, 63, 112,
                            169,
                        ],
                        [
                            210, 242, 58, 14, 75, 47, 213, 246, 37, 49, 224, 14, 157, 29, 61, 170,
                            255, 1, 28, 61, 10, 27, 107, 149, 71, 156, 225, 120, 8, 142, 28, 78,
                        ],
                        [
                            145, 204, 172, 37, 82, 174, 118, 253, 144, 253, 150, 245, 49, 17, 121,
                            191, 133, 248, 9, 138, 62, 18, 157, 35, 155, 182, 215, 99, 52, 157,
                            165, 232,
                        ],
                        [
                            129, 172, 120, 111, 81, 202, 56, 104, 6, 62, 248, 226, 247, 130, 239,
                            113, 126, 204, 68, 89, 73, 138, 160, 123, 53, 35, 127, 162, 135, 169,
                            190, 52,
                        ],
                        [
                            177, 121, 71, 61, 220, 200, 153, 252, 84, 71, 50, 73, 34, 124, 176,
                            215, 167, 63, 144, 140, 33, 141, 23, 252, 146, 105, 240, 214, 156, 84,
                            177, 1,
                        ],
                        [
                            178, 116, 178, 179, 66, 147, 60, 176, 149, 150, 109, 90, 44, 86, 156,
                            0, 161, 167, 80, 246, 109, 47, 30, 227, 9, 49, 81, 223, 4, 114, 69, 18,
                        ],
                        [
                            128, 38, 120, 164, 181, 170, 197, 171, 232, 203, 175, 66, 246, 141,
                            149, 114, 98, 219, 23, 11, 133, 109, 94, 143, 19, 255, 211, 47, 129,
                            171, 8, 238,
                        ],
                        [
                            240, 9, 39, 246, 251, 47, 91, 63, 29, 230, 229, 86, 54, 251, 14, 15,
                            185, 6, 21, 216, 133, 160, 78, 253, 247, 85, 233, 146, 197, 117, 49,
                            191,
                        ],
                        [
                            241, 58, 197, 171, 213, 193, 137, 130, 70, 101, 168, 64, 68, 171, 118,
                            196, 231, 22, 211, 76, 7, 1, 110, 53, 220, 37, 168, 13, 22, 3, 215,
                            195,
                        ],
                        [
                            192, 105, 97, 77, 49, 116, 35, 224, 211, 241, 74, 167, 206, 79, 81, 47,
                            234, 161, 60, 101, 195, 160, 245, 37, 100, 83, 80, 179, 227, 168, 56,
                            7,
                        ],
                        [
                            193, 72, 110, 176, 5, 0, 111, 17, 190, 68, 227, 254, 6, 107, 12, 162,
                            35, 162, 82, 6, 241, 135, 254, 95, 53, 122, 98, 218, 48, 102, 98, 18,
                        ],
                        [
                            34, 82, 206, 46, 252, 154, 179, 132, 213, 237, 48, 252, 108, 38, 145,
                            67, 116, 183, 32, 106, 242, 72, 233, 12, 120, 13, 188, 33, 159, 139,
                            118, 9,
                        ],
                        [
                            1, 50, 217, 238, 134, 14, 177, 85, 122, 145, 52, 159, 78, 172, 169,
                            241, 208, 128, 84, 204, 241, 135, 232, 59, 237, 201, 138, 237, 224, 97,
                            198, 100,
                        ],
                    ],
                    [
                        [
                            69, 88, 199, 181, 121, 25, 162, 199, 78, 151, 28, 190, 61, 147, 116,
                            188,
                        ],
                        [
                            10, 13, 199, 94, 85, 42, 163, 204, 112, 204, 47, 177, 133, 233, 12, 86,
                        ],
                        [
                            199, 112, 151, 251, 59, 78, 206, 108, 131, 120, 125, 104, 153, 88, 27,
                            178,
                        ],
                        [
                            97, 43, 23, 162, 187, 156, 26, 70, 214, 68, 125, 169, 67, 134, 77, 224,
                        ],
                        [
                            16, 146, 104, 188, 179, 84, 72, 164, 65, 46, 13, 14, 102, 153, 251, 8,
                        ],
                        [
                            51, 188, 138, 92, 7, 26, 169, 61, 41, 48, 190, 28, 193, 130, 196, 65,
                        ],
                        [
                            74, 145, 186, 152, 215, 185, 33, 82, 202, 189, 215, 228, 1, 40, 43, 219,
                        ],
                        [
                            192, 16, 56, 4, 161, 76, 82, 180, 67, 234, 74, 59, 67, 115, 165, 122,
                        ],
                        [
                            211, 90, 27, 177, 206, 185, 213, 240, 83, 156, 222, 91, 245, 229, 176,
                            97,
                        ],
                        [
                            123, 154, 145, 134, 208, 220, 18, 68, 31, 7, 30, 249, 70, 18, 207, 1,
                        ],
                        [
                            181, 35, 67, 171, 182, 69, 103, 46, 164, 74, 99, 100, 78, 90, 75, 21,
                        ],
                        [
                            153, 43, 208, 139, 234, 82, 139, 87, 112, 23, 49, 56, 5, 159, 238, 115,
                        ],
                        [
                            184, 179, 115, 232, 109, 4, 9, 54, 112, 130, 219, 178, 224, 56, 5, 206,
                        ],
                        [
                            15, 89, 221, 2, 44, 227, 145, 151, 233, 248, 178, 211, 94, 176, 88, 88,
                        ],
                        [
                            116, 76, 101, 171, 199, 114, 231, 4, 81, 207, 30, 150, 65, 108, 230,
                            159,
                        ],
                        [
                            219, 212, 130, 90, 133, 103, 133, 156, 74, 211, 239, 74, 48, 173, 180,
                            182,
                        ],
                        [
                            4, 241, 93, 233, 194, 54, 191, 74, 243, 91, 253, 5, 168, 71, 123, 246,
                        ],
                        [
                            223, 85, 40, 15, 176, 77, 216, 231, 173, 134, 6, 28, 95, 37, 20, 231,
                        ],
                        [
                            251, 215, 35, 162, 120, 90, 206, 66, 225, 130, 215, 82, 14, 132, 124,
                            97,
                        ],
                        [
                            242, 196, 90, 140, 153, 125, 15, 134, 243, 166, 203, 36, 196, 82, 254,
                            1,
                        ],
                        [
                            42, 78, 38, 194, 37, 170, 67, 87, 240, 85, 214, 176, 105, 138, 43, 86,
                        ],
                        [
                            175, 131, 52, 6, 104, 67, 120, 215, 221, 119, 97, 156, 48, 196, 5, 182,
                        ],
                        [
                            202, 85, 190, 89, 122, 203, 153, 9, 149, 234, 106, 163, 71, 160, 189,
                            57,
                        ],
                        [
                            76, 74, 236, 61, 218, 112, 19, 113, 116, 15, 236, 201, 178, 173, 67, 14,
                        ],
                        [
                            204, 183, 25, 18, 24, 134, 116, 178, 11, 30, 237, 239, 207, 1, 104, 99,
                        ],
                        [
                            162, 235, 103, 77, 224, 57, 89, 81, 61, 134, 112, 144, 61, 209, 199,
                            109,
                        ],
                        [
                            207, 124, 116, 41, 25, 68, 215, 255, 30, 81, 33, 162, 8, 180, 51, 170,
                        ],
                        [
                            128, 181, 100, 123, 48, 78, 110, 140, 129, 231, 76, 30, 109, 88, 254, 2,
                        ],
                        [
                            113, 241, 206, 87, 73, 145, 166, 94, 11, 59, 208, 57, 35, 54, 87, 138,
                        ],
                        [
                            156, 48, 174, 137, 31, 21, 42, 107, 58, 160, 212, 126, 211, 199, 24,
                            192,
                        ],
                        [
                            113, 125, 204, 17, 38, 155, 12, 49, 187, 246, 10, 14, 83, 92, 80, 206,
                        ],
                        [
                            153, 206, 179, 49, 18, 48, 222, 148, 184, 84, 61, 89, 212, 251, 89, 6,
                        ],
                        [
                            252, 165, 46, 8, 188, 61, 59, 62, 60, 117, 115, 128, 138, 24, 18, 203,
                        ],
                        [
                            35, 98, 80, 182, 122, 81, 2, 167, 224, 3, 18, 34, 21, 8, 79, 80,
                        ],
                        [
                            142, 112, 183, 49, 172, 101, 240, 113, 41, 227, 248, 9, 56, 232, 105,
                            104,
                        ],
                        [
                            189, 238, 156, 246, 147, 145, 91, 98, 168, 47, 32, 217, 145, 179, 74,
                            66,
                        ],
                        [
                            212, 173, 43, 130, 144, 135, 129, 170, 178, 14, 175, 174, 22, 247, 127,
                            41,
                        ],
                        [
                            41, 125, 130, 212, 212, 130, 77, 55, 64, 190, 160, 170, 62, 223, 216,
                            243,
                        ],
                        [
                            79, 80, 228, 175, 64, 191, 94, 79, 232, 176, 1, 180, 110, 53, 119, 40,
                        ],
                        [
                            91, 5, 90, 42, 222, 126, 27, 8, 60, 72, 194, 42, 164, 123, 153, 58,
                        ],
                        [
                            78, 124, 104, 173, 227, 72, 188, 215, 244, 227, 73, 2, 135, 169, 165,
                            150,
                        ],
                        [
                            116, 6, 66, 203, 244, 62, 97, 48, 244, 250, 149, 216, 227, 220, 240, 45,
                        ],
                        [
                            45, 64, 190, 46, 98, 246, 149, 3, 27, 123, 106, 163, 67, 66, 215, 78,
                        ],
                        [
                            81, 109, 103, 187, 169, 165, 144, 85, 65, 155, 101, 31, 149, 19, 117,
                            75,
                        ],
                        [
                            37, 123, 101, 184, 100, 140, 185, 177, 202, 217, 49, 69, 44, 23, 65,
                            183,
                        ],
                        [
                            121, 76, 102, 146, 185, 34, 107, 166, 96, 112, 133, 154, 19, 70, 101,
                            29,
                        ],
                        [
                            46, 119, 98, 53, 65, 118, 237, 76, 161, 167, 50, 14, 21, 166, 154, 80,
                        ],
                        [
                            49, 29, 131, 187, 181, 65, 213, 121, 36, 238, 117, 155, 128, 255, 181,
                            52,
                        ],
                        [
                            129, 27, 134, 130, 201, 214, 146, 50, 80, 205, 216, 241, 194, 179, 213,
                            118,
                        ],
                        [
                            168, 86, 2, 249, 139, 40, 48, 153, 86, 26, 47, 68, 74, 152, 211, 137,
                        ],
                        [
                            236, 136, 158, 103, 85, 235, 227, 114, 8, 208, 186, 0, 21, 14, 38, 131,
                        ],
                        [
                            221, 180, 190, 161, 8, 62, 166, 198, 98, 2, 252, 202, 12, 37, 118, 126,
                        ],
                        [
                            231, 221, 112, 180, 14, 242, 79, 0, 93, 138, 20, 212, 179, 60, 219, 126,
                        ],
                        [
                            94, 121, 98, 92, 219, 224, 112, 47, 150, 140, 65, 2, 5, 226, 96, 58,
                        ],
                        [
                            163, 118, 25, 254, 33, 246, 156, 93, 249, 92, 207, 110, 80, 74, 18, 32,
                        ],
                        [
                            116, 27, 5, 138, 254, 48, 175, 110, 83, 62, 60, 88, 155, 24, 208, 230,
                        ],
                        [
                            60, 185, 174, 253, 238, 35, 128, 175, 97, 157, 66, 90, 197, 23, 238,
                            223,
                        ],
                        [
                            147, 89, 190, 132, 38, 174, 74, 248, 65, 163, 22, 23, 181, 103, 159, 9,
                        ],
                        [
                            212, 249, 159, 202, 218, 167, 145, 161, 69, 215, 122, 9, 231, 143, 6,
                            178,
                        ],
                        [
                            71, 149, 17, 38, 46, 16, 212, 186, 55, 149, 206, 9, 154, 183, 105, 240,
                        ],
                        [
                            153, 208, 86, 159, 143, 177, 36, 190, 13, 74, 216, 212, 73, 111, 131,
                            140,
                        ],
                        [
                            24, 222, 130, 105, 183, 101, 245, 124, 72, 166, 233, 205, 54, 173, 112,
                            34,
                        ],
                        [
                            126, 81, 250, 255, 151, 29, 177, 41, 165, 244, 175, 197, 152, 16, 17,
                            53,
                        ],
                        [
                            112, 81, 217, 82, 22, 8, 131, 80, 138, 135, 200, 107, 150, 233, 191,
                            161,
                        ],
                        [
                            255, 1, 23, 236, 45, 139, 112, 126, 9, 93, 188, 23, 28, 219, 79, 33,
                        ],
                        [
                            167, 68, 86, 37, 156, 172, 193, 44, 96, 192, 60, 118, 62, 150, 39, 42,
                        ],
                        [
                            198, 16, 105, 28, 88, 171, 93, 13, 242, 112, 119, 211, 240, 247, 97,
                            102,
                        ],
                        [
                            199, 185, 238, 95, 131, 28, 74, 199, 5, 39, 220, 123, 47, 235, 158, 110,
                        ],
                        [
                            39, 76, 203, 101, 87, 201, 9, 153, 170, 111, 214, 78, 37, 83, 172, 1,
                        ],
                        [
                            211, 252, 104, 55, 94, 89, 247, 239, 151, 148, 241, 174, 225, 129, 6,
                            20,
                        ],
                        [
                            1, 203, 11, 168, 146, 172, 51, 54, 145, 33, 163, 204, 9, 226, 143, 242,
                        ],
                        [
                            230, 29, 208, 214, 79, 114, 0, 250, 114, 21, 46, 81, 28, 249, 100, 149,
                        ],
                        [
                            62, 87, 246, 51, 185, 160, 194, 50, 184, 148, 24, 72, 0, 190, 40, 133,
                        ],
                        [
                            58, 11, 195, 121, 143, 192, 102, 131, 172, 3, 232, 128, 6, 160, 237,
                            148,
                        ],
                        [
                            185, 60, 236, 28, 28, 202, 228, 28, 100, 109, 94, 136, 31, 103, 196, 63,
                        ],
                        [
                            133, 213, 245, 206, 82, 93, 81, 134, 185, 250, 220, 138, 195, 124, 214,
                            72,
                        ],
                        [
                            108, 134, 57, 8, 1, 71, 138, 11, 97, 95, 119, 52, 187, 66, 190, 255,
                        ],
                        [
                            133, 77, 87, 101, 240, 150, 63, 20, 83, 96, 38, 219, 142, 239, 153, 204,
                        ],
                        [
                            216, 142, 153, 90, 84, 33, 240, 167, 107, 12, 135, 35, 172, 209, 132,
                            133,
                        ],
                        [
                            28, 111, 49, 0, 214, 124, 15, 121, 134, 160, 98, 174, 129, 232, 93, 173,
                        ],
                        [
                            112, 144, 174, 93, 66, 90, 156, 230, 177, 155, 119, 172, 192, 84, 226,
                            254,
                        ],
                        [
                            196, 71, 177, 209, 18, 227, 56, 88, 32, 185, 220, 160, 11, 31, 143, 145,
                        ],
                        [
                            66, 44, 115, 191, 147, 250, 161, 52, 9, 57, 17, 240, 62, 92, 222, 246,
                        ],
                        [
                            61, 217, 188, 210, 98, 134, 252, 51, 159, 107, 9, 102, 255, 69, 142,
                            233,
                        ],
                        [
                            232, 224, 106, 125, 63, 255, 165, 170, 149, 9, 95, 234, 204, 184, 105,
                            142,
                        ],
                        [
                            16, 17, 80, 219, 31, 104, 43, 25, 148, 18, 219, 12, 157, 22, 43, 79,
                        ],
                        [
                            132, 96, 40, 74, 184, 228, 230, 57, 231, 60, 2, 145, 150, 235, 132, 178,
                        ],
                        [
                            124, 225, 150, 244, 217, 249, 106, 138, 129, 84, 20, 242, 55, 6, 211,
                            161,
                        ],
                        [
                            118, 174, 122, 106, 118, 155, 120, 68, 125, 192, 2, 112, 53, 96, 113,
                            200,
                        ],
                        [
                            24, 218, 167, 22, 71, 25, 53, 133, 166, 213, 149, 218, 156, 121, 40,
                            229,
                        ],
                        [
                            109, 2, 58, 51, 180, 69, 219, 75, 37, 134, 202, 51, 95, 104, 191, 114,
                        ],
                        [
                            251, 185, 225, 36, 143, 205, 1, 99, 188, 250, 239, 117, 244, 74, 42,
                            164,
                        ],
                        [
                            151, 86, 44, 188, 235, 3, 147, 22, 10, 169, 112, 1, 3, 66, 95, 64,
                        ],
                        [
                            60, 104, 84, 177, 230, 121, 178, 21, 87, 91, 212, 99, 198, 19, 252, 133,
                        ],
                        [
                            122, 74, 208, 149, 37, 49, 20, 44, 78, 217, 243, 222, 52, 36, 33, 58,
                        ],
                        [
                            8, 118, 9, 233, 49, 69, 24, 225, 197, 168, 98, 195, 32, 190, 201, 112,
                        ],
                        [
                            9, 212, 48, 85, 8, 130, 1, 200, 80, 143, 155, 31, 121, 204, 104, 57,
                        ],
                        [
                            12, 29, 119, 93, 162, 41, 155, 69, 236, 55, 183, 142, 110, 173, 210, 14,
                        ],
                        [
                            36, 185, 251, 18, 0, 209, 244, 100, 160, 214, 74, 239, 69, 47, 106, 43,
                        ],
                        [
                            28, 154, 187, 3, 136, 89, 4, 73, 187, 118, 134, 212, 66, 197, 220, 186,
                        ],
                        [
                            30, 232, 60, 163, 208, 76, 214, 120, 230, 175, 219, 78, 242, 79, 234,
                            223,
                        ],
                        [
                            246, 208, 164, 107, 216, 220, 96, 44, 207, 51, 146, 223, 120, 163, 115,
                            169,
                        ],
                        [
                            186, 56, 113, 220, 202, 48, 198, 9, 149, 149, 75, 230, 89, 83, 76, 19,
                        ],
                        [
                            72, 82, 211, 153, 175, 140, 114, 216, 194, 208, 17, 190, 4, 88, 104,
                            193,
                        ],
                        [
                            210, 44, 38, 31, 100, 220, 26, 97, 93, 107, 220, 48, 251, 184, 63, 239,
                        ],
                        [
                            192, 227, 127, 71, 76, 232, 30, 15, 46, 205, 198, 70, 179, 239, 246, 79,
                        ],
                        [
                            97, 14, 248, 26, 15, 217, 250, 211, 131, 202, 193, 66, 147, 192, 109,
                            117,
                        ],
                        [
                            58, 93, 19, 139, 124, 63, 135, 130, 205, 151, 246, 184, 238, 98, 92,
                            251,
                        ],
                        [
                            195, 41, 182, 143, 152, 133, 34, 22, 229, 134, 99, 178, 53, 233, 44,
                            155,
                        ],
                        [
                            64, 15, 144, 193, 236, 116, 82, 111, 237, 184, 244, 160, 1, 145, 83,
                            104,
                        ],
                        [
                            252, 196, 116, 72, 214, 153, 111, 49, 37, 92, 165, 166, 31, 160, 133,
                            108,
                        ],
                        [
                            233, 195, 21, 100, 207, 150, 25, 95, 244, 6, 87, 40, 245, 162, 180, 223,
                        ],
                        [
                            36, 240, 16, 5, 194, 244, 115, 194, 167, 109, 30, 45, 50, 1, 65, 109,
                        ],
                        [
                            72, 100, 253, 123, 115, 163, 72, 248, 193, 129, 138, 94, 252, 251, 0,
                            75,
                        ],
                        [
                            36, 74, 153, 88, 128, 132, 63, 104, 49, 151, 23, 133, 221, 154, 138, 70,
                        ],
                        [
                            37, 78, 230, 221, 117, 9, 20, 25, 96, 8, 28, 231, 19, 22, 14, 34,
                        ],
                        [
                            50, 201, 96, 72, 2, 224, 24, 65, 158, 51, 224, 72, 78, 69, 72, 134,
                        ],
                        [
                            221, 119, 99, 71, 164, 111, 133, 75, 189, 79, 241, 27, 246, 58, 113,
                            101,
                        ],
                        [
                            27, 165, 51, 97, 127, 136, 50, 23, 72, 83, 58, 157, 53, 12, 21, 145,
                        ],
                        [
                            42, 169, 79, 150, 24, 175, 158, 46, 154, 49, 1, 46, 122, 223, 215, 154,
                        ],
                        [
                            166, 10, 4, 245, 232, 150, 190, 255, 226, 55, 106, 85, 87, 218, 251, 83,
                        ],
                        [
                            184, 29, 119, 114, 221, 142, 220, 70, 197, 56, 88, 224, 29, 208, 199, 1,
                        ],
                        [
                            68, 94, 8, 227, 211, 232, 76, 176, 125, 117, 52, 50, 162, 87, 161, 67,
                        ],
                        [
                            175, 244, 98, 251, 51, 230, 18, 120, 151, 185, 239, 34, 159, 243, 140,
                            0,
                        ],
                        [
                            244, 190, 249, 214, 248, 39, 104, 32, 134, 12, 36, 3, 101, 97, 73, 228,
                        ],
                        [
                            110, 62, 161, 188, 231, 151, 183, 79, 49, 218, 225, 24, 30, 168, 42, 73,
                        ],
                        [
                            155, 170, 201, 6, 36, 229, 174, 31, 1, 251, 231, 58, 94, 124, 116, 238,
                        ],
                        [
                            105, 118, 100, 51, 140, 210, 118, 109, 131, 29, 22, 4, 35, 161, 4, 151,
                        ],
                        [
                            175, 142, 62, 180, 221, 202, 72, 99, 36, 37, 174, 237, 168, 32, 70, 37,
                        ],
                        [
                            118, 88, 42, 141, 121, 78, 35, 173, 103, 245, 240, 99, 244, 161, 140,
                            18,
                        ],
                        [
                            248, 89, 172, 202, 176, 72, 115, 26, 146, 206, 153, 24, 111, 135, 59,
                            173,
                        ],
                        [
                            105, 104, 33, 180, 105, 220, 241, 47, 28, 109, 59, 153, 66, 185, 226,
                            188,
                        ],
                        [
                            86, 99, 31, 113, 206, 254, 41, 172, 252, 204, 241, 137, 185, 15, 214,
                            240,
                        ],
                        [
                            117, 95, 36, 36, 238, 83, 214, 230, 17, 91, 17, 103, 19, 171, 12, 82,
                        ],
                        [
                            90, 133, 72, 165, 210, 155, 236, 126, 49, 234, 152, 101, 93, 228, 9,
                            124,
                        ],
                        [
                            251, 218, 161, 121, 8, 24, 196, 139, 249, 152, 16, 108, 16, 71, 142, 18,
                        ],
                        [
                            171, 63, 110, 215, 190, 212, 39, 225, 204, 149, 64, 206, 60, 109, 162,
                            85,
                        ],
                        [
                            10, 171, 175, 93, 75, 190, 134, 192, 5, 153, 180, 127, 47, 20, 185, 179,
                        ],
                        [
                            122, 172, 47, 44, 99, 7, 144, 169, 95, 65, 249, 13, 152, 158, 201, 25,
                        ],
                        [
                            202, 133, 230, 224, 252, 144, 115, 55, 26, 156, 3, 173, 29, 165, 37,
                            206,
                        ],
                        [
                            9, 120, 141, 185, 77, 82, 191, 158, 37, 154, 20, 161, 73, 60, 17, 44,
                        ],
                        [
                            74, 24, 185, 209, 133, 185, 219, 94, 111, 1, 26, 115, 237, 88, 96, 241,
                        ],
                        [
                            159, 181, 118, 223, 193, 125, 41, 87, 152, 168, 110, 199, 10, 236, 73,
                            218,
                        ],
                        [
                            127, 40, 167, 128, 245, 134, 75, 88, 110, 101, 126, 152, 249, 225, 158,
                            206,
                        ],
                        [
                            17, 151, 253, 49, 66, 28, 215, 179, 72, 62, 118, 203, 191, 115, 130,
                            224,
                        ],
                        [
                            237, 62, 219, 219, 156, 61, 124, 174, 10, 123, 35, 60, 88, 245, 4, 10,
                        ],
                        [
                            12, 127, 144, 182, 240, 247, 119, 5, 224, 135, 160, 34, 139, 222, 174,
                            39,
                        ],
                        [
                            192, 112, 146, 124, 16, 9, 255, 25, 84, 47, 118, 176, 129, 47, 115, 3,
                        ],
                        [
                            11, 141, 229, 11, 165, 232, 225, 0, 57, 212, 71, 119, 219, 118, 160, 14,
                        ],
                        [
                            254, 11, 30, 18, 3, 29, 168, 229, 231, 162, 156, 222, 133, 164, 74, 217,
                        ],
                        [
                            38, 173, 15, 169, 196, 206, 216, 234, 129, 135, 183, 243, 51, 185, 135,
                            21,
                        ],
                        [
                            164, 82, 133, 235, 163, 178, 30, 67, 207, 86, 152, 7, 191, 33, 41, 214,
                        ],
                        [
                            61, 25, 125, 149, 34, 157, 217, 157, 197, 225, 56, 32, 206, 198, 97, 79,
                        ],
                        [
                            26, 213, 23, 107, 78, 251, 106, 74, 227, 251, 198, 222, 168, 72, 186,
                            188,
                        ],
                        [
                            235, 69, 125, 20, 238, 123, 191, 230, 218, 208, 144, 95, 237, 61, 50,
                            116,
                        ],
                        [
                            22, 228, 206, 51, 247, 88, 107, 181, 21, 171, 87, 34, 247, 146, 230,
                            236,
                        ],
                        [
                            172, 16, 217, 12, 116, 229, 243, 66, 193, 126, 159, 50, 198, 74, 158,
                            142,
                        ],
                        [
                            19, 73, 99, 180, 119, 147, 150, 143, 126, 35, 248, 97, 196, 159, 249,
                            191,
                        ],
                        [
                            209, 241, 219, 66, 155, 164, 53, 206, 169, 149, 61, 150, 113, 199, 61,
                            175,
                        ],
                        [
                            199, 31, 136, 100, 227, 53, 246, 135, 6, 34, 59, 224, 149, 225, 30, 158,
                        ],
                        [
                            216, 87, 99, 189, 109, 38, 129, 42, 155, 102, 162, 52, 92, 106, 135,
                            179,
                        ],
                        [
                            140, 230, 20, 4, 36, 227, 12, 120, 60, 188, 178, 189, 21, 198, 188, 52,
                        ],
                        [
                            202, 153, 8, 153, 156, 56, 224, 30, 12, 248, 77, 216, 208, 172, 168,
                            225,
                        ],
                        [
                            194, 121, 225, 134, 34, 212, 194, 212, 244, 1, 240, 180, 65, 169, 9,
                            213,
                        ],
                        [
                            69, 186, 162, 232, 179, 126, 148, 59, 146, 214, 199, 83, 32, 243, 224,
                            217,
                        ],
                        [
                            125, 215, 150, 53, 97, 9, 157, 74, 234, 23, 114, 131, 224, 97, 153, 92,
                        ],
                        [
                            82, 181, 61, 30, 136, 167, 117, 187, 232, 91, 240, 245, 212, 14, 246,
                            26,
                        ],
                        [
                            146, 7, 203, 173, 141, 26, 96, 141, 184, 11, 254, 186, 94, 80, 52, 139,
                        ],
                        [
                            142, 121, 189, 33, 207, 155, 51, 2, 117, 5, 5, 71, 82, 192, 237, 251,
                        ],
                        [
                            181, 152, 101, 237, 138, 209, 228, 253, 199, 11, 202, 227, 1, 126, 253,
                            136,
                        ],
                        [
                            217, 30, 10, 247, 203, 165, 86, 79, 214, 9, 162, 150, 94, 4, 156, 36,
                        ],
                        [
                            176, 107, 158, 33, 110, 203, 237, 129, 245, 208, 69, 223, 126, 45, 103,
                            146,
                        ],
                        [
                            141, 194, 173, 161, 96, 59, 76, 77, 250, 13, 83, 219, 166, 70, 131, 91,
                        ],
                        [
                            201, 132, 212, 112, 22, 2, 46, 210, 34, 159, 211, 64, 23, 58, 81, 148,
                        ],
                        [
                            75, 102, 7, 139, 71, 241, 242, 113, 131, 45, 83, 103, 242, 188, 75, 180,
                        ],
                        [
                            16, 196, 238, 252, 220, 61, 149, 173, 159, 117, 148, 73, 31, 225, 28,
                            37,
                        ],
                        [
                            66, 112, 141, 184, 149, 108, 158, 197, 51, 146, 192, 38, 120, 90, 127,
                            25,
                        ],
                        [
                            97, 225, 214, 120, 73, 118, 174, 61, 102, 229, 196, 105, 221, 29, 186,
                            110,
                        ],
                        [
                            76, 161, 48, 35, 169, 42, 129, 12, 207, 216, 109, 36, 49, 233, 188, 255,
                        ],
                        [
                            72, 193, 234, 127, 84, 215, 33, 95, 187, 128, 9, 42, 135, 57, 37, 110,
                        ],
                        [
                            54, 156, 29, 232, 109, 220, 45, 28, 113, 114, 25, 131, 244, 250, 122,
                            219,
                        ],
                        [
                            224, 128, 139, 36, 225, 26, 239, 1, 29, 188, 54, 180, 234, 72, 97, 124,
                        ],
                        [
                            204, 134, 33, 202, 47, 207, 120, 213, 181, 8, 179, 78, 184, 34, 155,
                            121,
                        ],
                        [
                            81, 109, 151, 76, 95, 238, 2, 98, 251, 32, 156, 82, 169, 159, 15, 127,
                        ],
                        [
                            60, 134, 147, 99, 63, 210, 106, 116, 173, 207, 72, 8, 125, 196, 4, 218,
                        ],
                        [
                            254, 35, 103, 204, 169, 89, 237, 235, 200, 203, 209, 114, 197, 229,
                            165, 176,
                        ],
                        [
                            211, 209, 211, 198, 45, 145, 111, 49, 18, 184, 109, 110, 254, 174, 113,
                            233,
                        ],
                        [
                            160, 74, 163, 32, 77, 88, 94, 192, 142, 224, 251, 13, 225, 131, 212, 92,
                        ],
                        [
                            117, 125, 252, 67, 135, 8, 18, 8, 132, 193, 20, 127, 173, 168, 4, 36,
                        ],
                        [
                            164, 107, 35, 51, 50, 42, 1, 59, 201, 223, 156, 79, 91, 193, 109, 187,
                        ],
                        [
                            140, 85, 171, 47, 9, 61, 196, 183, 38, 30, 148, 41, 123, 211, 207, 162,
                        ],
                        [
                            49, 9, 130, 72, 34, 120, 109, 171, 110, 21, 225, 189, 157, 164, 203,
                            185,
                        ],
                        [
                            98, 59, 215, 153, 62, 186, 116, 128, 236, 33, 237, 141, 58, 251, 223,
                            147,
                        ],
                        [
                            148, 77, 39, 113, 135, 73, 53, 164, 105, 97, 142, 174, 26, 246, 77, 232,
                        ],
                        [
                            182, 5, 17, 255, 126, 139, 10, 93, 143, 162, 47, 89, 33, 126, 64, 92,
                        ],
                        [
                            71, 234, 103, 77, 223, 119, 156, 1, 83, 234, 154, 51, 29, 24, 248, 16,
                        ],
                        [
                            223, 141, 148, 26, 246, 26, 225, 196, 92, 250, 86, 26, 135, 158, 61, 6,
                        ],
                        [
                            194, 188, 82, 233, 40, 203, 239, 29, 252, 205, 14, 234, 254, 92, 76,
                            131,
                        ],
                        [
                            121, 205, 54, 170, 26, 101, 230, 43, 24, 30, 199, 154, 103, 32, 107, 92,
                        ],
                        [
                            1, 230, 40, 1, 134, 132, 55, 123, 47, 29, 226, 226, 95, 119, 204, 146,
                        ],
                        [
                            244, 135, 93, 54, 127, 96, 12, 164, 222, 31, 134, 40, 89, 25, 3, 126,
                        ],
                        [
                            99, 25, 198, 103, 6, 98, 247, 193, 102, 81, 11, 246, 99, 188, 244, 154,
                        ],
                        [
                            238, 231, 65, 10, 96, 44, 206, 65, 148, 86, 15, 119, 145, 39, 107, 214,
                        ],
                        [
                            68, 171, 108, 200, 50, 103, 41, 78, 244, 197, 166, 69, 241, 168, 38,
                            169,
                        ],
                        [
                            133, 50, 250, 80, 15, 35, 120, 236, 69, 235, 63, 150, 25, 115, 234, 210,
                        ],
                        [
                            247, 41, 152, 87, 2, 97, 19, 242, 255, 99, 161, 90, 175, 57, 208, 113,
                        ],
                        [
                            7, 224, 97, 62, 109, 74, 218, 32, 127, 150, 37, 75, 0, 78, 67, 170,
                        ],
                        [
                            90, 167, 113, 119, 67, 43, 213, 65, 72, 152, 168, 238, 203, 234, 46,
                            255,
                        ],
                        [
                            74, 229, 56, 42, 220, 168, 21, 172, 128, 238, 78, 242, 195, 69, 87, 208,
                        ],
                        [
                            124, 187, 136, 15, 136, 228, 20, 84, 44, 77, 121, 70, 83, 208, 74, 137,
                        ],
                        [
                            227, 201, 199, 61, 91, 209, 232, 104, 107, 66, 211, 207, 107, 5, 104,
                            33,
                        ],
                        [
                            65, 117, 97, 214, 244, 110, 244, 223, 40, 9, 115, 177, 104, 49, 242,
                            175,
                        ],
                        [
                            248, 154, 53, 114, 14, 192, 65, 236, 189, 24, 5, 171, 28, 226, 53, 130,
                        ],
                        [
                            14, 118, 192, 19, 33, 157, 105, 137, 103, 63, 213, 121, 130, 27, 102,
                            214,
                        ],
                        [
                            182, 178, 50, 7, 155, 131, 74, 226, 113, 19, 180, 9, 134, 192, 133, 107,
                        ],
                        [
                            5, 55, 2, 109, 167, 118, 158, 244, 187, 196, 90, 239, 109, 120, 39, 245,
                        ],
                        [
                            214, 218, 16, 230, 33, 90, 136, 179, 183, 148, 138, 90, 92, 96, 186, 33,
                        ],
                        [
                            239, 191, 251, 54, 103, 10, 30, 210, 7, 192, 48, 225, 219, 166, 93, 144,
                        ],
                        [
                            110, 30, 183, 142, 224, 132, 110, 228, 55, 41, 219, 78, 165, 51, 42,
                            133,
                        ],
                        [
                            186, 36, 124, 130, 0, 96, 44, 235, 38, 255, 144, 148, 12, 95, 236, 69,
                        ],
                        [
                            115, 130, 149, 177, 47, 159, 157, 56, 201, 99, 174, 229, 134, 47, 126,
                            51,
                        ],
                        [
                            81, 50, 54, 167, 156, 134, 246, 105, 133, 191, 107, 187, 6, 59, 98, 71,
                        ],
                        [
                            77, 56, 145, 143, 9, 74, 180, 101, 238, 146, 206, 67, 129, 83, 80, 245,
                        ],
                        [
                            239, 175, 88, 159, 44, 80, 6, 22, 156, 238, 72, 150, 26, 43, 155, 231,
                        ],
                        [
                            39, 251, 117, 253, 52, 2, 57, 207, 245, 108, 97, 236, 74, 241, 254, 159,
                        ],
                        [
                            9, 195, 210, 16, 179, 163, 175, 26, 215, 191, 100, 27, 60, 63, 73, 34,
                        ],
                        [
                            47, 95, 38, 168, 104, 251, 177, 161, 61, 100, 234, 16, 239, 28, 28, 95,
                        ],
                        [
                            12, 8, 127, 73, 191, 87, 18, 209, 21, 77, 8, 91, 178, 126, 18, 106,
                        ],
                        [
                            146, 104, 60, 8, 213, 122, 191, 50, 249, 123, 210, 155, 116, 232, 235,
                            231,
                        ],
                        [
                            154, 40, 142, 248, 37, 231, 94, 132, 205, 186, 71, 26, 178, 255, 74, 20,
                        ],
                        [
                            44, 198, 130, 21, 119, 6, 68, 15, 40, 126, 0, 226, 210, 229, 182, 149,
                        ],
                        [
                            179, 201, 170, 1, 15, 4, 134, 191, 48, 236, 93, 26, 219, 220, 230, 19,
                        ],
                        [
                            47, 35, 169, 87, 92, 36, 99, 122, 39, 27, 58, 77, 168, 21, 117, 87,
                        ],
                        [
                            47, 121, 186, 90, 239, 178, 245, 212, 178, 158, 117, 82, 175, 162, 61,
                            65,
                        ],
                        [
                            223, 66, 190, 247, 196, 198, 236, 137, 189, 59, 213, 177, 44, 56, 98,
                            74,
                        ],
                        [
                            187, 141, 210, 171, 203, 10, 52, 145, 171, 241, 189, 40, 102, 82, 75,
                            133,
                        ],
                        [
                            205, 164, 220, 30, 207, 89, 64, 219, 29, 107, 84, 176, 63, 238, 101, 75,
                        ],
                        [
                            172, 212, 195, 111, 15, 94, 210, 2, 169, 228, 69, 162, 126, 20, 150, 74,
                        ],
                        [
                            3, 227, 4, 46, 79, 5, 77, 13, 117, 192, 154, 24, 110, 146, 240, 9,
                        ],
                        [
                            159, 62, 125, 239, 177, 143, 250, 232, 1, 75, 134, 218, 56, 50, 12, 188,
                        ],
                        [
                            80, 146, 233, 120, 195, 130, 60, 104, 221, 155, 226, 232, 110, 30, 156,
                            247,
                        ],
                        [
                            103, 153, 66, 162, 249, 253, 168, 246, 43, 150, 190, 159, 44, 250, 1,
                            151,
                        ],
                        [
                            96, 122, 181, 133, 179, 67, 207, 94, 101, 153, 175, 98, 117, 62, 93,
                            208,
                        ],
                        [
                            209, 19, 5, 44, 54, 178, 58, 27, 84, 212, 227, 63, 146, 98, 213, 61,
                        ],
                        [
                            56, 63, 167, 148, 32, 30, 104, 226, 150, 240, 40, 147, 179, 153, 155,
                            200,
                        ],
                        [
                            100, 42, 118, 48, 182, 186, 244, 105, 11, 59, 10, 18, 238, 20, 227, 50,
                        ],
                        [
                            223, 20, 104, 78, 223, 118, 173, 190, 167, 171, 172, 186, 26, 240, 253,
                            81,
                        ],
                        [
                            214, 85, 242, 251, 85, 98, 128, 91, 158, 49, 196, 29, 188, 18, 106, 158,
                        ],
                        [
                            152, 145, 45, 214, 135, 249, 134, 30, 16, 136, 248, 13, 135, 200, 31,
                            175,
                        ],
                        [
                            101, 109, 160, 166, 151, 114, 92, 37, 170, 106, 31, 129, 47, 93, 111,
                            218,
                        ],
                        [
                            241, 85, 13, 183, 27, 43, 183, 8, 4, 128, 112, 4, 228, 75, 108, 51,
                        ],
                        [
                            172, 123, 239, 182, 55, 234, 199, 48, 22, 127, 178, 28, 235, 64, 102,
                            57,
                        ],
                        [
                            11, 67, 30, 14, 29, 238, 37, 240, 103, 30, 12, 24, 44, 109, 42, 202,
                        ],
                        [
                            29, 14, 102, 66, 82, 123, 32, 172, 138, 21, 218, 27, 119, 156, 2, 246,
                        ],
                        [
                            232, 6, 169, 192, 207, 136, 76, 129, 16, 61, 66, 153, 78, 10, 132, 54,
                        ],
                        [
                            185, 238, 15, 233, 54, 172, 149, 224, 32, 155, 41, 4, 242, 217, 132,
                            154,
                        ],
                        [
                            12, 1, 253, 21, 4, 183, 253, 236, 89, 46, 92, 223, 125, 179, 141, 32,
                        ],
                        [
                            233, 120, 167, 242, 238, 60, 210, 43, 192, 12, 40, 91, 182, 235, 176,
                            131,
                        ],
                        [
                            253, 209, 73, 33, 240, 172, 236, 168, 108, 70, 107, 131, 15, 237, 194,
                            229,
                        ],
                        [
                            35, 140, 92, 66, 134, 244, 131, 228, 177, 199, 93, 69, 156, 78, 203, 28,
                        ],
                        [
                            89, 247, 62, 222, 95, 129, 90, 70, 159, 226, 171, 59, 170, 190, 23, 134,
                        ],
                        [
                            93, 59, 38, 110, 25, 162, 162, 93, 205, 62, 183, 83, 17, 105, 179, 253,
                        ],
                        [
                            149, 8, 192, 4, 109, 14, 164, 10, 41, 183, 1, 240, 116, 184, 193, 118,
                        ],
                        [
                            144, 204, 5, 227, 178, 165, 28, 245, 190, 131, 29, 138, 212, 207, 87,
                            65,
                        ],
                        [
                            9, 242, 41, 169, 30, 68, 201, 238, 50, 224, 17, 61, 100, 13, 13, 44,
                        ],
                        [
                            226, 18, 142, 22, 2, 46, 21, 219, 152, 254, 77, 151, 170, 37, 187, 183,
                        ],
                        [
                            54, 21, 62, 219, 112, 8, 91, 6, 183, 45, 120, 248, 3, 15, 225, 210,
                        ],
                        [
                            36, 188, 202, 236, 62, 177, 250, 107, 92, 11, 36, 80, 243, 37, 192, 241,
                        ],
                        [
                            58, 88, 119, 17, 129, 57, 75, 16, 145, 213, 134, 240, 98, 128, 35, 164,
                        ],
                        [
                            70, 105, 13, 182, 191, 143, 126, 165, 128, 52, 125, 208, 70, 181, 59,
                            254,
                        ],
                        [
                            93, 210, 172, 31, 76, 70, 227, 82, 144, 87, 241, 4, 223, 28, 71, 197,
                        ],
                        [
                            180, 30, 198, 96, 84, 165, 198, 146, 107, 163, 17, 118, 220, 126, 223,
                            248,
                        ],
                        [
                            204, 148, 42, 130, 188, 65, 241, 138, 147, 185, 123, 78, 99, 132, 31,
                            106,
                        ],
                        [
                            170, 149, 163, 158, 164, 245, 131, 177, 226, 126, 186, 74, 226, 17,
                            137, 251,
                        ],
                        [
                            155, 159, 98, 159, 54, 115, 190, 46, 64, 200, 81, 224, 203, 248, 54, 15,
                        ],
                        [
                            192, 203, 145, 184, 113, 131, 51, 207, 45, 88, 104, 251, 75, 176, 24,
                            15,
                        ],
                        [
                            127, 127, 137, 133, 38, 159, 34, 244, 184, 159, 63, 246, 182, 150, 26,
                            146,
                        ],
                        [
                            244, 207, 200, 97, 32, 60, 57, 143, 117, 0, 127, 52, 224, 158, 22, 88,
                        ],
                        [
                            73, 205, 210, 26, 151, 20, 17, 49, 179, 206, 151, 159, 209, 203, 135,
                            106,
                        ],
                        [
                            193, 135, 168, 90, 50, 86, 135, 32, 142, 252, 214, 35, 20, 212, 228,
                            246,
                        ],
                        [
                            13, 14, 121, 82, 55, 6, 112, 196, 198, 52, 79, 202, 58, 136, 224, 14,
                        ],
                        [
                            8, 24, 221, 49, 225, 224, 24, 69, 19, 229, 7, 39, 195, 142, 151, 143,
                        ],
                        [
                            94, 0, 142, 191, 218, 107, 10, 169, 96, 27, 252, 108, 194, 169, 39, 100,
                        ],
                        [
                            161, 170, 240, 250, 170, 227, 69, 222, 126, 43, 202, 70, 101, 80, 240,
                            231,
                        ],
                        [
                            131, 232, 6, 225, 239, 219, 7, 43, 1, 114, 194, 147, 177, 11, 1, 137,
                        ],
                        [
                            142, 200, 200, 111, 174, 131, 147, 61, 217, 248, 10, 30, 9, 106, 49, 83,
                        ],
                        [
                            235, 16, 163, 177, 177, 151, 79, 115, 34, 231, 10, 225, 6, 195, 36, 52,
                        ],
                        [
                            40, 126, 171, 250, 87, 233, 196, 240, 96, 131, 231, 109, 45, 252, 5, 11,
                        ],
                        [
                            235, 243, 242, 121, 53, 250, 229, 88, 95, 238, 159, 231, 109, 130, 118,
                            112,
                        ],
                        [
                            84, 153, 168, 169, 144, 106, 30, 94, 89, 134, 246, 158, 51, 120, 184,
                            217,
                        ],
                        [
                            143, 204, 48, 119, 24, 121, 231, 42, 12, 204, 65, 36, 176, 134, 200, 65,
                        ],
                        [
                            228, 245, 22, 29, 44, 34, 152, 151, 219, 139, 154, 21, 205, 107, 125,
                            226,
                        ],
                        [
                            255, 163, 154, 40, 41, 15, 25, 62, 114, 127, 42, 102, 129, 135, 4, 1,
                        ],
                        [
                            252, 220, 64, 161, 86, 8, 241, 107, 250, 40, 202, 17, 212, 10, 64, 117,
                        ],
                        [
                            254, 144, 222, 214, 35, 4, 197, 207, 198, 222, 123, 150, 179, 230, 196,
                            176,
                        ],
                        [
                            209, 60, 85, 229, 184, 14, 144, 197, 208, 72, 162, 112, 111, 108, 31,
                            195,
                        ],
                        [
                            69, 209, 247, 162, 153, 165, 246, 54, 129, 118, 199, 208, 46, 48, 223,
                            91,
                        ],
                        [
                            236, 146, 153, 103, 95, 76, 22, 196, 177, 123, 254, 174, 84, 176, 204,
                            98,
                        ],
                        [
                            71, 212, 153, 88, 192, 155, 176, 151, 50, 182, 184, 80, 84, 244, 241,
                            147,
                        ],
                        [
                            123, 21, 109, 130, 179, 158, 175, 87, 67, 193, 70, 150, 136, 164, 215,
                            10,
                        ],
                        [
                            124, 153, 12, 64, 69, 205, 177, 156, 73, 209, 211, 153, 30, 142, 168,
                            58,
                        ],
                        [
                            215, 88, 139, 68, 220, 108, 97, 172, 25, 80, 27, 250, 77, 38, 172, 19,
                        ],
                        [
                            214, 198, 98, 91, 22, 44, 31, 65, 102, 30, 61, 95, 206, 136, 184, 127,
                        ],
                        [
                            57, 130, 221, 217, 163, 188, 149, 170, 51, 188, 242, 195, 242, 189, 22,
                            178,
                        ],
                        [
                            176, 227, 184, 241, 91, 240, 43, 31, 160, 70, 63, 159, 157, 234, 151,
                            66,
                        ],
                        [
                            171, 202, 208, 174, 168, 21, 210, 14, 91, 84, 240, 178, 114, 249, 115,
                            224,
                        ],
                        [
                            130, 12, 154, 164, 119, 67, 195, 78, 159, 26, 172, 114, 172, 113, 197,
                            79,
                        ],
                        [
                            118, 14, 50, 38, 71, 9, 220, 50, 234, 105, 199, 224, 252, 150, 139, 84,
                        ],
                        [
                            124, 150, 127, 84, 14, 171, 41, 36, 137, 139, 25, 7, 84, 33, 247, 111,
                        ],
                        [
                            175, 45, 0, 38, 251, 28, 255, 80, 62, 84, 3, 26, 126, 144, 215, 99,
                        ],
                        [
                            198, 124, 96, 240, 180, 138, 189, 184, 254, 18, 40, 125, 239, 255, 245,
                            233,
                        ],
                        [
                            228, 226, 117, 32, 232, 19, 11, 135, 21, 112, 6, 146, 203, 140, 64, 195,
                        ],
                        [
                            228, 103, 233, 173, 192, 106, 29, 202, 82, 110, 180, 67, 77, 90, 191,
                            20,
                        ],
                        [
                            34, 12, 164, 150, 213, 91, 27, 255, 77, 164, 123, 142, 203, 82, 138,
                            244,
                        ],
                        [
                            228, 236, 155, 124, 166, 43, 0, 140, 111, 24, 253, 203, 193, 107, 50,
                            186,
                        ],
                        [
                            61, 68, 3, 76, 172, 122, 241, 69, 173, 205, 173, 143, 194, 24, 37, 121,
                        ],
                        [
                            94, 166, 229, 134, 244, 53, 121, 208, 211, 17, 185, 71, 172, 241, 134,
                            240,
                        ],
                        [
                            147, 79, 0, 228, 110, 128, 82, 99, 27, 174, 175, 82, 210, 38, 174, 64,
                        ],
                        [
                            38, 104, 249, 76, 166, 83, 218, 193, 59, 80, 15, 217, 165, 46, 160, 186,
                        ],
                        [
                            147, 183, 89, 25, 40, 26, 44, 251, 27, 241, 183, 41, 13, 211, 68, 66,
                        ],
                        [
                            191, 20, 149, 113, 101, 9, 122, 161, 54, 27, 174, 41, 111, 240, 218,
                            162,
                        ],
                        [
                            19, 144, 124, 241, 189, 2, 84, 220, 212, 21, 95, 123, 121, 225, 134, 2,
                        ],
                        [
                            21, 241, 191, 45, 17, 169, 92, 234, 104, 185, 57, 168, 67, 138, 222,
                            139,
                        ],
                        [
                            194, 48, 207, 107, 186, 180, 219, 129, 152, 236, 133, 164, 180, 109,
                            56, 95,
                        ],
                        [
                            89, 48, 17, 234, 158, 143, 160, 190, 127, 182, 178, 211, 98, 222, 121,
                            41,
                        ],
                        [
                            190, 152, 166, 159, 142, 59, 150, 208, 245, 164, 67, 208, 219, 186,
                            185, 223,
                        ],
                        [
                            244, 205, 238, 201, 224, 60, 132, 1, 145, 106, 186, 190, 83, 2, 136,
                            115,
                        ],
                        [
                            234, 61, 94, 116, 37, 153, 230, 119, 41, 164, 211, 137, 248, 84, 50,
                            144,
                        ],
                        [
                            70, 50, 222, 69, 240, 122, 23, 73, 204, 237, 51, 88, 183, 248, 104, 109,
                        ],
                        [
                            98, 222, 52, 65, 114, 32, 147, 10, 57, 20, 43, 216, 87, 113, 37, 216,
                        ],
                        [
                            31, 230, 56, 187, 3, 64, 172, 243, 219, 205, 192, 118, 175, 86, 213,
                            199,
                        ],
                        [
                            185, 120, 9, 153, 197, 197, 221, 0, 164, 230, 27, 255, 112, 166, 109,
                            236,
                        ],
                        [
                            208, 148, 248, 170, 65, 209, 73, 191, 105, 162, 179, 240, 161, 28, 193,
                            86,
                        ],
                        [
                            10, 108, 38, 43, 199, 82, 65, 182, 187, 167, 156, 62, 9, 90, 251, 51,
                        ],
                        [
                            176, 124, 177, 104, 96, 27, 77, 90, 72, 32, 95, 85, 5, 205, 179, 166,
                        ],
                        [
                            209, 211, 190, 191, 134, 34, 38, 57, 222, 58, 208, 185, 220, 15, 83,
                            141,
                        ],
                        [
                            1, 229, 112, 245, 146, 123, 194, 187, 128, 252, 181, 87, 167, 63, 96,
                            219,
                        ],
                        [
                            207, 74, 49, 80, 56, 2, 94, 35, 225, 237, 165, 83, 60, 254, 88, 92,
                        ],
                        [
                            178, 92, 204, 105, 47, 247, 172, 31, 68, 47, 4, 30, 143, 42, 4, 157,
                        ],
                        [
                            22, 240, 113, 111, 96, 110, 232, 38, 127, 36, 41, 57, 174, 138, 81, 188,
                        ],
                        [
                            200, 235, 201, 206, 192, 44, 198, 26, 29, 1, 122, 67, 57, 95, 193, 178,
                        ],
                        [
                            218, 179, 178, 167, 129, 21, 125, 48, 213, 163, 141, 139, 5, 138, 153,
                            85,
                        ],
                        [
                            177, 81, 240, 166, 78, 69, 103, 191, 207, 72, 216, 80, 118, 14, 189,
                            197,
                        ],
                        [
                            36, 33, 140, 120, 215, 135, 175, 143, 173, 33, 246, 239, 125, 33, 211,
                            58,
                        ],
                        [
                            182, 0, 149, 2, 96, 116, 121, 90, 90, 226, 63, 233, 202, 32, 2, 43,
                        ],
                        [
                            16, 255, 81, 192, 184, 108, 225, 178, 8, 17, 192, 229, 234, 65, 241, 83,
                        ],
                        [
                            102, 36, 66, 162, 118, 174, 96, 243, 154, 48, 44, 208, 238, 120, 74,
                            136,
                        ],
                        [
                            121, 171, 99, 97, 178, 120, 211, 96, 22, 74, 71, 215, 64, 181, 136, 243,
                        ],
                        [
                            94, 150, 88, 7, 81, 188, 111, 59, 244, 191, 57, 161, 157, 154, 152, 91,
                        ],
                        [
                            207, 39, 235, 31, 175, 74, 87, 219, 151, 70, 168, 58, 75, 251, 217, 61,
                        ],
                        [
                            200, 67, 81, 180, 159, 255, 71, 103, 139, 201, 206, 187, 189, 71, 17,
                            34,
                        ],
                        [
                            85, 108, 72, 92, 176, 236, 181, 171, 37, 230, 204, 95, 136, 182, 223,
                            136,
                        ],
                        [
                            164, 211, 105, 19, 217, 236, 109, 159, 136, 107, 120, 42, 171, 167, 63,
                            50,
                        ],
                        [
                            231, 46, 166, 179, 200, 250, 178, 28, 247, 78, 165, 64, 206, 213, 24, 5,
                        ],
                        [
                            137, 172, 245, 243, 90, 140, 37, 219, 244, 125, 214, 100, 135, 30, 91,
                            12,
                        ],
                        [
                            0, 145, 131, 125, 100, 211, 2, 120, 117, 43, 174, 182, 5, 194, 46, 112,
                        ],
                        [
                            87, 10, 190, 219, 137, 79, 81, 97, 64, 153, 49, 230, 118, 194, 169, 142,
                        ],
                        [
                            149, 55, 224, 51, 91, 63, 58, 198, 146, 38, 148, 65, 232, 234, 61, 62,
                        ],
                        [
                            141, 157, 166, 205, 181, 170, 150, 43, 65, 99, 239, 20, 33, 216, 164,
                            217,
                        ],
                        [
                            241, 123, 127, 205, 250, 101, 8, 58, 228, 60, 168, 129, 168, 147, 59,
                            204,
                        ],
                        [
                            141, 91, 221, 22, 254, 214, 215, 117, 251, 79, 248, 157, 130, 69, 116,
                            54,
                        ],
                        [
                            92, 133, 200, 31, 105, 197, 71, 190, 161, 26, 97, 201, 123, 220, 121,
                            191,
                        ],
                        [
                            100, 137, 33, 37, 22, 132, 200, 59, 96, 145, 25, 157, 56, 37, 163, 144,
                        ],
                    ],
                );

                // tracing::info!("Asserts for dummy: {:?}", asserts);
                let bytes_digitwise_reversed_g16_output: [u8; 31] = g16_output
                    .iter()
                    .map(|&byte| {
                        let highu4 = byte >> 4;
                        let lowu4 = byte & 0x0F;
                        (lowu4 << 4) | highu4
                    })
                    .collect::<Vec<u8>>()
                    .try_into()
                    .expect("g16_output was not 31 bytes long, expected for digit-wise reversal");
                asserts.0[0][0] = 0;
                asserts.0[0][1..32].copy_from_slice(&bytes_digitwise_reversed_g16_output);
            } else {
                asserts = generate_assertions(
                    g16_proof,
                    vec![public_input_scalar],
                    &get_ark_verifying_key_dev_mode_bridge(),
                )
                .map_err(|e| eyre::eyre!("Failed to generate dev mode assertions: {}", e))?;
            }
        }

        #[cfg(not(test))]
        {
            asserts = generate_assertions(
                g16_proof,
                vec![public_input_scalar],
                &get_ark_verifying_key(),
            )
            .map_err(|e| eyre::eyre!("Failed to generate assertions: {}", e))?;
        };

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

    fn data(&self) -> OperatorData {
        OperatorData {
            xonly_pk: self.signer.xonly_public_key,
            collateral_funding_outpoint: self.collateral_funding_outpoint,
            reimburse_addr: self.reimburse_addr.clone(),
        }
    }

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

#[tonic::async_trait]
impl<C> Owner for Operator<C>
where
    C: CitreaClientT,
{
    const OWNER_TYPE: &'static str = "operator";
    async fn handle_duty(&self, duty: Duty) -> Result<DutyResult, BridgeError> {
        match duty {
            Duty::NewReadyToReimburse {
                round_idx,
                operator_xonly_pk,
                used_kickoffs,
            } => {
                tracing::info!("Operator {:?} called new ready to reimburse with round_idx: {}, operator_xonly_pk: {:?}, used_kickoffs: {:?}",
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
                    // add kickoff machine if there is a new kickoff
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
        let mut db_cache = ReimburseDbCache::from_context(self.db.clone(), &contract_context);
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
        tracing::info!("Operator called handle finalized block {}", _block_height);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::citrea::mock::MockCitreaClient;
    use crate::operator::Operator;
    use crate::test::common::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};

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
