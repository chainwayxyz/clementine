use crate::actor::{verify_schnorr, Actor, TweakCache, WinternitzDerivationPath};
use crate::bitcoin_syncer::BitcoinSyncer;
use crate::bitvm_client::{ClementineBitVMPublicKeys, REPLACE_SCRIPTS_LOCK};
use crate::builder::address::{create_taproot_address, taproot_builder_with_scripts};
use crate::builder::block_cache;
use crate::builder::script::{
    extract_winternitz_commits, extract_winternitz_commits_with_sigs, SpendableScript,
    TimelockScript, WinternitzCommit,
};
use crate::builder::sighash::{
    create_nofn_sighash_stream, create_operator_sighash_stream, PartialSignatureInfo, SignatureInfo,
};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::builder::transaction::{
    create_emergency_stop_txhandler, create_move_to_vault_txhandler,
    create_optimistic_payout_txhandler, TransactionType, TxHandler,
};
use crate::builder::transaction::{create_round_txhandlers, KickoffWinternitzKeys};
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::constants::{self, NON_EPHEMERAL_ANCHOR_AMOUNT, TEN_MINUTES_IN_SECS};
use crate::database::{Database, DatabaseTransaction};
use crate::deposit::{DepositData, KickoffData, OperatorData};
use crate::errors::{BridgeError, TxError};
use crate::extended_rpc::ExtendedRpc;
use crate::header_chain_prover::HeaderChainProver;
use crate::metrics::L1SyncStatusProvider;
use crate::operator::RoundIndex;
use crate::rpc::clementine::{EntityStatus, NormalSignatureKind, OperatorKeys, TaggedSignature};
use crate::task::entity_metric_publisher::{
    EntityMetricPublisher, ENTITY_METRIC_PUBLISHER_INTERVAL,
};
use crate::task::manager::BackgroundTaskManager;
use crate::task::{IntoTask, TaskExt};
#[cfg(feature = "automation")]
use crate::tx_sender::{TxSender, TxSenderClient};
use crate::utils::NamedEntity;
use crate::utils::TxMetadata;
use crate::{musig2, UTXO};
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, ScriptBuf, Witness, XOnlyPublicKey};
use bitcoin::{OutPoint, TxOut};
use bitcoin_script::builder::StructuredScript;
use bitvm::chunk::api::validate_assertions;
use bitvm::clementine::additional_disprove::{
    replace_placeholders_in_script, validate_assertions_for_additional_script,
};
use bitvm::signatures::winternitz;
#[cfg(feature = "automation")]
use circuits_lib::bridge_circuit::groth16::CircuitGroth16Proof;
use circuits_lib::bridge_circuit::transaction::CircuitTransaction;
use circuits_lib::bridge_circuit::{
    deposit_constant, get_first_op_return_output, parse_op_return_data,
};
use eyre::{Context, ContextCompat, OptionExt, Result};
use secp256k1::musig::{AggregatedNonce, PartialSignature, PublicNonce, SecretNonce};
#[cfg(feature = "automation")]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct NonceSession {
    /// Nonces used for a deposit session (last nonce is for the movetx signature)
    pub nonces: Vec<SecretNonce>,
}

#[derive(Debug)]
pub struct AllSessions {
    pub cur_id: u32,
    pub sessions: HashMap<u32, NonceSession>,
}

pub struct VerifierServer<C: CitreaClientT> {
    pub verifier: Verifier<C>,
    background_tasks: BackgroundTaskManager,
}

impl<C> VerifierServer<C>
where
    C: CitreaClientT,
{
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let verifier = Verifier::new(config.clone()).await?;
        let background_tasks = BackgroundTaskManager::default();

        Ok(VerifierServer {
            verifier,
            background_tasks,
        })
    }

    /// Starts the background tasks for the verifier.
    /// If called multiple times, it will restart only the tasks that are not already running.
    pub async fn start_background_tasks(&self) -> Result<(), BridgeError> {
        let rpc = ExtendedRpc::connect(
            self.verifier.config.bitcoin_rpc_url.clone(),
            self.verifier.config.bitcoin_rpc_user.clone(),
            self.verifier.config.bitcoin_rpc_password.clone(),
        )
        .await?;

        // initialize and run automation features
        #[cfg(feature = "automation")]
        {
            // TODO: Removing index causes to remove the index from the tx_sender handle as well
            let tx_sender = TxSender::new(
                self.verifier.signer.clone(),
                rpc.clone(),
                self.verifier.db.clone(),
                Verifier::<C>::TX_SENDER_CONSUMER_ID.to_string(),
                self.verifier.config.protocol_paramset(),
            );

            self.background_tasks
                .ensure_task_looping(tx_sender.into_task())
                .await;
            let state_manager = crate::states::StateManager::new(
                self.verifier.db.clone(),
                self.verifier.clone(),
                self.verifier.config.protocol_paramset(),
            )
            .await?;

            let should_run_state_mgr = {
                #[cfg(test)]
                {
                    self.verifier.config.test_params.should_run_state_manager
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
        #[cfg(not(feature = "automation"))]
        {
            use crate::metrics::get_btc_syncer_consumer_last_processed_block_height;
            use crate::task::TaskExt;
            // get current next height from the database
            // some blocks might still be processed again (if last processed block height is a reorged block)
            // processing same blocks again is not a problem, here we want to avoid starting from the beginning if verifier
            // has been restarted
            let last_processed_height = get_btc_syncer_consumer_last_processed_block_height(
                &self.verifier.db,
                &Verifier::<C>::FINALIZED_BLOCK_CONSUMER_ID.to_string(),
            )
            .await?;
            let next_height = match last_processed_height {
                // if last processed height is not None, start from the last processed height - finality depth + 1 as next height
                Some(height) => height
                    .checked_sub(self.verifier.config.protocol_paramset().finality_depth)
                    .map(|height| height + 1)
                    .unwrap_or(self.verifier.config.protocol_paramset().start_height),
                // if db is empty, start from the start height
                None => self.verifier.config.protocol_paramset().start_height,
            };

            self.background_tasks
                .ensure_task_looping(
                    crate::bitcoin_syncer::FinalizedBlockFetcherTask::new(
                        self.verifier.db.clone(),
                        Verifier::<C>::FINALIZED_BLOCK_CONSUMER_ID.to_string(),
                        self.verifier.config.protocol_paramset(),
                        next_height,
                        self.verifier.clone(),
                    )
                    .into_buffered_errors(50)
                    .with_delay(crate::bitcoin_syncer::BTC_SYNCER_POLL_DELAY),
                )
                .await;
        }

        let syncer = BitcoinSyncer::new(
            self.verifier.db.clone(),
            rpc.clone(),
            self.verifier.config.protocol_paramset(),
        )
        .await?;

        self.background_tasks
            .ensure_task_looping(syncer.into_task())
            .await;

        self.background_tasks
            .ensure_task_looping(
                EntityMetricPublisher::<Verifier<C>>::new(self.verifier.db.clone(), rpc.clone())
                    .with_delay(ENTITY_METRIC_PUBLISHER_INTERVAL),
            )
            .await;

        Ok(())
    }

    pub async fn get_current_status(&self) -> Result<EntityStatus, BridgeError> {
        let stopped_tasks = self.background_tasks.get_stopped_tasks().await?;
        // Determine if automation is enabled
        let automation_enabled = cfg!(feature = "automation");

        let l1_sync_status =
            Verifier::<C>::get_l1_status(&self.verifier.db, &self.verifier.rpc).await?;

        Ok(EntityStatus {
            automation: automation_enabled,
            wallet_balance: format!("{} BTC", l1_sync_status.wallet_balance.to_btc()),
            tx_sender_synced_height: l1_sync_status.tx_sender_synced_height.unwrap_or(0),
            finalized_synced_height: l1_sync_status.finalized_synced_height.unwrap_or(0),
            hcp_last_proven_height: l1_sync_status.hcp_last_proven_height.unwrap_or(0),
            rpc_tip_height: l1_sync_status.rpc_tip_height,
            bitcoin_syncer_synced_height: l1_sync_status.btc_syncer_synced_height.unwrap_or(0),
            stopped_tasks: Some(stopped_tasks),
            state_manager_next_height: l1_sync_status.state_manager_next_height.unwrap_or(0),
        })
    }

    pub async fn shutdown(&mut self) {
        self.background_tasks.graceful_shutdown().await;
    }
}

#[derive(Debug, Clone)]
pub struct Verifier<C: CitreaClientT> {
    rpc: ExtendedRpc,

    pub(crate) signer: Actor,
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,
    pub(crate) nonces: Arc<tokio::sync::Mutex<AllSessions>>,
    #[cfg(feature = "automation")]
    pub tx_sender: TxSenderClient,
    #[cfg(feature = "automation")]
    pub header_chain_prover: HeaderChainProver,
    pub citrea_client: C,
}

impl<C> Verifier<C>
where
    C: CitreaClientT,
{
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let db = Database::new(&config).await?;

        let citrea_client = C::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            None,
        )
        .await?;

        let all_sessions = AllSessions {
            cur_id: 0,
            sessions: HashMap::new(),
        };

        // TODO: Removing index causes to remove the index from the tx_sender handle as well
        #[cfg(feature = "automation")]
        let tx_sender = TxSenderClient::new(db.clone(), Self::TX_SENDER_CONSUMER_ID.to_string());

        #[cfg(feature = "automation")]
        let header_chain_prover = HeaderChainProver::new(&config, rpc.clone()).await?;

        let verifier = Verifier {
            rpc,
            signer,
            db: db.clone(),
            config: config.clone(),
            nonces: Arc::new(tokio::sync::Mutex::new(all_sessions)),
            #[cfg(feature = "automation")]
            tx_sender,
            #[cfg(feature = "automation")]
            header_chain_prover,
            citrea_client,
        };
        Ok(verifier)
    }

    /// Verifies all unspent kickoff signatures sent by the operator, converts them to TaggedSignature
    /// as they will be saved as TaggedSignatures to the db.
    fn verify_unspent_kickoff_sigs(
        &self,
        collateral_funding_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        wallet_reimburse_address: Address,
        unspent_kickoff_sigs: Vec<Signature>,
        kickoff_wpks: &KickoffWinternitzKeys,
    ) -> Result<Vec<TaggedSignature>, BridgeError> {
        let mut tweak_cache = TweakCache::default();
        let mut tagged_sigs = Vec::with_capacity(unspent_kickoff_sigs.len());
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            collateral_funding_outpoint,
            reimburse_addr: wallet_reimburse_address.clone(),
        };
        let mut cur_sig_index = 0;
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
                    for sighash in sighashes {
                        let message = Message::from_digest(sighash.0.to_byte_array());
                        verify_schnorr(
                            &unspent_kickoff_sigs[cur_sig_index],
                            &message,
                            operator_xonly_pk,
                            sighash.1.tweak_data,
                            Some(&mut tweak_cache),
                        )
                        .map_err(|e| {
                            eyre::eyre!(
                                "Verifier{}: Unspent kickoff signature verification failed for num sig {}: {}",
                                self.signer.xonly_public_key.to_string(),
                                cur_sig_index + 1,
                                e
                            )
                        })?;
                        tagged_sigs.push(TaggedSignature {
                            signature: unspent_kickoff_sigs[cur_sig_index].serialize().to_vec(),
                            signature_id: Some(sighash.1.signature_id),
                        });
                        cur_sig_index += 1;
                    }
                } else if let TransactionType::ReadyToReimburse = txhandler.get_transaction_type() {
                    prev_ready_to_reimburse = Some(txhandler);
                }
            }
        }

        Ok(tagged_sigs)
    }

    /// Checks if all operators in verifier's db that are still in protocol are in the deposit.
    /// Afterwards, it checks if the given deposit outpoint is valid. First it checks if the tx exists on chain,
    /// then it checks if the amount in TxOut is equal to bridge_amount and if the script is correct.
    ///
    /// # Arguments
    /// * `deposit_data` - The deposit data to check.
    ///
    /// # Returns
    /// * `true` if the deposit is valid, `false` otherwise.
    async fn is_deposit_valid(&self, deposit_data: &mut DepositData) -> Result<bool, BridgeError> {
        // check if security council is the same as in our config
        if deposit_data.security_council != self.config.security_council {
            tracing::error!(
                "Security council in deposit is not the same as in the config, expected {:?}, got {:?}",
                self.config.security_council,
                deposit_data.security_council
            );
            return Ok(false);
        }
        let operators_in_deposit = deposit_data.get_operators();
        // check if all operators that still have collateral are in the deposit
        let operators_in_db = self.db.get_operators(None).await?;
        for (xonly_pk, reimburse_addr, collateral_funding_outpoint) in operators_in_db.iter() {
            let operator_data = OperatorData {
                xonly_pk: *xonly_pk,
                collateral_funding_outpoint: *collateral_funding_outpoint,
                reimburse_addr: reimburse_addr.clone(),
            };
            let kickoff_winternitz_pks = self
                .db
                .get_operator_kickoff_winternitz_public_keys(None, *xonly_pk)
                .await?;
            let kickoff_wpks = KickoffWinternitzKeys::new(
                kickoff_winternitz_pks,
                self.config.protocol_paramset().num_kickoffs_per_round,
                self.config.protocol_paramset().num_round_txs,
            );
            let is_collateral_usable = self
                .rpc
                .collateral_check(
                    &operator_data,
                    &kickoff_wpks,
                    self.config.protocol_paramset(),
                )
                .await?;
            // if operator is not in deposit but its collateral is still on chain, return false
            if !operators_in_deposit.contains(xonly_pk) && is_collateral_usable {
                tracing::error!(
                    "Operator {:?} is is still in protocol but not in the deposit",
                    xonly_pk
                );
                return Ok(false);
            }
            // if operator is in deposit, but the collateral is not usable, return false
            if operators_in_deposit.contains(xonly_pk) && !is_collateral_usable {
                tracing::error!(
                    "Operator {:?} is in the deposit but its collateral is spent, operator cannot fulfill withdrawals anymore",
                    xonly_pk
                );
                return Ok(false);
            }
        }
        // check if there are any operators in the deposit that are not in the DB.
        for operator_xonly_pk in operators_in_deposit {
            if !operators_in_db
                .iter()
                .any(|(xonly_pk, _, _)| xonly_pk == &operator_xonly_pk)
            {
                tracing::error!(
                    "Operator {:?} is in the deposit but not in the DB, cannot sign deposit",
                    operator_xonly_pk
                );
                return Ok(false);
            }
        }
        // check if deposit script in deposit_outpoint is valid
        let deposit_scripts: Vec<ScriptBuf> = deposit_data
            .get_deposit_scripts(self.config.protocol_paramset())?
            .into_iter()
            .map(|s| s.to_script_buf())
            .collect();
        // what the deposit scriptpubkey is in the deposit_outpoint should be according to the deposit data
        let expected_scriptpubkey = create_taproot_address(
            &deposit_scripts,
            None,
            self.config.protocol_paramset().network,
        )
        .0
        .script_pubkey();
        let deposit_outpoint = deposit_data.get_deposit_outpoint();
        let deposit_txid = deposit_outpoint.txid;
        let deposit_tx = self
            .rpc
            .get_tx_of_txid(&deposit_txid)
            .await
            .wrap_err("Deposit tx could not be found on chain")?;
        let deposit_txout_in_chain = deposit_tx
            .output
            .get(deposit_outpoint.vout as usize)
            .ok_or(eyre::eyre!(
                "Deposit vout not found in tx {}, vout: {}",
                deposit_txid,
                deposit_outpoint.vout
            ))?;
        if deposit_txout_in_chain.value != self.config.protocol_paramset().bridge_amount {
            tracing::error!(
                "Deposit amount is not correct, expected {}, got {}",
                self.config.protocol_paramset().bridge_amount,
                deposit_txout_in_chain.value
            );
            return Ok(false);
        }
        if deposit_txout_in_chain.script_pubkey != expected_scriptpubkey {
            tracing::error!(
                "Deposit script pubkey in deposit outpoint does not match the deposit data, expected {:?}, got {:?}",
                expected_scriptpubkey,
                deposit_txout_in_chain.script_pubkey
            );
            return Ok(false);
        }
        Ok(true)
    }

    pub async fn set_operator(
        &self,
        collateral_funding_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        wallet_reimburse_address: Address,
        operator_winternitz_public_keys: Vec<winternitz::PublicKey>,
        unspent_kickoff_sigs: Vec<Signature>,
    ) -> Result<(), BridgeError> {
        tracing::info!("Setting operator: {:?}", operator_xonly_pk);
        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            collateral_funding_outpoint,
            reimburse_addr: wallet_reimburse_address,
        };

        let kickoff_wpks = KickoffWinternitzKeys::new(
            operator_winternitz_public_keys,
            self.config.protocol_paramset().num_kickoffs_per_round,
            self.config.protocol_paramset().num_round_txs,
        );

        if !self
            .rpc
            .collateral_check(
                &operator_data,
                &kickoff_wpks,
                self.config.protocol_paramset(),
            )
            .await?
        {
            return Err(eyre::eyre!(
                "Collateral utxo of operator {:?} does not exist or is not usable in bitcoin, cannot set operator",
                operator_xonly_pk,
            )
            .into());
        }

        let tagged_sigs = self.verify_unspent_kickoff_sigs(
            collateral_funding_outpoint,
            operator_xonly_pk,
            operator_data.reimburse_addr.clone(),
            unspent_kickoff_sigs,
            &kickoff_wpks,
        )?;

        let operator_winternitz_public_keys = kickoff_wpks.keys;
        let mut dbtx = self.db.begin_transaction().await?;
        // Save the operator details to the db
        self.db
            .set_operator(
                Some(&mut dbtx),
                operator_xonly_pk,
                &operator_data.reimburse_addr,
                collateral_funding_outpoint,
            )
            .await?;

        self.db
            .set_operator_kickoff_winternitz_public_keys(
                Some(&mut dbtx),
                operator_xonly_pk,
                operator_winternitz_public_keys,
            )
            .await?;

        let sigs_per_round = self.config.get_num_unspent_kickoff_sigs()
            / self.config.protocol_paramset().num_round_txs;
        let tagged_sigs_per_round: Vec<Vec<TaggedSignature>> = tagged_sigs
            .chunks(sigs_per_round)
            .map(|chunk| chunk.to_vec())
            .collect();

        for (round_idx, sigs) in tagged_sigs_per_round.into_iter().enumerate() {
            self.db
                .set_unspent_kickoff_sigs(
                    Some(&mut dbtx),
                    operator_xonly_pk,
                    RoundIndex::Round(round_idx),
                    sigs,
                )
                .await?;
        }

        #[cfg(feature = "automation")]
        {
            crate::states::StateManager::<Self>::dispatch_new_round_machine(
                self.db.clone(),
                &mut dbtx,
                operator_data,
            )
            .await?;
        }
        dbtx.commit().await?;
        tracing::info!("Operator: {:?} set successfully", operator_xonly_pk);
        Ok(())
    }

    pub async fn nonce_gen(&self, num_nonces: u32) -> Result<(u32, Vec<PublicNonce>), BridgeError> {
        let (sec_nonces, pub_nonces): (Vec<SecretNonce>, Vec<PublicNonce>) = (0..num_nonces)
            .map(|_| {
                // nonce pair needs keypair and a rng
                let (sec_nonce, pub_nonce) = musig2::nonce_pair(&self.signer.keypair)?;
                Ok((sec_nonce, pub_nonce))
            })
            .collect::<Result<Vec<(SecretNonce, PublicNonce)>, BridgeError>>()?
            .into_iter()
            .unzip(); // TODO: fix extra copies

        let session = NonceSession { nonces: sec_nonces };

        // save the session
        let session_id = {
            let all_sessions = &mut *self.nonces.lock().await;
            let session_id = all_sessions.cur_id;
            all_sessions.sessions.insert(session_id, session);
            all_sessions.cur_id += 1;
            session_id
        };

        Ok((session_id, pub_nonces))
    }

    pub async fn deposit_sign(
        &self,
        mut deposit_data: DepositData,
        session_id: u32,
        mut agg_nonce_rx: mpsc::Receiver<AggregatedNonce>,
    ) -> Result<mpsc::Receiver<PartialSignature>, BridgeError> {
        self.citrea_client
            .check_nofn_correctness(deposit_data.get_nofn_xonly_pk()?)
            .await?;

        if !self.is_deposit_valid(&mut deposit_data).await? {
            return Err(BridgeError::InvalidDeposit);
        }

        // set deposit data to db before starting to sign, ensures that if the deposit data already exists in db, it matches the one
        // given by the aggregator currently. We do not want to sign 2 different deposits for same deposit_outpoint
        self.db
            .set_deposit_data(None, &mut deposit_data, self.config.protocol_paramset())
            .await?;

        let verifier = self.clone();
        let (partial_sig_tx, partial_sig_rx) = mpsc::channel(constants::DEFAULT_CHANNEL_SIZE);
        let verifier_index = deposit_data.get_verifier_index(&self.signer.public_key)?;
        let verifiers_public_keys = deposit_data.get_verifiers();

        let deposit_blockhash = self
            .rpc
            .get_blockhash_of_tx(&deposit_data.get_deposit_outpoint().txid)
            .await?;

        tokio::spawn(async move {
            // Take the lock and extract the session before entering the async block
            // Extract the session and remove it from the map to release the lock early
            let mut session = {
                let mut session_map = verifier.nonces.lock().await;
                session_map
                    .sessions
                    .remove(&session_id)
                    .ok_or_else(|| eyre::eyre!("Could not find session id {session_id}"))?
            };
            session.nonces.reverse();

            let mut nonce_idx: usize = 0;

            let mut sighash_stream = Box::pin(create_nofn_sighash_stream(
                verifier.db.clone(),
                verifier.config.clone(),
                deposit_data.clone(),
                deposit_blockhash,
                false,
            ));
            let num_required_sigs = verifier.config.get_num_required_nofn_sigs(&deposit_data);

            assert_eq!(
                num_required_sigs + 2,
                session.nonces.len(),
                "Expected nonce count to be num_required_sigs + 2 (movetx & emergency stop)"
            );

            while let Some(agg_nonce) = agg_nonce_rx.recv().await {
                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or(eyre::eyre!("No sighash received"))??;
                tracing::debug!("Verifier {} found sighash: {:?}", verifier_index, sighash);

                let nonce = session
                    .nonces
                    .pop()
                    .ok_or(eyre::eyre!("No nonce available"))?;

                let partial_sig = musig2::partial_sign(
                    verifiers_public_keys.clone(),
                    None,
                    nonce,
                    agg_nonce,
                    verifier.signer.keypair,
                    Message::from_digest(*sighash.0.as_byte_array()),
                )?;

                partial_sig_tx
                    .send(partial_sig)
                    .await
                    .wrap_err("Failed to send partial signature")?;

                nonce_idx += 1;
                tracing::debug!(
                    "Verifier {} signed and sent sighash {} of {}",
                    verifier_index,
                    nonce_idx,
                    num_required_sigs
                );
                if nonce_idx == num_required_sigs {
                    break;
                }
            }

            if session.nonces.len() != 2 {
                return Err(eyre::eyre!(
                    "Expected 2 nonces remaining in session, one for move tx and one for emergency stop, got {}",
                    session.nonces.len()
                ).into());
            }

            let mut session_map = verifier.nonces.lock().await;
            session_map
                .sessions
                .insert(session_id, session)
                .ok_or_else(|| eyre::eyre!("Could not find session id {session_id}"))?;

            Ok::<(), BridgeError>(())
        });

        Ok(partial_sig_rx)
    }

    /// TODO: This function should be split in to multiple functions
    pub async fn deposit_finalize(
        &self,
        deposit_data: &mut DepositData,
        session_id: u32,
        mut sig_receiver: mpsc::Receiver<Signature>,
        mut agg_nonce_receiver: mpsc::Receiver<AggregatedNonce>,
        mut operator_sig_receiver: mpsc::Receiver<Signature>,
    ) -> Result<(PartialSignature, PartialSignature), BridgeError> {
        self.citrea_client
            .check_nofn_correctness(deposit_data.get_nofn_xonly_pk()?)
            .await?;

        if !self.is_deposit_valid(deposit_data).await? {
            return Err(BridgeError::InvalidDeposit);
        }

        let mut tweak_cache = TweakCache::default();
        let deposit_blockhash = self
            .rpc
            .get_blockhash_of_tx(&deposit_data.get_deposit_outpoint().txid)
            .await?;

        let mut sighash_stream = pin!(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            deposit_data.clone(),
            deposit_blockhash,
            true,
        ));

        let num_required_nofn_sigs = self.config.get_num_required_nofn_sigs(deposit_data);
        let num_required_nofn_sigs_per_kickoff = self
            .config
            .get_num_required_nofn_sigs_per_kickoff(deposit_data);
        let num_required_op_sigs = self.config.get_num_required_operator_sigs(deposit_data);
        let num_required_op_sigs_per_kickoff = self
            .config
            .get_num_required_operator_sigs_per_kickoff(deposit_data);

        let operator_xonly_pks = deposit_data.get_operators();
        let num_operators = deposit_data.get_num_operators();

        let ProtocolParamset {
            num_round_txs,
            num_kickoffs_per_round,
            ..
        } = *self.config.protocol_paramset();

        let mut verified_sigs = vec![
            vec![
                vec![
                    Vec::<TaggedSignature>::with_capacity(
                        num_required_nofn_sigs_per_kickoff + num_required_op_sigs_per_kickoff
                    );
                    num_kickoffs_per_round
                ];
                num_round_txs + 1
            ];
            num_operators
        ];

        let mut kickoff_txids = vec![vec![vec![]; num_round_txs + 1]; num_operators];

        // ------ N-of-N SIGNATURES VERIFICATION ------

        let mut nonce_idx: usize = 0;

        while let Some(sighash) = sighash_stream.next().await {
            let typed_sighash = sighash.wrap_err("Failed to read from sighash stream")?;

            let &SignatureInfo {
                operator_idx,
                round_idx,
                kickoff_utxo_idx,
                signature_id,
                tweak_data,
                kickoff_txid,
            } = &typed_sighash.1;

            if signature_id == NormalSignatureKind::YieldKickoffTxid.into() {
                kickoff_txids[operator_idx][round_idx.to_index()]
                    .push((kickoff_txid, kickoff_utxo_idx));
                continue;
            }

            let sig = sig_receiver
                .recv()
                .await
                .ok_or_eyre("No signature received")?;

            tracing::debug!("Verifying Final nofn Signature {}", nonce_idx + 1);

            verify_schnorr(
                &sig,
                &Message::from(typed_sighash.0),
                deposit_data.get_nofn_xonly_pk()?,
                tweak_data,
                Some(&mut tweak_cache),
            )
            .wrap_err_with(|| {
                format!(
                    "Failed to verify nofn signature {} with signature info {:?}",
                    nonce_idx + 1,
                    typed_sighash.1
                )
            })?;

            let tagged_sig = TaggedSignature {
                signature: sig.serialize().to_vec(),
                signature_id: Some(signature_id),
            };
            verified_sigs[operator_idx][round_idx.to_index()][kickoff_utxo_idx].push(tagged_sig);

            tracing::debug!("Final Signature Verified");

            nonce_idx += 1;
        }

        if nonce_idx != num_required_nofn_sigs {
            return Err(eyre::eyre!(
                "Did not receive enough nofn signatures. Needed: {}, received: {}",
                num_required_nofn_sigs,
                nonce_idx
            )
            .into());
        }

        tracing::info!(
            "Verifier{} Finished verifying final signatures of NofN",
            self.signer.xonly_public_key.to_string()
        );

        let move_tx_agg_nonce = agg_nonce_receiver
            .recv()
            .await
            .ok_or(eyre::eyre!("Aggregated nonces channel ended prematurely"))?;

        let emergency_stop_agg_nonce = agg_nonce_receiver
            .recv()
            .await
            .ok_or(eyre::eyre!("Aggregated nonces channel ended prematurely"))?;

        tracing::info!(
            "Verifier{} Received move tx and emergency stop aggregated nonces",
            self.signer.xonly_public_key.to_string()
        );
        // ------ OPERATOR SIGNATURES VERIFICATION ------

        let num_required_total_op_sigs = num_required_op_sigs * deposit_data.get_num_operators();
        let mut total_op_sig_count = 0;

        // get operator data
        let operators_data = deposit_data.get_operators();

        // get signatures of operators and verify them
        for (operator_idx, &op_xonly_pk) in operators_data.iter().enumerate() {
            let mut op_sig_count = 0;
            // generate the sighash stream for operator
            let mut sighash_stream = pin!(create_operator_sighash_stream(
                self.db.clone(),
                op_xonly_pk,
                self.config.clone(),
                deposit_data.clone(),
                deposit_blockhash,
            ));
            while let Some(operator_sig) = operator_sig_receiver.recv().await {
                let typed_sighash = sighash_stream
                    .next()
                    .await
                    .ok_or_eyre("Operator sighash stream ended prematurely")??;

                tracing::debug!(
                    "Verifying Final operator signature {} for operator {}, signature info {:?}",
                    nonce_idx + 1,
                    operator_idx,
                    typed_sighash.1
                );

                let &SignatureInfo {
                    operator_idx,
                    round_idx,
                    kickoff_utxo_idx,
                    signature_id,
                    kickoff_txid: _,
                    tweak_data,
                } = &typed_sighash.1;

                verify_schnorr(
                    &operator_sig,
                    &Message::from(typed_sighash.0),
                    op_xonly_pk,
                    tweak_data,
                    Some(&mut tweak_cache),
                )
                .wrap_err_with(|| {
                    format!(
                        "Operator {} Signature {}: verification failed. Signature info: {:?}.",
                        operator_idx,
                        op_sig_count + 1,
                        typed_sighash.1
                    )
                })?;

                let tagged_sig = TaggedSignature {
                    signature: operator_sig.serialize().to_vec(),
                    signature_id: Some(signature_id),
                };
                verified_sigs[operator_idx][round_idx.to_index()][kickoff_utxo_idx]
                    .push(tagged_sig);

                op_sig_count += 1;
                total_op_sig_count += 1;
                if op_sig_count == num_required_op_sigs {
                    break;
                }
            }
        }

        if total_op_sig_count != num_required_total_op_sigs {
            return Err(eyre::eyre!(
                "Did not receive enough operator signatures. Needed: {}, received: {}",
                num_required_total_op_sigs,
                total_op_sig_count
            )
            .into());
        }

        tracing::info!(
            "Verifier{} Finished verifying final signatures of operators",
            self.signer.xonly_public_key.to_string()
        );
        // ----- MOVE TX SIGNING

        // Generate partial signature for move transaction
        let move_txhandler =
            create_move_to_vault_txhandler(deposit_data, self.config.protocol_paramset())?;

        let move_tx_sighash = move_txhandler.calculate_script_spend_sighash_indexed(
            0,
            0,
            bitcoin::TapSighashType::Default,
        )?;

        let movetx_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| eyre::eyre!("Could not find session id {session_id}"))?;
            session
                .nonces
                .pop()
                .ok_or_eyre("No move tx secnonce in session")?
        };

        let emergency_stop_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| eyre::eyre!("Could not find session id {session_id}"))?;
            session
                .nonces
                .pop()
                .ok_or_eyre("No emergency stop secnonce in session")?
        };

        // sign move tx and save everything to db if everything is correct
        let move_tx_partial_sig = musig2::partial_sign(
            deposit_data.get_verifiers(),
            None,
            movetx_secnonce,
            move_tx_agg_nonce,
            self.signer.keypair,
            Message::from_digest(move_tx_sighash.to_byte_array()),
        )?;

        tracing::info!(
            "Verifier{} Finished signing move tx",
            self.signer.xonly_public_key.to_string()
        );

        let emergency_stop_txhandler = create_emergency_stop_txhandler(
            deposit_data,
            &move_txhandler,
            self.config.protocol_paramset(),
        )?;

        let emergency_stop_sighash = emergency_stop_txhandler
            .calculate_script_spend_sighash_indexed(
                0,
                0,
                bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
            )?;

        let emergency_stop_partial_sig = musig2::partial_sign(
            deposit_data.get_verifiers(),
            None,
            emergency_stop_secnonce,
            emergency_stop_agg_nonce,
            self.signer.keypair,
            Message::from_digest(emergency_stop_sighash.to_byte_array()),
        )?;

        tracing::info!(
            "Verifier{} Finished signing emergency stop tx",
            self.signer.xonly_public_key.to_string()
        );

        // Save signatures to db
        let mut dbtx = self.db.begin_transaction().await?;
        // Deposit is not actually finalized here, its only finalized after the aggregator gets all the partial sigs and checks the aggregated sig
        // TODO: It can create problems if the deposit fails at the end by some verifier not sending movetx partial sig, but we still added sigs to db
        for (operator_idx, (operator_xonly_pk, operator_sigs)) in operator_xonly_pks
            .into_iter()
            .zip(verified_sigs.into_iter())
            .enumerate()
        {
            // skip indexes until round 0 (currently 0th index corresponds to collateral, which doesn't have any sigs)
            for (round_idx, mut op_round_sigs) in operator_sigs
                .into_iter()
                .enumerate()
                .skip(RoundIndex::Round(0).to_index())
            {
                if kickoff_txids[operator_idx][round_idx].len()
                    != self.config.protocol_paramset().num_signed_kickoffs
                {
                    return Err(eyre::eyre!(
                        "Number of signed kickoff utxos for operator: {}, round: {} is wrong. Expected: {}, got: {}",
                                operator_xonly_pk, round_idx, self.config.protocol_paramset().num_signed_kickoffs, kickoff_txids[operator_idx][round_idx].len()
                    ).into());
                }
                for (kickoff_txid, kickoff_idx) in &kickoff_txids[operator_idx][round_idx] {
                    if kickoff_txid.is_none() {
                        return Err(eyre::eyre!(
                            "Kickoff txid not found for {}, {}, {}",
                            operator_xonly_pk,
                            round_idx, // rounds start from 1
                            kickoff_idx
                        )
                        .into());
                    }

                    tracing::trace!(
                        "Setting deposit signatures for {:?}, {:?}, {:?} {:?}",
                        operator_xonly_pk,
                        round_idx, // rounds start from 1
                        kickoff_idx,
                        kickoff_txid
                    );

                    self.db
                        .set_deposit_signatures(
                            Some(&mut dbtx),
                            deposit_data.get_deposit_outpoint(),
                            operator_xonly_pk,
                            RoundIndex::from_index(round_idx),
                            *kickoff_idx,
                            kickoff_txid.expect("Kickoff txid must be Some"),
                            std::mem::take(&mut op_round_sigs[*kickoff_idx]),
                        )
                        .await?;
                }
            }
        }
        dbtx.commit().await?;

        Ok((move_tx_partial_sig, emergency_stop_partial_sig))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_optimistic_payout(
        &self,
        nonce_session_id: u32,
        agg_nonce: AggregatedNonce,
        deposit_id: u32,
        input_signature: Signature,
        input_outpoint: OutPoint,
        output_script_pubkey: ScriptBuf,
        output_amount: Amount,
    ) -> Result<PartialSignature, BridgeError> {
        // check if withdrawal is valid first
        let move_txid = self
            .db
            .get_move_to_vault_txid_from_citrea_deposit(None, deposit_id)
            .await?;
        if move_txid.is_none() {
            return Err(eyre::eyre!("Deposit not found for id: {}", deposit_id).into());
        }

        // amount in move_tx is exactly the bridge amount
        if output_amount
            > self.config.protocol_paramset().bridge_amount - NON_EPHEMERAL_ANCHOR_AMOUNT
        {
            return Err(eyre::eyre!(
                "Output amount is greater than the bridge amount: {} > {}",
                output_amount,
                self.config.protocol_paramset().bridge_amount
                    - self.config.protocol_paramset().anchor_amount()
                    - NON_EPHEMERAL_ANCHOR_AMOUNT
            )
            .into());
        }

        // check if withdrawal utxo is correct
        let withdrawal_utxo = self
            .db
            .get_withdrawal_utxo_from_citrea_withdrawal(None, deposit_id)
            .await?;
        if withdrawal_utxo != input_outpoint {
            return Err(eyre::eyre!(
                "Withdrawal utxo is not correct: {:?} != {:?}",
                withdrawal_utxo,
                input_outpoint
            )
            .into());
        }

        let move_txid = move_txid.expect("Withdrawal must be Some");
        let mut deposit_data = self
            .db
            .get_deposit_data_with_move_tx(None, move_txid)
            .await?
            .ok_or_eyre("Deposit data corresponding to move txid not found")?;

        let withdrawal_prevout = self.rpc.get_txout_from_outpoint(&input_outpoint).await?;
        let withdrawal_utxo = UTXO {
            outpoint: input_outpoint,
            txout: withdrawal_prevout,
        };
        let output_txout = TxOut {
            value: output_amount,
            script_pubkey: output_script_pubkey,
        };

        let opt_payout_txhandler = create_optimistic_payout_txhandler(
            &mut deposit_data,
            withdrawal_utxo,
            output_txout,
            input_signature,
            self.config.protocol_paramset(),
        )?;
        // txin at index 1 is deposited utxo in movetx
        let sighash = opt_payout_txhandler.calculate_script_spend_sighash_indexed(
            1,
            0,
            bitcoin::TapSighashType::Default,
        )?;

        let opt_payout_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map
                .sessions
                .get_mut(&nonce_session_id)
                .ok_or_else(|| eyre::eyre!("Could not find session id {nonce_session_id}"))?;
            session
                .nonces
                .pop()
                .ok_or_eyre("No move tx secnonce in session")?
        };

        let opt_payout_partial_sig = musig2::partial_sign(
            deposit_data.get_verifiers(),
            None,
            opt_payout_secnonce,
            agg_nonce,
            self.signer.keypair,
            Message::from_digest(sighash.to_byte_array()),
        )?;

        Ok(opt_payout_partial_sig)
    }

    pub async fn set_operator_keys(
        &self,
        mut deposit_data: DepositData,
        keys: OperatorKeys,
        operator_xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        self.citrea_client
            .check_nofn_correctness(deposit_data.get_nofn_xonly_pk()?)
            .await?;

        if !self.is_deposit_valid(&mut deposit_data).await? {
            return Err(BridgeError::InvalidDeposit);
        }

        self.db
            .set_deposit_data(None, &mut deposit_data, self.config.protocol_paramset())
            .await?;

        let hashes: Vec<[u8; 20]> = keys
            .challenge_ack_digests
            .into_iter()
            .map(|x| {
                x.hash.try_into().map_err(|e: Vec<u8>| {
                    eyre::eyre!("Invalid hash length, expected 20 bytes, got {}", e.len())
                })
            })
            .collect::<Result<Vec<[u8; 20]>, eyre::Report>>()?;

        if hashes.len() != self.config.get_num_challenge_ack_hashes(&deposit_data) {
            return Err(eyre::eyre!(
                "Invalid number of challenge ack hashes received from operator {:?}: got: {} expected: {}",
                operator_xonly_pk,
                hashes.len(),
                self.config.get_num_challenge_ack_hashes(&deposit_data)
            ).into());
        }

        let operator_data = self
            .db
            .get_operator(None, operator_xonly_pk)
            .await?
            .ok_or(BridgeError::OperatorNotFound(operator_xonly_pk))?;

        self.db
            .set_operator_challenge_ack_hashes(
                None,
                operator_xonly_pk,
                deposit_data.get_deposit_outpoint(),
                &hashes,
            )
            .await?;

        let winternitz_keys: Vec<winternitz::PublicKey> = keys
            .winternitz_pubkeys
            .into_iter()
            .map(|x| x.try_into())
            .collect::<Result<_, BridgeError>>()?;

        if winternitz_keys.len() != ClementineBitVMPublicKeys::number_of_flattened_wpks() {
            tracing::error!(
                "Invalid number of winternitz keys received from operator {:?}: got: {} expected: {}",
                operator_xonly_pk,
                winternitz_keys.len(),
                ClementineBitVMPublicKeys::number_of_flattened_wpks()
            );
            return Err(eyre::eyre!(
                "Invalid number of winternitz keys received from operator {:?}: got: {} expected: {}",
                operator_xonly_pk,
                winternitz_keys.len(),
                ClementineBitVMPublicKeys::number_of_flattened_wpks()
            )
            .into());
        }

        let bitvm_pks = ClementineBitVMPublicKeys::from_flattened_vec(&winternitz_keys);

        let assert_tx_addrs = bitvm_pks
            .get_assert_taproot_leaf_hashes(operator_data.xonly_pk)
            .iter()
            .map(|x| x.to_byte_array())
            .collect::<Vec<_>>();

        // TODO: Use correct verification key and along with a dummy proof.
        // wrap around a mutex lock to avoid OOM
        let guard = REPLACE_SCRIPTS_LOCK.lock().await;
        let start = std::time::Instant::now();
        let scripts: Vec<ScriptBuf> = bitvm_pks.get_g16_verifier_disprove_scripts();

        let taproot_builder = taproot_builder_with_scripts(scripts);

        let root_hash = taproot_builder
            .try_into_taptree()
            .expect("taproot builder always builds a full taptree")
            .root_hash()
            .to_byte_array();

        // bitvm scripts are dropped, release the lock
        drop(guard);
        tracing::debug!("Built taproot tree in {:?}", start.elapsed());

        let latest_blockhash_wots = bitvm_pks.latest_blockhash_pk.to_vec();

        let latest_blockhash_script = WinternitzCommit::new(
            vec![(latest_blockhash_wots, 40)],
            operator_data.xonly_pk,
            self.config.protocol_paramset().winternitz_log_d,
        )
        .to_script_buf();

        let latest_blockhash_root_hash = taproot_builder_with_scripts(&[latest_blockhash_script])
            .try_into_taptree()
            .expect("taproot builder always builds a full taptree")
            .root_hash()
            .to_raw_hash()
            .to_byte_array();

        self.db
            .set_operator_bitvm_keys(
                None,
                operator_xonly_pk,
                deposit_data.get_deposit_outpoint(),
                bitvm_pks.to_flattened_vec(),
            )
            .await?;
        // Save the public input wots to db along with the root hash
        self.db
            .set_bitvm_setup(
                None,
                operator_xonly_pk,
                deposit_data.get_deposit_outpoint(),
                &assert_tx_addrs,
                &root_hash,
                &latest_blockhash_root_hash,
            )
            .await?;

        Ok(())
    }

    /// Checks if the operator who sent the kickoff matches the payout data saved in our db
    /// Payout data in db is updated during citrea sync.
    async fn is_kickoff_malicious(
        &self,
        kickoff_witness: Witness,
        deposit_data: &mut DepositData,
        kickoff_data: KickoffData,
    ) -> Result<bool, BridgeError> {
        let move_txid =
            create_move_to_vault_txhandler(deposit_data, self.config.protocol_paramset())?
                .get_cached_tx()
                .compute_txid();
        let payout_info = self
            .db
            .get_payout_info_from_move_txid(None, move_txid)
            .await;
        if let Err(e) = &payout_info {
            tracing::warn!(
                "Couldn't retrieve payout info from db {}, assuming malicious",
                e
            );
            return Ok(true);
        }
        let payout_info = payout_info?;
        let Some((operator_xonly_pk_opt, payout_blockhash, _, _)) = payout_info else {
            tracing::warn!("No payout info found in db, assuming malicious");
            return Ok(true);
        };

        let Some(operator_xonly_pk) = operator_xonly_pk_opt else {
            tracing::warn!("No operator xonly pk found in payout tx OP_RETURN, assuming malicious");
            return Ok(true);
        };

        if operator_xonly_pk != kickoff_data.operator_xonly_pk {
            tracing::warn!("Operator xonly pk for the payout does not match with the kickoff_data");
            return Ok(true);
        }

        let wt_derive_path = WinternitzDerivationPath::Kickoff(
            kickoff_data.round_idx,
            kickoff_data.kickoff_idx,
            self.config.protocol_paramset(),
        );
        let commits = extract_winternitz_commits(
            kickoff_witness,
            &[wt_derive_path],
            self.config.protocol_paramset(),
        )?;
        let blockhash_data = commits.first();
        // only last 20 bytes of the blockhash is committed
        let truncated_blockhash = &payout_blockhash[12..];
        if let Some(committed_blockhash) = blockhash_data {
            if committed_blockhash != truncated_blockhash {
                tracing::warn!("Payout blockhash does not match committed hash: committed: {:?}, truncated payout blockhash: {:?}",
                        blockhash_data, truncated_blockhash);
                return Ok(true);
            }
        } else {
            return Err(eyre::eyre!("Couldn't retrieve committed data from witness").into());
        }
        Ok(false)
    }

    /// Checks if the kickoff is malicious and sends the appropriate txs if it is.
    /// Returns true if the kickoff is malicious.
    pub async fn handle_kickoff<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        kickoff_witness: Witness,
        mut deposit_data: DepositData,
        kickoff_data: KickoffData,
        challenged_before: bool,
    ) -> Result<bool, BridgeError> {
        let is_malicious = self
            .is_kickoff_malicious(kickoff_witness, &mut deposit_data, kickoff_data)
            .await?;
        if !is_malicious {
            return Ok(false);
        }

        tracing::warn!(
            "Malicious kickoff {:?} for deposit {:?}",
            kickoff_data,
            deposit_data
        );

        let transaction_data = TransactionRequestData {
            deposit_outpoint: deposit_data.get_deposit_outpoint(),
            kickoff_data,
        };

        let signed_txs = create_and_sign_txs(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            transaction_data,
            None, // No need
        )
        .await?;

        let tx_metadata = Some(TxMetadata {
            tx_type: TransactionType::Dummy, // will be replaced in add_tx_to_queue
            operator_xonly_pk: Some(kickoff_data.operator_xonly_pk),
            round_idx: Some(kickoff_data.round_idx),
            kickoff_idx: Some(kickoff_data.kickoff_idx),
            deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
        });

        // try to send them
        for (tx_type, signed_tx) in &signed_txs {
            if *tx_type == TransactionType::Challenge && challenged_before {
                // do not send challenge tx operator was already challenged in the same round
                tracing::warn!(
                    "Operator {:?} was already challenged in the same round, skipping challenge tx",
                    kickoff_data.operator_xonly_pk
                );
                continue;
            }
            match *tx_type {
                TransactionType::Challenge
                | TransactionType::AssertTimeout(_)
                | TransactionType::KickoffNotFinalized
                | TransactionType::LatestBlockhashTimeout
                | TransactionType::OperatorChallengeNack(_) => {
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

        Ok(true)
    }

    #[cfg(feature = "automation")]
    async fn send_watchtower_challenge(
        &self,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
    ) -> Result<(), BridgeError> {
        let current_tip_hcp = self
            .header_chain_prover
            .get_tip_header_chain_proof()
            .await?;

        let (work_only_proof, work_output) = self
            .header_chain_prover
            .prove_work_only(current_tip_hcp.0)?;

        let g16: [u8; 256] = work_only_proof
            .inner
            .groth16()
            .wrap_err("Work only receipt is not groth16")?
            .seal
            .to_owned()
            .try_into()
            .map_err(|e: Vec<u8>| {
                eyre::eyre!(
                    "Invalid g16 proof length, expected 256 bytes, got {}",
                    e.len()
                )
            })?;

        let g16_proof = CircuitGroth16Proof::from_seal(&g16);
        let mut commit_data: Vec<u8> = g16_proof
            .to_compressed()
            .wrap_err("Couldn't compress g16 proof")?
            .to_vec();

        let total_work =
            borsh::to_vec(&work_output.work_u128).wrap_err("Couldn't serialize total work")?;

        #[cfg(test)]
        {
            let wt_ind = self
                .config
                .test_params
                .all_verifiers_secret_keys
                .iter()
                .position(|x| x == &self.config.secret_key)
                .ok_or_else(|| eyre::eyre!("Verifier secret key not found in test params"))?;

            self.config
                .test_params
                .maybe_disrupt_commit_data_for_total_work(&mut commit_data, wt_ind);
        }

        commit_data.extend_from_slice(&total_work);

        tracing::info!("Watchtower prepared commit data, trying to send watchtower challenge");

        self.queue_watchtower_challenge(kickoff_data, deposit_data, commit_data)
            .await
    }

    async fn queue_watchtower_challenge(
        &self,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        commit_data: Vec<u8>,
    ) -> Result<(), BridgeError> {
        let (tx_type, challenge_tx, rbf_info) = self
            .create_watchtower_challenge(
                TransactionRequestData {
                    deposit_outpoint: deposit_data.get_deposit_outpoint(),
                    kickoff_data,
                },
                &commit_data,
            )
            .await?;

        #[cfg(test)]
        let mut challenge_tx = challenge_tx;

        #[cfg(test)]
        {
            if let Some(annex_bytes) = rbf_info.annex.clone() {
                challenge_tx.input[0].witness.push(annex_bytes);
            }
        }

        #[cfg(feature = "automation")]
        {
            let mut dbtx = self.db.begin_transaction().await?;

            self.tx_sender
                .add_tx_to_queue(
                    &mut dbtx,
                    tx_type,
                    &challenge_tx,
                    &[],
                    Some(TxMetadata {
                        tx_type,
                        operator_xonly_pk: Some(kickoff_data.operator_xonly_pk),
                        round_idx: Some(kickoff_data.round_idx),
                        kickoff_idx: Some(kickoff_data.kickoff_idx),
                        deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                    }),
                    &self.config,
                    Some(rbf_info),
                )
                .await?;

            dbtx.commit().await?;
            tracing::info!(
                "Committed watchtower challenge, commit data: {:?}",
                commit_data
            );
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, dbtx))]
    async fn update_citrea_deposit_and_withdrawals(
        &self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
        l2_height_start: u64,
        l2_height_end: u64,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let last_deposit_idx = self.db.get_last_deposit_idx(None).await?;
        tracing::debug!("Last Citrea deposit idx: {:?}", last_deposit_idx);

        let last_withdrawal_idx = self.db.get_last_withdrawal_idx(None).await?;
        tracing::debug!("Last Citrea withdrawal idx: {:?}", last_withdrawal_idx);

        let new_deposits = self
            .citrea_client
            .collect_deposit_move_txids(last_deposit_idx, l2_height_end)
            .await?;
        tracing::debug!("New deposits received from Citrea: {:?}", new_deposits);

        let new_withdrawals = self
            .citrea_client
            .collect_withdrawal_utxos(last_withdrawal_idx, l2_height_end)
            .await?;
        tracing::debug!(
            "New withdrawals received from Citrea: {:?}",
            new_withdrawals
        );

        for (idx, move_to_vault_txid) in new_deposits {
            tracing::info!(
                "Saving move to vault txid {:?} with index {} for Citrea deposits",
                move_to_vault_txid,
                idx
            );
            self.db
                .set_move_to_vault_txid_from_citrea_deposit(
                    Some(dbtx),
                    idx as u32,
                    &move_to_vault_txid,
                )
                .await?;
        }

        for (idx, withdrawal_utxo_outpoint) in new_withdrawals {
            tracing::info!(
                "Saving withdrawal utxo {:?} with index {} for Citrea withdrawals",
                withdrawal_utxo_outpoint,
                idx
            );
            self.db
                .set_withdrawal_utxo_from_citrea_withdrawal(
                    Some(dbtx),
                    idx as u32,
                    withdrawal_utxo_outpoint,
                    block_height,
                )
                .await?;
        }

        let replacement_move_txids = self
            .citrea_client
            .get_replacement_deposit_move_txids(l2_height_start + 1, l2_height_end)
            .await?;

        for (idx, new_move_txid) in replacement_move_txids {
            tracing::info!(
                "Setting replacement move txid: {:?} -> {:?}",
                idx,
                new_move_txid
            );
            self.db
                .set_replacement_deposit_move_txid(dbtx, idx, new_move_txid)
                .await?;
        }

        Ok(())
    }

    async fn update_finalized_payouts(
        &self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
        block_id: u32,
        block_cache: &block_cache::BlockCache,
    ) -> Result<(), BridgeError> {
        let payout_txids = self
            .db
            .get_payout_txs_for_withdrawal_utxos(Some(dbtx), block_id)
            .await?;

        let block = block_cache
            .block
            .as_ref()
            .ok_or(eyre::eyre!("Block not found"))?;

        let block_hash = block.block_hash();

        let mut payout_txs_and_payer_operator_idx = vec![];
        for (idx, payout_txid) in payout_txids {
            let payout_tx_idx = block_cache.txids.get(&payout_txid);
            if payout_tx_idx.is_none() {
                tracing::error!(
                    "Payout tx not found in block cache: {:?} and in block: {:?}",
                    payout_txid,
                    block_id
                );
                tracing::error!("Block cache: {:?}", block_cache);
                return Err(eyre::eyre!("Payout tx not found in block cache").into());
            }
            let payout_tx_idx = payout_tx_idx.expect("Payout tx not found in block cache");
            let payout_tx = &block.txdata[*payout_tx_idx];
            // Find the first output that contains OP_RETURN
            let circuit_payout_tx = CircuitTransaction::from(payout_tx.clone());
            let op_return_output = get_first_op_return_output(&circuit_payout_tx);

            // If OP_RETURN doesn't exist in any outputs, or the data in OP_RETURN is not a valid xonly_pubkey,
            // operator_xonly_pk will be set to None, and the corresponding column in DB set to NULL.
            // This can happen if optimistic payout is used, or an operator constructs the payout tx wrong.
            let operator_xonly_pk = op_return_output
                .and_then(|output| parse_op_return_data(&output.script_pubkey))
                .and_then(|bytes| XOnlyPublicKey::from_slice(bytes).ok());

            if operator_xonly_pk.is_none() {
                tracing::info!(
                    "No valid operator xonly pk found in payout tx {:?} OP_RETURN. Either it is an optimistic payout or the operator constructed the payout tx wrong",
                    payout_txid
                );
            }

            tracing::info!(
                "A new payout tx detected for withdrawal {}, payout txid: {:?}, operator xonly pk: {:?}",
                idx,
                payout_txid,
                operator_xonly_pk
            );

            payout_txs_and_payer_operator_idx.push((
                idx,
                payout_txid,
                operator_xonly_pk,
                block_hash,
            ));
        }

        self.db
            .set_payout_txs_and_payer_operator_xonly_pk(
                Some(dbtx),
                payout_txs_and_payer_operator_idx,
            )
            .await?;

        Ok(())
    }

    async fn send_unspent_kickoff_connectors(
        &self,
        round_idx: RoundIndex,
        operator_xonly_pk: XOnlyPublicKey,
        used_kickoffs: HashSet<usize>,
    ) -> Result<(), BridgeError> {
        if used_kickoffs.len() == self.config.protocol_paramset().num_kickoffs_per_round {
            // ok, every kickoff spent
            return Ok(());
        }

        let unspent_kickoff_txs = self
            .create_and_sign_unspent_kickoff_connector_txs(round_idx, operator_xonly_pk)
            .await?;
        let mut dbtx = self.db.begin_transaction().await?;
        for (tx_type, tx) in unspent_kickoff_txs {
            if let TransactionType::UnspentKickoff(kickoff_idx) = tx_type {
                if used_kickoffs.contains(&kickoff_idx) {
                    continue;
                }
                #[cfg(feature = "automation")]
                self.tx_sender
                    .add_tx_to_queue(
                        &mut dbtx,
                        tx_type,
                        &tx,
                        &[],
                        Some(TxMetadata {
                            tx_type,
                            operator_xonly_pk: Some(operator_xonly_pk),
                            round_idx: Some(round_idx),
                            kickoff_idx: Some(kickoff_idx as u32),
                            deposit_outpoint: None,
                        }),
                        &self.config,
                        None,
                    )
                    .await?;
            }
        }
        dbtx.commit().await?;
        Ok(())
    }

    /// Verifies the conditions required to disprove an operator's actions using the "additional" disprove path.
    ///
    /// This function handles specific, non-Groth16 challenges. It reconstructs a unique challenge script
    /// based on on-chain data and constants (`deposit_constant`). It then validates the operator's
    /// provided assertions (`operator_asserts`) and acknowledgements (`operator_acks`) against this script.
    /// The goal is to produce a spendable witness for the disprove transaction if the operator is found to be at fault.
    ///
    /// # Arguments
    /// * `deposit_data` - Mutable data for the specific deposit being challenged.
    /// * `kickoff_data` - Information about the kickoff transaction that initiated this challenge.
    /// * `latest_blockhash` - The witness containing Winternitz signature for the latest Bitcoin blockhash.
    /// * `payout_blockhash` - The witness containing Winternitz signature for the payout transaction's blockhash.
    /// * `operator_asserts` - A map of witnesses from the operator, containing their assertions (claims).
    /// * `operator_acks` - A map of witnesses from the operator, containing their acknowledgements of watchtower challenges.
    /// * `txhandlers` - A map of transaction builders, used here to retrieve TXIDs of dependent transactions.
    ///
    /// # Returns
    /// - `Ok(Some(bitcoin::Witness))` if the operator's claims are successfully proven false, returning the complete witness needed to spend the disprove script path.
    /// - `Ok(None)` if the operator's claims are valid under this specific challenge, and no disprove is possible.
    /// - `Err(BridgeError)` if any error occurs during script reconstruction or validation.
    #[cfg(feature = "automation")]
    #[allow(clippy::too_many_arguments)]
    async fn verify_additional_disprove_conditions(
        &self,
        deposit_data: &mut DepositData,
        kickoff_data: &KickoffData,
        latest_blockhash: &Witness,
        payout_blockhash: &Witness,
        operator_asserts: &HashMap<usize, Witness>,
        operator_acks: &HashMap<usize, Witness>,
        txhandlers: &BTreeMap<TransactionType, TxHandler>,
    ) -> Result<Option<bitcoin::Witness>, BridgeError> {
        use bitvm::clementine::additional_disprove::debug_assertions_for_additional_script;

        use crate::builder::transaction::ReimburseDbCache;

        let mut reimburse_db_cache = ReimburseDbCache::new_for_deposit(
            self.db.clone(),
            kickoff_data.operator_xonly_pk,
            deposit_data.get_deposit_outpoint(),
            self.config.protocol_paramset(),
        );

        let nofn_key = deposit_data.get_nofn_xonly_pk().inspect_err(|e| {
            tracing::error!("Error getting nofn xonly pk: {:?}", e);
        })?;

        let move_txid = txhandlers
            .get(&TransactionType::MoveToVault)
            .ok_or(TxError::TxHandlerNotFound(TransactionType::MoveToVault))?
            .get_txid()
            .to_byte_array();

        let round_txid = txhandlers
            .get(&TransactionType::Round)
            .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?
            .get_txid()
            .to_byte_array();

        let vout = kickoff_data.kickoff_idx + 1;

        let watchtower_challenge_start_idx =
            u16::try_from(UtxoVout::WatchtowerChallenge(0).get_vout())
                .wrap_err("Watchtower challenge start index overflow")?;

        let secp = Secp256k1::verification_only();

        let watchtower_xonly_pk = deposit_data.get_watchtowers();
        let watchtower_pubkeys = watchtower_xonly_pk
            .iter()
            .map(|xonly_pk| {
                // Create timelock script that this watchtower key will commit to
                let nofn_2week = Arc::new(TimelockScript::new(
                    Some(nofn_key),
                    self.config
                        .protocol_paramset
                        .watchtower_challenge_timeout_timelock,
                ));

                let builder = TaprootBuilder::new();
                let tweaked = builder
                    .add_leaf(0, nofn_2week.to_script_buf())
                    .expect("Valid script leaf")
                    .finalize(&secp, *xonly_pk)
                    .expect("taproot finalize must succeed");

                tweaked.output_key().serialize()
            })
            .collect::<Vec<_>>();

        let deposit_constant = deposit_constant(
            kickoff_data.operator_xonly_pk.serialize(),
            watchtower_challenge_start_idx,
            &watchtower_pubkeys,
            move_txid,
            round_txid,
            vout,
            self.config.protocol_paramset.genesis_chain_state_hash,
        );

        tracing::debug!("Deposit constant: {:?}", deposit_constant);

        let kickoff_winternitz_keys = reimburse_db_cache
            .get_kickoff_winternitz_keys()
            .await?
            .clone();

        let payout_tx_blockhash_pk = kickoff_winternitz_keys
            .get_keys_for_round(kickoff_data.round_idx)?
            .get(kickoff_data.kickoff_idx as usize)
            .ok_or(TxError::IndexOverflow)?
            .clone();

        let replaceable_additional_disprove_script = reimburse_db_cache
            .get_replaceable_additional_disprove_script()
            .await?;

        let additional_disprove_script = replace_placeholders_in_script(
            replaceable_additional_disprove_script.clone(),
            payout_tx_blockhash_pk,
            deposit_constant.0,
        );

        let witness = operator_asserts
            .get(&0)
            .wrap_err("No witness found in operator asserts")?
            .clone();

        let deposit_outpoint = deposit_data.get_deposit_outpoint();
        let paramset = self.config.protocol_paramset();

        let commits = extract_winternitz_commits_with_sigs(
            witness,
            &ClementineBitVMPublicKeys::mini_assert_derivations_0(deposit_outpoint, paramset),
            self.config.protocol_paramset(),
        )?;

        let mut challenge_sending_watchtowers_signature = Witness::new();
        let len = commits.len();

        for elem in commits[len - 1].iter() {
            challenge_sending_watchtowers_signature.push(elem);
        }

        let mut g16_public_input_signature = Witness::new();

        for elem in commits[len - 2].iter() {
            g16_public_input_signature.push(elem);
        }

        let num_of_watchtowers = deposit_data.get_num_watchtowers();

        let mut operator_acks_vec: Vec<Option<[u8; 20]>> = vec![None; num_of_watchtowers];

        for (idx, witness) in operator_acks.iter() {
            tracing::debug!(
                "Processing operator ack for idx: {}, witness: {:?}",
                idx,
                witness
            );

            let pre_image: [u8; 20] = witness
                .nth(1)
                .wrap_err("No pre-image found in operator ack witness")?
                .try_into()
                .wrap_err("Invalid pre-image length, expected 20 bytes")?;
            if *idx >= operator_acks_vec.len() {
                return Err(eyre::eyre!(
                    "Operator ack index {} out of bounds for vec of length {}",
                    idx,
                    operator_acks_vec.len()
                )
                .into());
            }
            operator_acks_vec[*idx] = Some(pre_image);

            tracing::debug!(target: "ci", "Operator ack for idx {}", idx);
        }

        let latest_blockhash: Vec<Vec<u8>> = latest_blockhash
            .iter()
            .skip(1)
            .take(88)
            .map(|x| x.to_vec())
            .collect();

        let mut latest_blockhash_new = Witness::new();
        for element in latest_blockhash {
            latest_blockhash_new.push(element);
        }

        let payout_blockhash: Vec<Vec<u8>> = payout_blockhash
            .iter()
            .skip(1)
            .take(88)
            .map(|x| x.to_vec())
            .collect();

        let mut payout_blockhash_new = Witness::new();
        for element in payout_blockhash {
            payout_blockhash_new.push(element);
        }

        tracing::debug!(
            target: "ci",
            "Verify additional disprove conditions - Genesis height: {:?}, operator_xonly_pk: {:?}, move_txid: {:?}, round_txid: {:?}, vout: {:?}, watchtower_challenge_start_idx: {:?}, genesis_chain_state_hash: {:?}, deposit_constant: {:?}",
            self.config.protocol_paramset.genesis_height,
            kickoff_data.operator_xonly_pk,
            move_txid,
            round_txid,
            vout,
            watchtower_challenge_start_idx,
            self.config.protocol_paramset.genesis_chain_state_hash,
            deposit_constant
        );

        tracing::debug!(
            target: "ci",
            "Payout blockhash: {:?}\nLatest blockhash: {:?}\nChallenge sending watchtowers signature: {:?}\nG16 public input signature: {:?}",
            payout_blockhash_new,
            latest_blockhash_new,
            challenge_sending_watchtowers_signature,
            g16_public_input_signature
        );

        let additional_disprove_witness = validate_assertions_for_additional_script(
            additional_disprove_script.clone(),
            g16_public_input_signature.clone(),
            payout_blockhash_new.clone(),
            latest_blockhash_new.clone(),
            challenge_sending_watchtowers_signature.clone(),
            operator_acks_vec.clone(),
        );

        let debug_additional_disprove_script = debug_assertions_for_additional_script(
            additional_disprove_script.clone(),
            g16_public_input_signature.clone(),
            payout_blockhash_new.clone(),
            latest_blockhash_new.clone(),
            challenge_sending_watchtowers_signature.clone(),
            operator_acks_vec,
        );

        tracing::info!(
            "Debug additional disprove script: {:?}",
            debug_additional_disprove_script
        );

        tracing::info!(
            "Additional disprove witness: {:?}",
            additional_disprove_witness
        );

        Ok(additional_disprove_witness)
    }

    /// Constructs, signs, and broadcasts the "additional" disprove transaction.
    ///
    /// This function is called after `verify_additional_disprove_conditions` successfully returns a witness.
    /// It takes this witness, places it into the disprove transaction's script spend path, adds the required
    /// operator and verifier signatures, and broadcasts the finalized transaction to the Bitcoin network.
    ///
    /// # Arguments
    /// * `txhandlers` - A map containing the pre-built `Disprove` transaction handler.
    /// * `kickoff_data` - Contextual data from the kickoff transaction.
    /// * `deposit_data` - Contextual data for the deposit being challenged.
    /// * `additional_disprove_witness` - The witness generated by `verify_additional_disprove_conditions`, proving the operator's fault.
    ///
    /// # Returns
    /// - `Ok(())` on successful broadcast of the transaction.
    /// - `Err(BridgeError)` if signing or broadcasting fails.
    #[cfg(feature = "automation")]
    async fn send_disprove_tx_additional(
        &self,
        txhandlers: &BTreeMap<TransactionType, TxHandler>,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        additional_disprove_witness: Witness,
    ) -> Result<(), BridgeError> {
        let verifier_xonly_pk = self.signer.xonly_public_key;

        let mut disprove_txhandler = txhandlers
            .get(&TransactionType::Disprove)
            .wrap_err("Disprove txhandler not found in txhandlers")?
            .clone();

        let disprove_input = additional_disprove_witness
            .iter()
            .map(|x| x.to_vec())
            .collect::<Vec<_>>();

        disprove_txhandler
            .set_p2tr_script_spend_witness(&disprove_input, 0, 1)
            .inspect_err(|e| {
                tracing::error!("Error setting disprove input witness: {:?}", e);
            })?;

        let operators_sig = self
            .db
            .get_deposit_signatures(
                None,
                deposit_data.get_deposit_outpoint(),
                kickoff_data.operator_xonly_pk,
                kickoff_data.round_idx,
                kickoff_data.kickoff_idx as usize,
            )
            .await?
            .ok_or_eyre("No operator signature found for the disprove tx")?;

        let mut tweak_cache = TweakCache::default();

        self.signer
            .tx_sign_and_fill_sigs(
                &mut disprove_txhandler,
                operators_sig.as_ref(),
                Some(&mut tweak_cache),
            )
            .inspect_err(|e| {
                tracing::error!(
                    "Error signing disprove tx for verifier {:?}: {:?}",
                    verifier_xonly_pk,
                    e
                );
            })?;

        let disprove_tx = disprove_txhandler.get_cached_tx().clone();

        tracing::debug!("Disprove txid: {:?}", disprove_tx.compute_txid());

        tracing::warn!(
            "Additional disprove tx created for verifier {:?} with kickoff_data: {:?}, deposit_data: {:?}",
            verifier_xonly_pk,
            kickoff_data,
            deposit_data
        );

        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .add_tx_to_queue(
                &mut dbtx,
                TransactionType::Disprove,
                &disprove_tx,
                &[],
                Some(TxMetadata {
                    tx_type: TransactionType::Disprove,
                    deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                    operator_xonly_pk: Some(kickoff_data.operator_xonly_pk),
                    round_idx: Some(kickoff_data.round_idx),
                    kickoff_idx: Some(kickoff_data.kickoff_idx),
                }),
                &self.config,
                None,
            )
            .await?;
        dbtx.commit().await?;
        Ok(())
    }

    /// Performs the primary G16 proof verification to disprove an operator's claim.
    ///
    /// This is a complex function that aggregates all of the operator's assertions, which are commitments
    /// from a Winternitz one-time signature scheme. It meticulously parses and reorganizes these commitments
    /// into the precise input format required by the underlying Groth16 SNARK verifier (`validate_assertions`).
    /// It then invokes the verifier to check for a faulty computation.
    ///
    /// # Arguments
    /// * `deposit_data` - Mutable data for the specific deposit being challenged.
    /// * `operator_asserts` - A map containing all 33 required operator assertion witnesses.
    ///
    /// # Returns
    /// - `Ok(Some((index, script)))` if the ZK proof is faulty. The tuple contains the `StructuredScript`
    ///   that can be executed on-chain and its `index` in the Taproot tree.
    /// - `Ok(None)` if the ZK proof is valid.
    /// - `Err(BridgeError)` if any error occurs during data processing or ZK proof verification.
    #[cfg(feature = "automation")]
    async fn verify_disprove_conditions(
        &self,
        deposit_data: &mut DepositData,
        operator_asserts: &HashMap<usize, Witness>,
    ) -> Result<Option<(usize, StructuredScript)>, BridgeError> {
        use bridge_circuit_host::utils::get_verifying_key;

        let bitvm_pks = self.signer.generate_bitvm_pks_for_deposit(
            deposit_data.get_deposit_outpoint(),
            self.config.protocol_paramset,
        )?;
        let disprove_scripts = bitvm_pks.get_g16_verifier_disprove_scripts();

        let deposit_outpoint = deposit_data.get_deposit_outpoint();
        let paramset = self.config.protocol_paramset();

        // Pre-allocate commit vectors. Initializing with known sizes or empty vectors
        // is slightly more efficient as it can prevent reallocations.
        let mut g16_public_input_commit: Vec<Vec<Vec<u8>>> = vec![vec![vec![]]; 1];
        let mut num_u256_commits: Vec<Vec<Vec<u8>>> = vec![vec![vec![]]; 14];
        let mut intermediate_value_commits: Vec<Vec<Vec<u8>>> = vec![vec![vec![]]; 363];

        tracing::info!("Number of operator asserts: {}", operator_asserts.len());

        if operator_asserts.len() != ClementineBitVMPublicKeys::number_of_assert_txs() {
            return Err(eyre::eyre!(
                "Expected exactly {} operator asserts, got {}",
                ClementineBitVMPublicKeys::number_of_assert_txs(),
                operator_asserts.len()
            )
            .into());
        }

        for i in 0..operator_asserts.len() {
            let witness = operator_asserts
                .get(&i)
                .expect("indexed from 0 to 32")
                .clone();

            let mut commits = extract_winternitz_commits_with_sigs(
                witness,
                &ClementineBitVMPublicKeys::get_assert_derivations(i, deposit_outpoint, paramset),
                self.config.protocol_paramset(),
            )?;

            // Similar to the original operator asserts ordering, here we reorder into the format that BitVM expects.
            // For the first transaction, we have specific commits that need to be assigned to their respective arrays.
            // It includes the g16 public input commit, the last 2 num_u256 commits, and the last 3 intermediate value commits.
            // The rest of the commits are assigned to the num_u256_commits and intermediate_value_commits arrays.
            match i {
                0 => {
                    // Remove the last commit, which is for challenge-sending watchtowers
                    commits.pop();
                    let len = commits.len();

                    // Assign specific commits to their respective arrays by removing from the end.
                    // This is slightly more efficient than removing from arbitrary indices.
                    g16_public_input_commit[0] = commits.remove(len - 1);
                    num_u256_commits[12] = commits.remove(len - 2);
                    num_u256_commits[13] = commits.remove(len - 3);
                    intermediate_value_commits[360] = commits.remove(len - 4);
                    intermediate_value_commits[361] = commits.remove(len - 5);
                    intermediate_value_commits[362] = commits.remove(len - 6);
                }
                1 | 2 => {
                    // Handles i = 1 and i = 2
                    for j in 0..6 {
                        num_u256_commits[6 * (i - 1) + j] = commits
                            .pop()
                            .expect("Should not panic: `num_u256_commits` index out of bounds");
                    }
                }
                3..=32 => {
                    // Handles i from 3 to 32
                    for j in 0..12 {
                        intermediate_value_commits[12 * (i - 3) + j] = commits.pop().expect(
                            "Should not panic: `intermediate_value_commits` index out of bounds",
                        );
                    }
                }
                _ => {
                    // Catch-all for any other 'i' values
                    panic!("Unexpected operator assert index: {}; expected 0 to 32.", i);
                }
            }
        }

        tracing::info!("Converting assert commits to required format");
        tracing::info!(
            "g16_public_input_commit[0]: {:?}",
            g16_public_input_commit[0]
        );

        // Helper closure to parse commit data into the ([u8; 20], u8) format.
        // This avoids code repetition and improves readability.
        let fill_from_commits = |source: &Vec<Vec<u8>>, target: &mut [([u8; 20], u8)]| {
            // We iterate over chunks of 2 `Vec<u8>` elements at a time.
            for (i, chunk) in source.chunks_exact(2).enumerate() {
                // The first element of the chunk is the 20-byte array.
                let array_part: [u8; 20] = chunk[0]
                    .as_slice()
                    .try_into()
                    .expect("Slice is not 20 bytes");
                // The second element of the chunk is the single byte (u8).
                let u8_part: u8 = *chunk[1].first().unwrap_or(&0);
                target[i] = (array_part, u8_part);
            }
        };

        let mut first_box = Box::new([[([0u8; 20], 0u8); 68]; 1]);
        fill_from_commits(&g16_public_input_commit[0], &mut first_box[0]);

        let mut second_box = Box::new([[([0u8; 20], 0u8); 68]; 14]);
        for i in 0..14 {
            fill_from_commits(&num_u256_commits[i], &mut second_box[i]);
        }

        let mut third_box = Box::new([[([0u8; 20], 0u8); 36]; 363]);
        for i in 0..363 {
            fill_from_commits(&intermediate_value_commits[i], &mut third_box[i]);
        }

        tracing::info!("Boxes created");

        let vk = get_verifying_key();

        let res = tokio::task::spawn_blocking(move || {
            validate_assertions(
                &vk,
                (first_box, second_box, third_box),
                bitvm_pks.bitvm_pks,
                disprove_scripts
                    .as_slice()
                    .try_into()
                    .expect("static bitvm_cache contains exactly 364 disprove scripts"),
            )
        })
        .await
        .wrap_err("Validate assertions thread failed with error")?;

        tracing::info!("Disprove validation result: {:?}", res);

        match res {
            None => {
                tracing::info!("No disprove witness found");
                Ok(None)
            }
            Some((index, disprove_script)) => {
                tracing::info!("Disprove witness found");
                Ok(Some((index, disprove_script)))
            }
        }
    }

    /// Constructs, signs, and broadcasts the primary disprove transaction based on the operator assertions.
    ///
    /// This function takes the `StructuredScript` and its `index` returned by `verify_disprove_conditions`.
    /// It compiles the script, extracts the witness data (the push-only elements), and places it into the correct
    /// script path (`index`) of the disprove transaction. It then adds the necessary operator and verifier
    /// signatures before broadcasting the transaction to the Bitcoin network.
    ///
    /// # Arguments
    /// * `txhandlers` - A map containing the pre-built `Disprove` transaction handler.
    /// * `kickoff_data` - Contextual data from the kickoff transaction.
    /// * `deposit_data` - Contextual data for the deposit being challenged.
    /// * `disprove_script` - A tuple containing the executable `StructuredScript` and its Taproot leaf `index`, as returned by `verify_disprove_conditions`.
    ///
    /// # Returns
    /// - `Ok(())` on successful broadcast of the transaction.
    /// - `Err(BridgeError)` if signing or broadcasting fails.
    #[cfg(feature = "automation")]
    async fn send_disprove_tx(
        &self,
        txhandlers: &BTreeMap<TransactionType, TxHandler>,
        kickoff_data: KickoffData,
        deposit_data: DepositData,
        disprove_script: (usize, StructuredScript),
    ) -> Result<(), BridgeError> {
        let verifier_xonly_pk = self.signer.xonly_public_key;

        let mut disprove_txhandler = txhandlers
            .get(&TransactionType::Disprove)
            .wrap_err("Disprove txhandler not found in txhandlers")?
            .clone();

        let disprove_inputs: Vec<Vec<u8>> = disprove_script
            .1
            .compile()
            .instructions()
            .filter_map(|ins_res| match ins_res {
                Ok(Instruction::PushBytes(bytes)) => Some(bytes.as_bytes().to_vec()),
                _ => None,
            })
            .collect();

        disprove_txhandler
            .set_p2tr_script_spend_witness(&disprove_inputs, 0, disprove_script.0 + 2)
            .inspect_err(|e| {
                tracing::error!("Error setting disprove input witness: {:?}", e);
            })?;

        let operators_sig = self
            .db
            .get_deposit_signatures(
                None,
                deposit_data.get_deposit_outpoint(),
                kickoff_data.operator_xonly_pk,
                kickoff_data.round_idx,
                kickoff_data.kickoff_idx as usize,
            )
            .await?
            .ok_or_eyre("No operator signature found for the disprove tx")?;

        let mut tweak_cache = TweakCache::default();

        self.signer
            .tx_sign_and_fill_sigs(
                &mut disprove_txhandler,
                operators_sig.as_ref(),
                Some(&mut tweak_cache),
            )
            .inspect_err(|e| {
                tracing::error!(
                    "Error signing disprove tx for verifier {:?}: {:?}",
                    verifier_xonly_pk,
                    e
                );
            })?;

        let disprove_tx = disprove_txhandler.get_cached_tx().clone();

        tracing::debug!("Disprove txid: {:?}", disprove_tx.compute_txid());

        tracing::warn!(
            "BitVM disprove tx created for verifier {:?} with kickoff_data: {:?}, deposit_data: {:?}",
            verifier_xonly_pk,
            kickoff_data,
            deposit_data
        );

        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .add_tx_to_queue(
                &mut dbtx,
                TransactionType::Disprove,
                &disprove_tx,
                &[],
                Some(TxMetadata {
                    tx_type: TransactionType::Disprove,
                    deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                    operator_xonly_pk: Some(kickoff_data.operator_xonly_pk),
                    round_idx: Some(kickoff_data.round_idx),
                    kickoff_idx: Some(kickoff_data.kickoff_idx),
                }),
                &self.config,
                None,
            )
            .await?;
        dbtx.commit().await?;
        Ok(())
    }

    async fn handle_finalized_block(
        &self,
        mut dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block_height: u32,
        block_cache: Arc<block_cache::BlockCache>,
        light_client_proof_wait_interval_secs: Option<u32>,
    ) -> Result<(), BridgeError> {
        tracing::info!("Verifier handling finalized block height: {}", block_height);

        // before a certain number of blocks, citrea doesn't produce proofs (defined in citrea config)
        let max_attempts = light_client_proof_wait_interval_secs.unwrap_or(TEN_MINUTES_IN_SECS);
        let timeout = Duration::from_secs(max_attempts as u64);

        let (l2_height_start, l2_height_end) = self
            .citrea_client
            .get_citrea_l2_height_range(
                block_height.into(),
                timeout,
                self.config.protocol_paramset().network,
            )
            .await
            .inspect_err(|e| tracing::error!("Error getting citrea l2 height range: {:?}", e))?;

        tracing::debug!(
            "l2_height_start: {:?}, l2_height_end: {:?}, collecting deposits and withdrawals...",
            l2_height_start,
            l2_height_end
        );
        self.update_citrea_deposit_and_withdrawals(
            &mut dbtx,
            l2_height_start,
            l2_height_end,
            block_height,
        )
        .await?;

        self.update_finalized_payouts(&mut dbtx, block_id, &block_cache)
            .await?;

        #[cfg(feature = "automation")]
        {
            // Save unproven block cache to the database
            self.header_chain_prover
                .save_unproven_block_cache(Some(&mut dbtx), &block_cache)
                .await?;
            while (self.header_chain_prover.prove_if_ready().await?).is_some() {
                // Continue until prove_if_ready returns None
                // If it doesn't return None, it means next batch_size amount of blocks were proven
            }
        }

        Ok(())
    }
}

// This implementation is only relevant for non-automation mode, where the verifier is run as a standalone process
#[cfg(not(feature = "automation"))]
#[async_trait::async_trait]
impl<C> crate::bitcoin_syncer::BlockHandler for Verifier<C>
where
    C: CitreaClientT,
{
    async fn handle_new_block(
        &mut self,
        dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block: bitcoin::Block,
        height: u32,
    ) -> Result<(), BridgeError> {
        self.handle_finalized_block(
            dbtx,
            block_id,
            height,
            Arc::new(block_cache::BlockCache::from_block(&block, height)),
            None,
        )
        .await
    }
}

impl<C> NamedEntity for Verifier<C>
where
    C: CitreaClientT,
{
    const ENTITY_NAME: &'static str = "verifier";
    const TX_SENDER_CONSUMER_ID: &'static str = "verifier_tx_sender";
    const FINALIZED_BLOCK_CONSUMER_ID: &'static str = "verifier_finalized_block_fetcher";
}

#[cfg(feature = "automation")]
mod states {
    use super::*;
    use crate::builder::transaction::{
        create_txhandlers, ContractContext, ReimburseDbCache, TxHandlerCache,
    };
    use crate::states::context::DutyResult;
    use crate::states::{block_cache, StateManager};
    use crate::states::{Duty, Owner};
    use std::collections::BTreeMap;
    use tonic::async_trait;

    #[async_trait]
    impl<C> Owner for Verifier<C>
    where
        C: CitreaClientT,
    {
        async fn handle_duty(&self, duty: Duty) -> Result<DutyResult, BridgeError> {
            let verifier_xonly_pk = &self.signer.xonly_public_key;
            match duty {
                Duty::NewReadyToReimburse {
                    round_idx,
                    operator_xonly_pk,
                    used_kickoffs,
                } => {
                    tracing::info!(
                    "Verifier {:?} called new ready to reimburse with round_idx: {:?}, operator_idx: {}, used_kickoffs: {:?}",
                    verifier_xonly_pk, round_idx, operator_xonly_pk, used_kickoffs
                );
                    self.send_unspent_kickoff_connectors(
                        round_idx,
                        operator_xonly_pk,
                        used_kickoffs,
                    )
                    .await?;
                    Ok(DutyResult::Handled)
                }
                Duty::WatchtowerChallenge {
                    kickoff_data,
                    deposit_data,
                } => {
                    tracing::warn!(
                    "Verifier {:?} called watchtower challenge with kickoff_data: {:?}, deposit_data: {:?}",
                    verifier_xonly_pk, kickoff_data, deposit_data
                );
                    self.send_watchtower_challenge(kickoff_data, deposit_data)
                        .await?;

                    tracing::info!("Verifier sent watchtower challenge",);

                    Ok(DutyResult::Handled)
                }
                Duty::SendOperatorAsserts { .. } => Ok(DutyResult::Handled),
                Duty::VerifierDisprove {
                    kickoff_data,
                    mut deposit_data,
                    operator_asserts,
                    operator_acks,
                    payout_blockhash,
                    latest_blockhash,
                } => {
                    #[cfg(test)]
                    {
                        if !self
                            .config
                            .test_params
                            .should_disprove(&self.signer.public_key, &deposit_data)?
                        {
                            return Ok(DutyResult::Handled);
                        }
                    }
                    let context = ContractContext::new_context_with_signer(
                        kickoff_data,
                        deposit_data.clone(),
                        self.config.protocol_paramset(),
                        self.signer.clone(),
                    );
                    let mut db_cache = ReimburseDbCache::from_context(self.db.clone(), &context);

                    let txhandlers = create_txhandlers(
                        TransactionType::Disprove,
                        context,
                        &mut TxHandlerCache::new(),
                        &mut db_cache,
                    )
                    .await?;

                    // Attempt to find an additional disprove witness first
                    if let Some(additional_disprove_witness) = self
                        .verify_additional_disprove_conditions(
                            &mut deposit_data,
                            &kickoff_data,
                            &latest_blockhash,
                            &payout_blockhash,
                            &operator_asserts,
                            &operator_acks,
                            &txhandlers,
                        )
                        .await?
                    {
                        tracing::info!(
                            "The additional public inputs for the bridge proof provided by operator {:?} for the deposit are incorrect.",
                            kickoff_data.operator_xonly_pk
                        );
                        self.send_disprove_tx_additional(
                            &txhandlers,
                            kickoff_data,
                            deposit_data,
                            additional_disprove_witness,
                        )
                        .await?;
                    } else {
                        tracing::info!(
                            "The additional public inputs for the bridge proof provided by operator {:?} for the deposit are correct.",
                            kickoff_data.operator_xonly_pk
                        );

                        // If no additional witness, try to find a standard disprove witness
                        match self
                            .verify_disprove_conditions(&mut deposit_data, &operator_asserts)
                            .await?
                        {
                            Some((index, disprove_script)) => {
                                tracing::info!(
                                    "The public inputs for the bridge proof provided by operator {:?} for the deposit are incorrect.",
                                    kickoff_data.operator_xonly_pk
                                );

                                self.send_disprove_tx(
                                    &txhandlers,
                                    kickoff_data,
                                    deposit_data,
                                    (index, disprove_script),
                                )
                                .await?;
                            }
                            None => {
                                tracing::info!(
                                    "The public inputs for the bridge proof provided by operator {:?} for the deposit are correct.",
                                    kickoff_data.operator_xonly_pk
                                );
                            }
                        }
                    }

                    Ok(DutyResult::Handled)
                }
                Duty::SendLatestBlockhash { .. } => Ok(DutyResult::Handled),
                Duty::CheckIfKickoff {
                    txid,
                    block_height,
                    witness,
                    challenged_before,
                } => {
                    tracing::debug!(
                        "Verifier {:?} called check if kickoff with txid: {:?}, block_height: {:?}",
                        verifier_xonly_pk,
                        txid,
                        block_height,
                    );
                    let db_kickoff_data = self
                        .db
                        .get_deposit_data_with_kickoff_txid(None, txid)
                        .await?;
                    let mut challenged = false;
                    if let Some((deposit_data, kickoff_data)) = db_kickoff_data {
                        tracing::debug!(
                            "New kickoff found {:?}, for deposit: {:?}",
                            kickoff_data,
                            deposit_data.get_deposit_outpoint()
                        );
                        let mut dbtx = self.db.begin_transaction().await?;
                        // add kickoff machine if there is a new kickoff
                        // do not add if kickoff finalizer is already spent => kickoff is finished
                        // this can happen if we are resyncing
                        StateManager::<Self>::dispatch_new_kickoff_machine(
                            self.db.clone(),
                            &mut dbtx,
                            kickoff_data,
                            block_height,
                            deposit_data.clone(),
                            witness.clone(),
                        )
                        .await?;
                        challenged = self
                            .handle_kickoff(
                                &mut dbtx,
                                witness,
                                deposit_data,
                                kickoff_data,
                                challenged_before,
                            )
                            .await?;
                        dbtx.commit().await?;
                    }
                    Ok(DutyResult::CheckIfKickoff { challenged })
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
            dbtx: DatabaseTransaction<'_, '_>,
            block_id: u32,
            block_height: u32,
            block_cache: Arc<block_cache::BlockCache>,
            light_client_proof_wait_interval_secs: Option<u32>,
        ) -> Result<(), BridgeError> {
            self.handle_finalized_block(
                dbtx,
                block_id,
                block_height,
                block_cache,
                light_client_proof_wait_interval_secs,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::common::citrea::MockCitreaClient;
    use crate::test::common::*;
    use bitcoin::Block;
    use std::sync::Arc;

    #[tokio::test]
    #[ignore]
    async fn test_handle_finalized_block_idempotency() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let verifier = Verifier::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();

        // Create test block data
        let block_id = 1u32;
        let block_height = 100u32;
        let test_block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 12345,
            },
            txdata: vec![], // empty transactions
        };
        let block_cache = Arc::new(block_cache::BlockCache::from_block(
            &test_block,
            block_height,
        ));

        // First call to handle_finalized_block
        let mut dbtx1 = verifier.db.begin_transaction().await.unwrap();
        let result1 = verifier
            .handle_finalized_block(
                &mut dbtx1,
                block_id,
                block_height,
                block_cache.clone(),
                None,
            )
            .await;
        // Should succeed or fail gracefully - testing idempotency, not functionality
        tracing::info!("First call result: {:?}", result1);

        // Commit the first transaction
        dbtx1.commit().await.unwrap();

        // Second call with identical parameters should also succeed (idempotent)
        let mut dbtx2 = verifier.db.begin_transaction().await.unwrap();
        let result2 = verifier
            .handle_finalized_block(
                &mut dbtx2,
                block_id,
                block_height,
                block_cache.clone(),
                None,
            )
            .await;
        // Should succeed or fail gracefully - testing idempotency, not functionality
        tracing::info!("Second call result: {:?}", result2);

        // Commit the second transaction
        dbtx2.commit().await.unwrap();

        // Both calls should have same outcome (both succeed or both fail with same error type)
        assert_eq!(
            result1.is_ok(),
            result2.is_ok(),
            "Both calls should have the same outcome"
        );
    }

    #[tokio::test]
    #[cfg(feature = "automation")]
    async fn test_database_operations_idempotency() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let verifier = Verifier::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();

        // Test header chain prover save operation idempotency
        let test_block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 12345,
            },
            txdata: vec![], // empty transactions
        };
        let block_cache = block_cache::BlockCache::from_block(&test_block, 100u32);

        // First save
        let mut dbtx1 = verifier.db.begin_transaction().await.unwrap();
        let result1 = verifier
            .header_chain_prover
            .save_unproven_block_cache(Some(&mut dbtx1), &block_cache)
            .await;
        assert!(result1.is_ok(), "First save should succeed");
        dbtx1.commit().await.unwrap();

        // Second save with same data should be idempotent
        let mut dbtx2 = verifier.db.begin_transaction().await.unwrap();
        let result2 = verifier
            .header_chain_prover
            .save_unproven_block_cache(Some(&mut dbtx2), &block_cache)
            .await;
        assert!(result2.is_ok(), "Second save should succeed (idempotent)");
        dbtx2.commit().await.unwrap();
    }
}
