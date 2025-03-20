use crate::actor::Actor;
use crate::bitcoin_syncer::BitcoinSyncer;
use crate::bitvm_client::{self, ClementineBitVMPublicKeys, SECP};
use crate::builder::address::taproot_builder_with_scripts;
use crate::builder::sighash::{
    create_nofn_sighash_stream, create_operator_sighash_stream, PartialSignatureInfo, SignatureInfo,
};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::builder::transaction::{
    create_move_to_vault_txhandler, create_txhandlers, ContractContext, DepositData, OperatorData,
    ReimburseDbCache, TransactionType, TxHandler, TxHandlerCache,
};
use crate::builder::transaction::{create_round_txhandlers, KickoffWinternitzKeys};
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::constants::TEN_MINUTES_IN_SECS;
use crate::database::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, AggregateFromPublicKeys};
use crate::rpc;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::{
    KickoffId, NormalSignatureKind, OperatorKeys, TaggedSignature, TransactionRequest,
};
use crate::states::{block_cache, StateManager};
use crate::states::{Duty, Owner};
use crate::task::manager::BackgroundTaskManager;
use crate::task::IntoTask;
use crate::tx_sender::{TxMetadata, TxSender, TxSenderClient};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::{secp256k1::PublicKey, OutPoint};
use bitcoin::{Address, ScriptBuf, TapTweakHash, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce, MusigSecNonce};
use std::collections::{BTreeMap, HashMap};
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::async_trait;

#[derive(Debug)]
pub struct NonceSession {
    /// Nonces used for a deposit session (last nonce is for the movetx signature)
    pub nonces: Vec<MusigSecNonce>,
}

#[derive(Debug)]
pub struct AllSessions {
    pub cur_id: u32,
    pub sessions: HashMap<u32, NonceSession>,
}

#[derive(Debug, Clone)]
pub struct NofN {
    pub public_keys: Vec<bitcoin::secp256k1::PublicKey>,
    pub agg_xonly_pk: bitcoin::secp256k1::XOnlyPublicKey,
    pub idx: usize,
}

impl NofN {
    pub fn new(
        self_pk: bitcoin::secp256k1::PublicKey,
        public_keys: Vec<bitcoin::secp256k1::PublicKey>,
    ) -> Result<Self, BridgeError> {
        let idx = public_keys
            .iter()
            .position(|pk| pk == &self_pk)
            .ok_or(BridgeError::PublicKeyNotFound)?;
        let agg_xonly_pk =
            bitcoin::secp256k1::XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None)?;
        Ok(NofN {
            public_keys,
            agg_xonly_pk,
            idx,
        })
    }
}

pub struct VerifierServer<C: CitreaClientT> {
    pub verifier: Verifier<C>,
    background_tasks: BackgroundTaskManager<Verifier<C>>,
}

impl<C> VerifierServer<C>
where
    C: CitreaClientT,
{
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let verifier = Verifier::new(config.clone()).await?;
        let db = verifier.db.clone();
        let mut background_tasks = BackgroundTaskManager::default();

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let tx_sender = TxSender::new(
            verifier.signer.clone(),
            rpc.clone(),
            verifier.db.clone(),
            format!("verifier_{}", verifier.idx).to_string(),
            config.protocol_paramset().network,
        );

        background_tasks.loop_and_monitor(tx_sender.into_task());

        // initialize and run state manager
        let state_manager =
            StateManager::new(db.clone(), verifier.clone(), config.protocol_paramset()).await?;

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

        let syncer = BitcoinSyncer::new(db, rpc, config.protocol_paramset()).await?;

        background_tasks.loop_and_monitor(syncer.into_task());

        Ok(VerifierServer {
            verifier,
            background_tasks,
        })
    }

    pub async fn shutdown(&mut self) {
        self.background_tasks
            .graceful_shutdown_with_timeout(Duration::from_secs(10))
            .await;
    }
}

#[derive(Debug, Clone)]
pub struct Verifier<C: CitreaClientT> {
    rpc: ExtendedRpc,
    pub idx: usize,

    pub(crate) signer: Actor,
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,

    pub(crate) nofn_xonly_pk: bitcoin::secp256k1::XOnlyPublicKey,
    pub(crate) nofn: Arc<tokio::sync::RwLock<Option<NofN>>>,
    _operator_xonly_pks: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    pub(crate) nonces: Arc<tokio::sync::Mutex<AllSessions>>,
    pub tx_sender: TxSenderClient,
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

        // TODO: In the future, we won't get verifiers public keys from config files, rather in set_verifiers rpc call.
        let idx = config
            .verifiers_public_keys
            .iter()
            .position(|pk| pk == &signer.public_key)
            .ok_or(BridgeError::PublicKeyNotFound)?;

        let db = Database::new(&config).await?;

        let citrea_client = C::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            None,
        )
        .await?;

        let nofn_xonly_pk = bitcoin::secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
        )?;

        let operator_xonly_pks = config.operators_xonly_pks.clone();

        let all_sessions = AllSessions {
            cur_id: 0,
            sessions: HashMap::new(),
        };

        let verifiers_pks = db.get_verifiers_public_keys(None).await?;

        let nofn = if !verifiers_pks.is_empty() {
            tracing::debug!("Verifier public keys found: {:?}", verifiers_pks);
            let nofn = NofN::new(signer.public_key, verifiers_pks)?;
            Some(nofn)
        } else {
            None
        };

        let tx_sender = TxSenderClient::new(db.clone(), format!("verifier_{}", idx).to_string());

        tracing::info!(
            "Verifier {} created with nofn_xonly_pk: {}",
            idx,
            nofn_xonly_pk
        );

        let verifier = Verifier {
            rpc,
            signer,
            db: db.clone(),
            config: config.clone(),
            nofn_xonly_pk,
            nofn: Arc::new(tokio::sync::RwLock::new(nofn)),
            _operator_xonly_pks: operator_xonly_pks,
            nonces: Arc::new(tokio::sync::Mutex::new(all_sessions)),
            idx,
            tx_sender,
            citrea_client,
        };
        Ok(verifier)
    }

    pub async fn set_verifiers(
        &self,
        verifiers_public_keys: Vec<PublicKey>,
    ) -> Result<(), BridgeError> {
        // Check if verifiers are already set
        if self.nofn.read().await.clone().is_some() {
            return Err(BridgeError::AlreadyInitialized);
        }

        // Save verifiers public keys to db
        self.db
            .set_verifiers_public_keys(None, &verifiers_public_keys)
            .await?;

        // Save the nofn to memory for fast access
        let nofn = NofN::new(self.signer.public_key, verifiers_public_keys.clone())?;
        self.nofn.write().await.replace(nofn);

        Ok(())
    }

    /// Verifies all unspent kickoff signatures sent by the operator, converts them to TaggedSignature
    /// as they will be saved as TaggedSignatures to the db.
    fn verify_unspent_kickoff_sigs(
        &self,
        operator_index: u32,
        collateral_funding_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        wallet_reimburse_address: Address,
        unspent_kickoff_sigs: Vec<Signature>,
        kickoff_wpks: &KickoffWinternitzKeys,
    ) -> Result<Vec<TaggedSignature>, BridgeError> {
        let mut tagged_sigs = Vec::with_capacity(unspent_kickoff_sigs.len());
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            collateral_funding_outpoint,
            reimburse_addr: wallet_reimburse_address.clone(),
        };
        let mut cur_sig_index = 0;
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
                        operator_idx: operator_index as usize,
                        round_idx: idx,
                        kickoff_utxo_idx: kickoff_idx,
                    };
                    let sighashes = txhandler
                        .calculate_shared_txins_sighash(EntityType::OperatorSetup, partial)?;
                    for sighash in sighashes {
                        let message = Message::from_digest(sighash.0.to_byte_array());
                        bitvm_client::SECP
                            .verify_schnorr(
                                &unspent_kickoff_sigs[cur_sig_index],
                                &message,
                                &operator_xonly_pk,
                            )
                            .map_err(|e| {
                                BridgeError::Error(format!(
                                    "Unspent kickoff signature verification failed for num sig {}: {}",
                                    cur_sig_index + 1,
                                    e
                                ))
                            })?;
                        tagged_sigs.push(TaggedSignature {
                            signature: unspent_kickoff_sigs[cur_sig_index].serialize().to_vec(),
                            signature_id: Some(sighash.1.signature_id),
                        });
                        cur_sig_index += 1;
                    }
                }
                if let TransactionType::ReadyToReimburse = txhandler.get_transaction_type() {
                    prev_ready_to_reimburse = Some(txhandler);
                }
            }
        }

        Ok(tagged_sigs)
    }

    pub async fn set_operator(
        &self,
        operator_index: u32,
        collateral_funding_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        wallet_reimburse_address: Address,
        operator_winternitz_public_keys: Vec<winternitz::PublicKey>,
        unspent_kickoff_sigs: Vec<Signature>,
    ) -> Result<(), BridgeError> {
        let kickoff_wpks = KickoffWinternitzKeys::new(
            operator_winternitz_public_keys,
            self.config.protocol_paramset().num_kickoffs_per_round,
        );
        let tagged_sigs = self.verify_unspent_kickoff_sigs(
            operator_index,
            collateral_funding_outpoint,
            operator_xonly_pk,
            wallet_reimburse_address.clone(),
            unspent_kickoff_sigs,
            &kickoff_wpks,
        )?;

        let operator_winternitz_public_keys = kickoff_wpks.keys;
        let mut dbtx = self.db.begin_transaction().await?;
        // Save the operator details to the db
        self.db
            .set_operator(
                Some(&mut dbtx),
                operator_index as i32,
                operator_xonly_pk,
                wallet_reimburse_address.to_string(),
                collateral_funding_outpoint,
            )
            .await?;

        self.db
            .set_operator_kickoff_winternitz_public_keys(
                Some(&mut dbtx),
                operator_index,
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
                .set_unspent_kickoff_sigs(Some(&mut dbtx), operator_index as usize, round_idx, sigs)
                .await?;
        }

        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            collateral_funding_outpoint,
            reimburse_addr: wallet_reimburse_address,
        };

        StateManager::<Self>::dispatch_new_round_machine(
            self.db.clone(),
            &mut dbtx,
            operator_data,
            operator_index,
        )
        .await?;

        dbtx.commit().await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, xonly_pk), fields(verifier_idx = self.idx), ret)]
    pub async fn set_watchtower(
        &self,
        watchtower_idx: u32,
        xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        self.db
            .set_watchtower_xonly_pk(None, watchtower_idx, &xonly_pk)
            .await?;

        Ok(())
    }

    pub async fn nonce_gen(
        &self,
        num_nonces: u32,
    ) -> Result<(u32, Vec<MusigPubNonce>), BridgeError> {
        let (sec_nonces, pub_nonces): (Vec<MusigSecNonce>, Vec<MusigPubNonce>) = (0..num_nonces)
            .map(|_| {
                // nonce pair needs keypair and a rng
                let (sec_nonce, pub_nonce) = musig2::nonce_pair(
                    &self.signer.keypair,
                    &mut bitcoin::secp256k1::rand::thread_rng(),
                )?;
                Ok((sec_nonce, pub_nonce))
            })
            .collect::<Result<Vec<(MusigSecNonce, MusigPubNonce)>, BridgeError>>()?
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
        deposit_data: DepositData,
        session_id: u32,
        mut agg_nonce_rx: mpsc::Receiver<MusigAggNonce>,
    ) -> Result<mpsc::Receiver<MusigPartialSignature>, BridgeError> {
        let verifier = self.clone();
        let (partial_sig_tx, partial_sig_rx) = mpsc::channel(1280);

        let deposit_blockhash = self
            .rpc
            .get_blockhash_of_tx(&deposit_data.get_deposit_outpoint().txid)
            .await?;

        tokio::spawn(async move {
            let mut session_map = verifier.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).ok_or_else(|| {
                BridgeError::Error(format!("Could not find session id {session_id}"))
            })?;
            session.nonces.reverse();

            let mut nonce_idx: usize = 0;

            let mut sighash_stream = Box::pin(create_nofn_sighash_stream(
                verifier.db.clone(),
                verifier.config.clone(),
                deposit_data,
                deposit_blockhash,
                false,
            ));
            let num_required_sigs = verifier.config.get_num_required_nofn_sigs();

            assert_eq!(
                num_required_sigs + 1,
                session.nonces.len(),
                "Expected nonce count to be num_required_sigs + 1 (movetx)"
            );

            while let Some(agg_nonce) = agg_nonce_rx.recv().await {
                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or(BridgeError::Error("No sighash received".to_string()))??;
                tracing::debug!("Verifier {} found sighash: {:?}", verifier.idx, sighash);

                let nonce = session
                    .nonces
                    .pop()
                    .ok_or(BridgeError::Error("No nonce available".to_string()))?;
                let partial_sig = musig2::partial_sign(
                    verifier.config.verifiers_public_keys.clone(),
                    None,
                    nonce,
                    agg_nonce,
                    verifier.signer.keypair,
                    Message::from_digest(*sighash.0.as_byte_array()),
                )?;
                partial_sig_tx
                    .send(partial_sig)
                    .await
                    .map_err(|e| BridgeError::SendError("partial signature", e.to_string()))?;

                nonce_idx += 1;
                tracing::debug!(
                    "Verifier {} signed and sent sighash {} of {}",
                    verifier.idx,
                    nonce_idx,
                    num_required_sigs
                );
                if nonce_idx == num_required_sigs {
                    break;
                }
            }

            let last_nonce = session
                .nonces
                .pop()
                .ok_or(BridgeError::Error("No last nonce available".to_string()))?;
            session.nonces.clear();
            session.nonces.push(last_nonce);

            Ok::<(), BridgeError>(())
        });

        Ok(partial_sig_rx)
    }

    pub async fn deposit_finalize(
        &self,
        deposit_data: DepositData,
        session_id: u32,
        mut sig_receiver: mpsc::Receiver<Signature>,
        mut agg_nonce_receiver: mpsc::Receiver<MusigAggNonce>,
        mut operator_sig_receiver: mpsc::Receiver<Signature>,
    ) -> Result<MusigPartialSignature, BridgeError> {
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

        let num_required_nofn_sigs = self.config.get_num_required_nofn_sigs();
        let num_required_nofn_sigs_per_kickoff =
            self.config.get_num_required_nofn_sigs_per_kickoff();
        let num_required_op_sigs = self.config.get_num_required_operator_sigs();
        let num_required_op_sigs_per_kickoff =
            self.config.get_num_required_operator_sigs_per_kickoff();
        let &BridgeConfig { num_operators, .. } = &self.config;

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
                num_round_txs
            ];
            num_operators
        ];

        let mut kickoff_txids = vec![vec![vec![]; num_round_txs]; num_operators];

        // ------ N-of-N SIGNATURES VERIFICATION ------

        let mut nonce_idx: usize = 0;

        while let Some(sighash) = sighash_stream.next().await {
            let sighash = sighash.map_err(|_| BridgeError::SighashStreamEndedPrematurely)?;

            let &SignatureInfo {
                operator_idx,
                round_idx,
                kickoff_utxo_idx,
                signature_id,
                kickoff_txid,
            } = &sighash.1;

            if signature_id == NormalSignatureKind::YieldKickoffTxid.into() {
                kickoff_txids[operator_idx][round_idx].push((kickoff_txid, kickoff_utxo_idx));
                continue;
            }

            let sig = sig_receiver
                .recv()
                .await
                .ok_or(BridgeError::Error("No signature received".to_string()))?;

            tracing::debug!("Verifying Final nofn Signature {}", nonce_idx + 1);
            bitvm_client::SECP
                .verify_schnorr(&sig, &Message::from(sighash.0), &self.nofn_xonly_pk)
                .map_err(|x| {
                    BridgeError::Error(format!(
                        "Nofn Signature {} Verification Failed: {}.",
                        nonce_idx + 1,
                        x
                    ))
                })?;

            let tagged_sig = TaggedSignature {
                signature: sig.serialize().to_vec(),
                signature_id: Some(signature_id),
            };
            verified_sigs[operator_idx][round_idx][kickoff_utxo_idx].push(tagged_sig);
            tracing::debug!("Final Signature Verified");

            nonce_idx += 1;
        }

        if nonce_idx != num_required_nofn_sigs {
            return Err(BridgeError::Error(format!(
                "Not received enough nofn signatures. Needed: {}, received: {}",
                num_required_nofn_sigs, nonce_idx
            )));
        }

        // ------ OPERATOR SIGNATURES VERIFICATION ------

        let num_required_total_op_sigs = num_required_op_sigs * self.config.num_operators;
        let mut total_op_sig_count = 0;

        // get operator data
        let operators_data: Vec<(XOnlyPublicKey, bitcoin::Address, OutPoint)> =
            self.db.get_operators(None).await?;

        // get signatures of operators and verify them
        for (operator_idx, (op_xonly_pk, _, _)) in operators_data.iter().enumerate() {
            let mut op_sig_count = 0;
            // tweak the operator xonly public key with None (because merkle root is empty as operator utxos have no scripts)
            let scalar = TapTweakHash::from_key_and_tweak(*op_xonly_pk, None).to_scalar();
            let tweaked_op_xonly_pk = op_xonly_pk
                .add_tweak(&SECP, &scalar)
                .map_err(|x| {
                    BridgeError::Error(format!("Failed to tweak operator xonly public key: {}", x))
                })?
                .0;
            // generate the sighash stream for operator
            let mut sighash_stream = pin!(create_operator_sighash_stream(
                self.db.clone(),
                operator_idx,
                self.config.clone(),
                deposit_data.clone(),
                deposit_blockhash,
            ));
            while let Some(operator_sig) = operator_sig_receiver.recv().await {
                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or(BridgeError::SighashStreamEndedPrematurely)??;

                tracing::debug!(
                    "Verifying Final operator Signature {} for operator {}",
                    nonce_idx + 1,
                    operator_idx
                );

                bitvm_client::SECP
                    .verify_schnorr(
                        &operator_sig,
                        &Message::from(sighash.0),
                        &tweaked_op_xonly_pk,
                    )
                    .map_err(|x| {
                        BridgeError::Error(format!(
                            "Operator {} Signature {}: verification failed: {}.",
                            operator_idx,
                            op_sig_count + 1,
                            x
                        ))
                    })?;

                let &SignatureInfo {
                    operator_idx,
                    round_idx,
                    kickoff_utxo_idx,
                    signature_id,
                    kickoff_txid: _,
                } = &sighash.1;
                let tagged_sig = TaggedSignature {
                    signature: operator_sig.serialize().to_vec(),
                    signature_id: Some(signature_id),
                };
                verified_sigs[operator_idx][round_idx][kickoff_utxo_idx].push(tagged_sig);

                op_sig_count += 1;
                total_op_sig_count += 1;
                if op_sig_count == num_required_op_sigs {
                    break;
                }
            }
        }

        if total_op_sig_count != num_required_total_op_sigs {
            return Err(BridgeError::Error(format!(
                "Not enough operator signatures. Needed: {}, received: {}",
                num_required_total_op_sigs, total_op_sig_count
            )));
        }

        // ----- MOVE TX SIGNING

        // Generate partial signature for move transaction
        let move_txhandler =
            create_move_to_vault_txhandler(deposit_data.clone(), self.config.protocol_paramset())?;

        let move_tx_sighash = move_txhandler.calculate_script_spend_sighash_indexed(
            0,
            0,
            bitcoin::TapSighashType::Default,
        )?;

        let agg_nonce =
            agg_nonce_receiver
                .recv()
                .await
                .ok_or(BridgeError::ChannelEndedPrematurely(
                    "verifier::deposit_finalize",
                    "aggregated nonces",
                ))?;

        let movetx_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).ok_or_else(|| {
                BridgeError::Error(format!(
                    "could not find session with id {} in session cache",
                    session_id
                ))
            })?;
            session
                .nonces
                .pop()
                .ok_or_else(|| BridgeError::Error("No move tx secnonce in session".to_string()))?
        };

        // sign move tx and save everything to db if everything is correct
        let partial_sig = musig2::partial_sign(
            self.config.verifiers_public_keys.clone(),
            None,
            movetx_secnonce,
            agg_nonce,
            self.signer.keypair,
            Message::from_digest(move_tx_sighash.to_byte_array()),
        )?;

        // Save signatures to db
        let mut dbtx = self.db.begin_transaction().await?;
        self.db
            .set_deposit_data(
                Some(&mut dbtx),
                deposit_data.clone(),
                *move_txhandler.get_txid(),
            )
            .await?;
        // Deposit is not actually finalized here, its only finalized after the aggregator gets all the partial sigs and checks the aggregated sig
        // TODO: It can create problems if the deposit fails at the end by some verifier not sending movetx partial sig, but we still added sigs to db
        for (operator_idx, operator_sigs) in verified_sigs.into_iter().enumerate() {
            for (round_idx, mut op_round_sigs) in operator_sigs.into_iter().enumerate() {
                if kickoff_txids[operator_idx][round_idx].len()
                    != self.config.protocol_paramset().num_signed_kickoffs
                {
                    return Err(BridgeError::Error(format!(
                        "Number of signed kickoff utxos for operator: {}, round: {} is wrong. Expected: {}, got: {}",
                        operator_idx, round_idx, self.config.protocol_paramset().num_signed_kickoffs, kickoff_txids[operator_idx][round_idx].len()
                    )));
                }
                for (kickoff_txid, kickoff_idx) in &kickoff_txids[operator_idx][round_idx] {
                    if kickoff_txid.is_none() {
                        return Err(BridgeError::Error(format!(
                            "Kickoff txid not found for {}, {}, {}",
                            operator_idx, round_idx, kickoff_idx
                        )));
                    }

                    self.db
                        .set_deposit_signatures(
                            Some(&mut dbtx),
                            deposit_data.get_deposit_outpoint(),
                            operator_idx,
                            round_idx,
                            *kickoff_idx,
                            kickoff_txid.expect("Kickoff txid must be Some"),
                            std::mem::take(&mut op_round_sigs[*kickoff_idx]),
                        )
                        .await?;
                }
            }
        }
        dbtx.commit().await?;

        Ok(partial_sig)
    }

    pub async fn set_operator_keys(
        &self,
        deposit_data: DepositData,
        keys: OperatorKeys,
        operator_idx: u32,
    ) -> Result<(), BridgeError> {
        let hashes: Vec<[u8; 20]> = keys
            .challenge_ack_digests
            .into_iter()
            .map(|x| {
                x.hash
                    .try_into()
                    .map_err(|_| BridgeError::Error("Invalid hash length".to_string()))
            })
            .collect::<Result<Vec<[u8; 20]>, BridgeError>>()?;

        if hashes.len() != self.config.get_num_challenge_ack_hashes() {
            return Err(BridgeError::Error(
                format!(
                    "Invalid number of challenge ack hashes received from operator {}: got: {} expected: {}",
                    operator_idx,
                    hashes.len(),
                    self.config.get_num_challenge_ack_hashes()
                )
            ));
        }

        let operator_data = self
            .db
            .get_operator(None, operator_idx as i32)
            .await?
            .ok_or(BridgeError::OperatorNotFound(operator_idx))?;

        self.db
            .set_operator_challenge_ack_hashes(
                None,
                operator_idx as i32,
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
                "Invalid number of winternitz keys received from operator {}: got: {} expected: {}",
                operator_idx,
                winternitz_keys.len(),
                ClementineBitVMPublicKeys::number_of_flattened_wpks()
            );
            return Err(BridgeError::Error(format!(
                "Invalid number of winternitz keys received from operator {}: got: {} expected: {}",
                operator_idx,
                winternitz_keys.len(),
                ClementineBitVMPublicKeys::number_of_flattened_wpks()
            )));
        }

        let bitvm_pks = ClementineBitVMPublicKeys::from_flattened_vec(&winternitz_keys);
        let assert_tx_addrs = bitvm_pks
            .get_assert_taproot_leaf_hashes(operator_data.xonly_pk)
            .iter()
            .map(|x| x.to_byte_array())
            .collect::<Vec<_>>();

        // TODO: Use correct verification key and along with a dummy proof.
        let start = std::time::Instant::now();
        let scripts: Vec<ScriptBuf> = bitvm_pks.get_g16_verifier_disprove_scripts();

        let taproot_builder = taproot_builder_with_scripts(&scripts);
        let root_hash = taproot_builder
            .try_into_taptree()
            .expect("taproot builder always builds a full taptree")
            .root_hash();
        let root_hash_bytes = root_hash.to_raw_hash().to_byte_array();
        tracing::debug!("Built taproot tree in {:?}", start.elapsed());
        // let root_hash_bytes = [0u8; 32];

        // Save the public input wots to db along with the root hash
        self.db
            .set_bitvm_setup(
                None,
                operator_idx as i32,
                deposit_data.get_deposit_outpoint(),
                &assert_tx_addrs,
                &root_hash_bytes,
            )
            .await?;

        Ok(())
    }

    // TODO: #402
    async fn is_kickoff_malicious(
        &self,
        _kickoff_txid: bitcoin::Txid,
    ) -> Result<bool, BridgeError> {
        Ok(true)
    }

    pub async fn handle_kickoff<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        kickoff_txid: bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        let is_malicious = self.is_kickoff_malicious(kickoff_txid).await?;
        if !is_malicious {
            return Ok(());
        }

        let (deposit_data, kickoff_id, _) = self
            .db
            .get_deposit_signatures_with_kickoff_txid(None, kickoff_txid)
            .await?
            .ok_or(BridgeError::Error("Kickoff txid not found".to_string()))?;

        let transaction_data = TransactionRequestData {
            deposit_data: deposit_data.clone(),
            kickoff_id,
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
            operator_idx: Some(kickoff_id.operator_idx),
            verifier_idx: Some(self.idx as u32),
            round_idx: Some(kickoff_id.round_idx),
            kickoff_idx: Some(kickoff_id.kickoff_idx),
            deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
        });

        // self._rpc.client.import_descriptors(vec!["tr("])

        // try to send them
        for (tx_type, signed_tx) in &signed_txs {
            match *tx_type {
                TransactionType::Challenge
                | TransactionType::AssertTimeout(_)
                | TransactionType::KickoffNotFinalized
                | TransactionType::OperatorChallengeNack(_) => {
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

        Ok(())
    }

    async fn send_watchtower_challenge(
        &self,
        kickoff_id: KickoffId,
        deposit_data: DepositData,
    ) -> Result<(), BridgeError> {
        let watchtower_endpoint = self.config.trusted_watchtower_endpoint.clone();
        if watchtower_endpoint.is_none() {
            tracing::error!("No watchtower endpoint provided, cannot send challenge");
            return Ok(());
        }
        let watchtower_endpoint =
            watchtower_endpoint.expect("Watchtower endpoint must be provided");
        let mut watchtower =
            rpc::get_clients(vec![watchtower_endpoint], ClementineWatchtowerClient::new).await?[0]
                .clone();

        let raw_challenge_tx = watchtower
            .internal_create_watchtower_challenge(TransactionRequest {
                deposit_params: Some(deposit_data.clone().into()),
                kickoff_id: Some(kickoff_id),
            })
            .await?
            .into_inner()
            .raw_tx;
        let challenge_tx = bitcoin::consensus::deserialize(&raw_challenge_tx)?;
        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .add_tx_to_queue(
                &mut dbtx,
                TransactionType::WatchtowerChallenge(self.idx),
                &challenge_tx,
                &[],
                Some(TxMetadata {
                    tx_type: TransactionType::WatchtowerChallenge(self.idx),
                    operator_idx: None,
                    verifier_idx: Some(self.idx as u32),
                    round_idx: Some(kickoff_id.round_idx),
                    kickoff_idx: Some(kickoff_id.kickoff_idx),
                    deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                }),
                &self.config,
            )
            .await?;
        dbtx.commit().await?;
        tracing::warn!("Commited watchtower challenge for watchtower {}", self.idx);
        Ok(())
    }

    async fn update_citrea_withdrawals(
        &self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
        l2_height_start: u64,
        l2_height_end: u64,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let new_deposits = self
            .citrea_client
            .collect_deposit_move_txids(l2_height_start + 1, l2_height_end)
            .await?;
        tracing::info!("New Deposits: {:?}", new_deposits);
        let new_withdrawals = self
            .citrea_client
            .collect_withdrawal_utxos(l2_height_start + 1, l2_height_end)
            .await?;
        tracing::info!("New Withdrawals: {:?}", new_withdrawals);
        for (idx, move_to_vault_txid) in new_deposits {
            tracing::info!("Setting move to vault txid: {:?}", move_to_vault_txid);
            self.db
                .set_move_to_vault_txid_from_citrea_deposit(
                    Some(dbtx),
                    idx as u32 - 1,
                    &move_to_vault_txid,
                )
                .await?;
        }
        for (idx, withdrawal_utxo_outpoint) in new_withdrawals {
            tracing::info!("Setting withdrawal utxo: {:?}", withdrawal_utxo_outpoint);
            self.db
                .set_withdrawal_utxo_from_citrea_withdrawal(
                    Some(dbtx),
                    idx as u32,
                    withdrawal_utxo_outpoint,
                    block_height,
                )
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
            .ok_or(BridgeError::Error("Block not found".to_string()))?;

        let block_hash = block.block_hash();

        let mut payout_txs_and_payer_operator_idx = vec![];
        for (idx, payout_txid) in payout_txids {
            let payout_tx_idx = block_cache
                .txids
                .get(&payout_txid)
                .ok_or(BridgeError::Error("Payout tx not found".to_string()))?;
            let payout_tx = &block.txdata[*payout_tx_idx];
            let last_output = &payout_tx.output[payout_tx.output.len() - 1]
                .script_pubkey
                .to_bytes();
            tracing::info!("last_output: {}, idx: {}", hex::encode(last_output), idx);

            // We remove the first 2 bytes which are OP_RETURN OP_PUSH, example: 6a0100
            let mut operator_idx_bytes = [0u8; 4]; // Create a 4-byte array initialized with zeros
            operator_idx_bytes[..last_output.len() - 3]
                .copy_from_slice(&last_output[2..last_output.len() - 1]);
            let operator_idx = u32::from_le_bytes(operator_idx_bytes);

            payout_txs_and_payer_operator_idx.push((idx, payout_txid, operator_idx, block_hash));
        }

        self.db
            .set_payout_txs_and_payer_operator_idx(Some(dbtx), payout_txs_and_payer_operator_idx)
            .await?;

        Ok(())
    }
}

#[async_trait]
impl<C> Owner for Verifier<C>
where
    C: CitreaClientT,
{
    const OWNER_TYPE: &'static str = "verifier";

    async fn handle_duty(&self, duty: Duty) -> Result<(), BridgeError> {
        match duty {
            Duty::NewReadyToReimburse {
                round_idx,
                operator_idx,
                used_kickoffs,
            } => {
                tracing::info!(
                    "Verifier {} called new ready to reimburse with round_idx: {}, operator_idx: {}, used_kickoffs: {:?}",
                    self.idx, round_idx, operator_idx, used_kickoffs
                );
            }
            Duty::WatchtowerChallenge {
                kickoff_id,
                deposit_data,
            } => {
                tracing::warn!(
                    "Verifier {} called watchtower challenge with kickoff_id: {:?}, deposit_data: {:?}",
                    self.idx, kickoff_id, deposit_data
                );
                self.send_watchtower_challenge(kickoff_id, deposit_data)
                    .await?;
            }
            Duty::SendOperatorAsserts {
                kickoff_id,
                deposit_data,
                watchtower_challenges,
                ..
            } => {
                tracing::info!(
                    "Verifier {} called send operator asserts with kickoff_id: {:?}, deposit_data: {:?}, watchtower_challenges: {:?}",
                    self.idx, kickoff_id, deposit_data, watchtower_challenges.len()
                );
            }
            Duty::VerifierDisprove {
                kickoff_id,
                deposit_data,
                operator_asserts,
                operator_acks,
                payout_blockhash,
            } => {
                tracing::warn!(
                    "Verifier {} called verifier disprove with kickoff_id: {:?}, deposit_data: {:?}, operator_asserts: {:?}, operator_acks: {:?}
                    payout_blockhash: {:?}", self.idx, kickoff_id, deposit_data, operator_asserts.len(), operator_acks.len(), payout_blockhash.len());
            }
            Duty::CheckIfKickoff {
                txid,
                block_height,
                witness,
            } => {
                tracing::info!(
                    "Verifier {} called check if kickoff with txid: {:?}, block_height: {:?}",
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
                    self.handle_kickoff(&mut dbtx, txid).await?;
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
        mut dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block_height: u32,
        block_cache: Arc<block_cache::BlockCache>,
        light_client_proof_wait_interval_secs: Option<u32>,
    ) -> Result<(), BridgeError> {
        let max_attempts = light_client_proof_wait_interval_secs.unwrap_or(TEN_MINUTES_IN_SECS);
        let timeout = Duration::from_secs(max_attempts as u64);

        let (l2_height_start, l2_height_end) = self
            .citrea_client
            .get_citrea_l2_height_range(block_height.into(), timeout)
            .await?;

        tracing::info!("l2_height_end: {:?}", l2_height_end);
        tracing::info!("l2_height_start: {:?}", l2_height_start);

        tracing::info!("Collecting deposits and withdrawals");
        self.update_citrea_withdrawals(&mut dbtx, l2_height_start, l2_height_end, block_height)
            .await?;

        tracing::info!("Getting payout txids");
        self.update_finalized_payouts(&mut dbtx, block_id, &block_cache)
            .await?;

        Ok(())
    }
}
