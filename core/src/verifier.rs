use crate::actor::Actor;
use crate::bitvm_client::{self, ClementineBitVMPublicKeys, SECP};
use crate::builder::address::taproot_builder_with_scripts;
use crate::builder::script::{SpendableScript, WinternitzCommit};
use crate::builder::sighash::{
    create_nofn_sighash_stream, create_operator_sighash_stream, PartialSignatureInfo, SignatureInfo,
};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::{
    create_move_to_vault_txhandler, DepositData, OperatorData, TransactionType, TxHandler,
};
use crate::builder::transaction::{create_round_txhandlers, KickoffWinternitzKeys};
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, AggregateFromPublicKeys};
use crate::rpc::clementine::{OperatorKeys, TaggedSignature, WatchtowerKeys};
use crate::tx_sender::TxSender;
use crate::{bitcoin_syncer, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::{secp256k1::PublicKey, OutPoint};
use bitcoin::{Address, ScriptBuf, TapTweakHash, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce, MusigSecNonce};
use std::collections::HashMap;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

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

#[derive(Debug, Clone)]
pub struct Verifier {
    _rpc: ExtendedRpc,
    pub(crate) signer: Actor,
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,
    pub(crate) nofn_xonly_pk: bitcoin::secp256k1::XOnlyPublicKey,
    pub(crate) nofn: Arc<tokio::sync::RwLock<Option<NofN>>>,
    _operator_xonly_pks: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    pub(crate) nonces: Arc<tokio::sync::Mutex<AllSessions>>,
    pub idx: usize,
    pub tx_sender: TxSender,
}

impl Verifier {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );

        // let pk: bitcoin::secp256k1:: PublicKey = config.secret_key.public_key(&utils::SECP);

        // TODO: In the future, we won't get verifiers public keys from config files, rather in set_verifiers rpc call.
        let idx = config
            .verifiers_public_keys
            .iter()
            .position(|pk| pk == &signer.public_key)
            .ok_or(BridgeError::PublicKeyNotFound)?;

        let db = Database::new(&config).await?;
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let tx_sender = TxSender::new(
            signer.clone(),
            rpc.clone(),
            db.clone(),
            &format!("verifier_{}", idx).to_string(),
            config.protocol_paramset().network,
        );
        let tx_sender_handle = tx_sender.run(Duration::from_secs(1)).await?;

        // Monitor the tx_sender_handle and abort if it dies unexpectedly
        crate::utils::monitor_task_with_abort(tx_sender_handle, "tx_sender for verifier");

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
            tracing::debug!("Verifiers public keys found: {:?}", verifiers_pks);
            let nofn = NofN::new(signer.public_key, verifiers_pks)?;
            Some(nofn)
        } else {
            None
        };

        bitcoin_syncer::set_initial_block_info_if_not_exists(&db, &rpc).await?;
        let _handle =
            bitcoin_syncer::start_bitcoin_syncer(db.clone(), rpc.clone(), Duration::from_secs(1))
                .await?;

        Ok(Verifier {
            _rpc: rpc,
            signer,
            db,
            config,
            nofn_xonly_pk,
            nofn: Arc::new(tokio::sync::RwLock::new(nofn)),
            _operator_xonly_pks: operator_xonly_pks,
            nonces: Arc::new(tokio::sync::Mutex::new(all_sessions)),
            idx,
            tx_sender,
        })
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
                prev_ready_to_reimburse.clone(),
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
        // Save the operator details to the db
        self.db
            .set_operator(
                None,
                operator_index as i32,
                operator_xonly_pk,
                wallet_reimburse_address.to_string(),
                collateral_funding_outpoint,
            )
            .await?;

        self.db
            .set_operator_kickoff_winternitz_public_keys(
                None,
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
                .set_unspent_kickoff_sigs(None, operator_index as usize, round_idx, sigs)
                .await?;
        }

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
        deposit_outpoint: OutPoint,
        evm_address: EVMAddress,
        recovery_taproot_address: Address<NetworkUnchecked>,
        session_id: u32,
        mut agg_nonce_rx: mpsc::Receiver<MusigAggNonce>,
    ) -> Result<mpsc::Receiver<MusigPartialSignature>, BridgeError> {
        let verifier = self.clone();
        let (partial_sig_tx, partial_sig_rx) = mpsc::channel(1280);

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
                DepositData {
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                },
                verifier.nofn_xonly_pk,
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
        deposit_outpoint: OutPoint,
        evm_address: EVMAddress,
        recovery_taproot_address: Address<NetworkUnchecked>,
        session_id: u32,
        mut sig_receiver: mpsc::Receiver<Signature>,
        mut agg_nonce_receiver: mpsc::Receiver<MusigAggNonce>,
        mut operator_sig_receiver: mpsc::Receiver<Signature>,
    ) -> Result<MusigPartialSignature, BridgeError> {
        let mut sighash_stream = pin!(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            DepositData {
                deposit_outpoint,
                evm_address,
                recovery_taproot_address: recovery_taproot_address.clone(),
            },
            self.nofn_xonly_pk,
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

        let mut nonce_idx: usize = 0;

        while let Some(sig) = sig_receiver.recv().await {
            let sighash = sighash_stream
                .next()
                .await
                .ok_or(BridgeError::SighashStreamEndedPrematurely)??;

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
            let &SignatureInfo {
                operator_idx,
                round_idx,
                kickoff_utxo_idx,
                signature_id,
            } = &sighash.1;
            let tagged_sig = TaggedSignature {
                signature: sig.serialize().to_vec(),
                signature_id: Some(signature_id),
            };
            verified_sigs[operator_idx][round_idx][kickoff_utxo_idx].push(tagged_sig);
            tracing::debug!("Final Signature Verified");

            nonce_idx += 1;
            if nonce_idx == num_required_nofn_sigs {
                break;
            }
        }

        if nonce_idx != num_required_nofn_sigs {
            return Err(BridgeError::Error(format!(
                "Not received enough nofn signatures. Needed: {}, received: {}",
                num_required_nofn_sigs, nonce_idx
            )));
        }

        // Generate partial signature for move transaction
        let move_txhandler = create_move_to_vault_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            self.nofn_xonly_pk,
            self.config.protocol_paramset().user_takes_after,
            self.config.protocol_paramset().bridge_amount,
            self.config.protocol_paramset().network,
        )?;

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

        let num_required_total_op_sigs = num_required_op_sigs * self.config.num_operators;
        let mut total_op_sig_count = 0;

        // get operator data
        let operators_data: Vec<(XOnlyPublicKey, bitcoin::Address, OutPoint)> =
            self.db.get_operators(None).await?;

        // get signatures of operators and verify them
        for (operator_idx, (op_xonly_pk, reimburse_addr, collateral_outpoint)) in
            operators_data.iter().enumerate()
        {
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
                *collateral_outpoint,
                reimburse_addr.clone(),
                *op_xonly_pk,
                self.config.clone(),
                DepositData {
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address: recovery_taproot_address.clone(),
                },
                self.nofn_xonly_pk,
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
                DepositData {
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address: recovery_taproot_address.clone(),
                },
            )
            .await?;
        // Deposit is not actually finalized here, its only finalized after the aggregator gets all the partial sigs and checks the aggregated sig
        // TODO: It can create problems if the deposit fails at the end by some verifier not sending movetx partial sig, but we still added sigs to db
        for (operator_idx, operator_sigs) in verified_sigs.into_iter().enumerate() {
            for (seq_idx, op_sequential_sigs) in operator_sigs.into_iter().enumerate() {
                for (kickoff_idx, kickoff_sigs) in op_sequential_sigs.into_iter().enumerate() {
                    self.db
                        .set_deposit_signatures(
                            Some(&mut dbtx),
                            deposit_outpoint,
                            operator_idx,
                            seq_idx,
                            kickoff_idx,
                            kickoff_sigs,
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
        deposit_id: DepositData,
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
                deposit_id.deposit_outpoint,
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
                deposit_id.deposit_outpoint,
                &assert_tx_addrs,
                &root_hash_bytes,
            )
            .await?;

        Ok(())
    }

    pub async fn set_watchtower_keys(
        &self,
        deposit_id: DepositData,
        keys: WatchtowerKeys,
        watchtower_idx: u32,
    ) -> Result<(), BridgeError> {
        let watchtower_xonly_pk = self
            .db
            .get_watchtower_xonly_pk(None, watchtower_idx)
            .await?;

        let winternitz_keys: Vec<winternitz::PublicKey> = keys
            .winternitz_pubkeys
            .into_iter()
            .map(|x| x.try_into())
            .collect::<Result<_, BridgeError>>()?;

        for (operator_id, winternitz_key) in winternitz_keys.into_iter().enumerate() {
            self.db
                .set_watchtower_winternitz_public_keys(
                    None,
                    watchtower_idx,
                    operator_id as u32,
                    deposit_id.deposit_outpoint,
                    &winternitz_key,
                )
                .await?;

            let script = WinternitzCommit::new(
                vec![(
                    winternitz_key,
                    self.config
                        .protocol_paramset()
                        .watchtower_challenge_message_length as u32,
                )],
                watchtower_xonly_pk,
                self.config.protocol_paramset().winternitz_log_d,
            )
            .to_script_buf();

            let taproot_builder = taproot_builder_with_scripts(&[script]);
            let root_hash = taproot_builder
                .try_into_taptree()
                .expect("taproot builder always builds a full taptree")
                .root_hash();
            let root_hash_bytes = root_hash.to_raw_hash().to_byte_array();

            self.db
                .set_watchtower_challenge_hash(
                    None,
                    watchtower_idx,
                    operator_id as u32,
                    root_hash_bytes,
                    deposit_id.deposit_outpoint,
                )
                .await?;
        }

        Ok(())
    }
}
