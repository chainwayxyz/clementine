use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::sighash::{create_operator_sighash_stream, PartialSignatureInfo};
use crate::builder::transaction::creator::{create_round_txhandlers, KickoffWinternitzKeys};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::{DepositData, OperatorData, TransactionType, TxHandler};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::tx_sender::TxSender;
use crate::utils::SECP;
use crate::{builder, UTXO};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use bitcoincore_rpc::RpcApi;
use bitvm::signatures::winternitz;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

pub type SecretPreimage = [u8; 20];
pub type PublicHash = [u8; 20]; // TODO: Make sure these are 20 bytes and maybe do this a struct?

#[derive(Debug, Clone)]
pub struct Operator {
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub signer: Actor,
    pub config: BridgeConfig,
    pub nofn_xonly_pk: XOnlyPublicKey,
    pub collateral_funding_outpoint: OutPoint,
    pub idx: usize,
    pub(crate) reimburse_addr: Address,
    pub tx_sender: TxSender,
    pub citrea_client: Option<jsonrpsee::http_client::HttpClient>,
}

impl Operator {
    /// Creates a new `Operator`.
    pub async fn new(config: BridgeConfig, rpc: ExtendedRpc) -> Result<Self, BridgeError> {
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );

        let db = Database::new(&config).await?;

        let tx_sender = TxSender::new(signer.clone(), rpc.clone(), db.clone(), config.network);

        let nofn_xonly_pk =
            XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)?;
        let idx = config
            .operators_xonly_pks
            .iter()
            .position(|xonly_pk| xonly_pk == &signer.xonly_public_key)
            .ok_or(BridgeError::ServerError(std::io::Error::other(format!(
                "{} is not found in operator x-only public keys",
                signer.xonly_public_key
            ))))?;

        if config.operator_withdrawal_fee_sats.is_none() {
            return Err(BridgeError::OperatorWithdrawalFeeNotSet);
        }

        // TODO: Fix this where the config will only have one address. also check??
        let reimburse_addr = config.operator_wallet_addresses[idx]
            .clone()
            .assume_checked();

        // check if we store our collateral outpoint already in db
        let op_data = db.get_operator(None, idx as i32).await?;
        let collateral_funding_outpoint = match op_data {
            Some(op_data) => op_data.collateral_funding_outpoint,
            None => {
                let outpoint = rpc
                    .send_to_address(&signer.address, config.collateral_funding_amount)
                    .await?;
                db.set_operator(
                    None,
                    idx as i32,
                    signer.xonly_public_key,
                    reimburse_addr.to_string(),
                    outpoint,
                )
                .await?;
                outpoint
            }
        };

        let citrea_client = if !config.citrea_rpc_url.is_empty() {
            Some(HttpClientBuilder::default().build(config.citrea_rpc_url.clone())?)
        } else {
            None
        };

        tracing::debug!(
            "Operator idx: {:?}, db created with name: {:?}",
            idx,
            config.db_name
        );

        Ok(Self {
            rpc,
            db,
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
        let kickoff_wpks = KickoffWinternitzKeys::new(wpks, self.config.num_kickoffs_per_round);
        let kickoff_sigs = self.generate_unspent_kickoff_sigs(&kickoff_wpks)?;
        let wpks = kickoff_wpks.keys;
        let (sig_tx, sig_rx) = mpsc::channel(kickoff_sigs.len());

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
        deposit_id: DepositData,
    ) -> Result<mpsc::Receiver<schnorr::Signature>, BridgeError> {
        let (sig_tx, sig_rx) = mpsc::channel(1280);

        let mut sighash_stream = Box::pin(create_operator_sighash_stream(
            self.db.clone(),
            self.idx,
            self.collateral_funding_outpoint,
            self.reimburse_addr.clone(),
            self.signer.xonly_public_key,
            self.config.clone(),
            deposit_id,
            self.nofn_xonly_pk,
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

    // /// Public endpoint for every depositor to call.
    // ///
    // /// It will get signatures from all verifiers:
    // ///
    // /// 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    // /// 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
    // /// 3. Create a kickoff transaction but do not broadcast it
    // ///
    // /// TODO: Create multiple kickoffs in single transaction
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn new_deposit(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     recovery_taproot_address: Address<NetworkUnchecked>,
    //     evm_address: EVMAddress,
    // ) -> Result<(UTXO, schnorr::Signature), BridgeError> {
    //     tracing::info!(
    //         "New deposit request for UTXO: {:?}, EVM address: {:?} and recovery taproot address of: {:?}",
    //         deposit_outpoint,
    //         evm_address,
    //         recovery_taproot_address
    //     );

    //     // 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    //     self.rpc
    //         .check_deposit_utxo(
    //             self.nofn_xonly_pk,
    //             &deposit_outpoint,
    //             &recovery_taproot_address,
    //             evm_address,
    //             self.config.bridge_amount_sats,
    //             self.config.confirmation_threshold,
    //             self.config.network,
    //             self.config.user_takes_after,
    //         )
    //         .await?;

    //     let mut tx = self.db.begin_transaction().await?;

    //     self.db.lock_operators_kickoff_utxo_table(&mut tx).await?;

    //     // 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
    //     let kickoff_utxo = self
    //         .db
    //         .get_kickoff_utxo(Some(&mut tx), deposit_outpoint)
    //         .await?;
    //     // if we already have a kickoff UTXO for this deposit UTXO, return it
    //     if let Some(kickoff_utxo) = kickoff_utxo {
    //         tracing::debug!(
    //             "Kickoff UTXO found: {:?} already exists for deposit UTXO: {:?}",
    //             kickoff_utxo,
    //             deposit_outpoint
    //         );
    //         let kickoff_sig_hash = crate::sha256_hash!(
    //             deposit_outpoint.txid,
    //             deposit_outpoint.vout.to_be_bytes(),
    //             kickoff_utxo.outpoint.txid,
    //             kickoff_utxo.outpoint.vout.to_be_bytes()
    //         );

    //         let sig = self
    //             .signer
    //             .sign(TapSighash::from_byte_array(kickoff_sig_hash));

    //         // self.db.unlock_operators_kickoff_utxo_table(&mut tx).await?;
    //         tx.commit().await?;
    //         return Ok((kickoff_utxo, sig));
    //     }

    //     // Check if we already have an unused kickoff UTXO available
    //     let unused_kickoff_utxo = self
    //         .db
    //         .get_unused_kickoff_utxo_and_increase_idx(Some(&mut tx))
    //         .await?;
    //     if let Some(unused_kickoff_utxo) = unused_kickoff_utxo {
    //         self.db
    //             .save_kickoff_utxo(Some(&mut tx), deposit_outpoint, unused_kickoff_utxo.clone())
    //             .await?;

    //         // self.db.unlock_operators_kickoff_utxo_table(&mut tx).await?;
    //         tx.commit().await?;

    //         tracing::debug!(
    //             "Unused kickoff UTXO found: {:?} found for deposit UTXO: {:?}",
    //             unused_kickoff_utxo,
    //             deposit_outpoint
    //         );
    //         let kickoff_sig_hash = crate::sha256_hash!(
    //             deposit_outpoint.txid,
    //             deposit_outpoint.vout.to_be_bytes(),
    //             unused_kickoff_utxo.outpoint.txid,
    //             unused_kickoff_utxo.outpoint.vout.to_be_bytes()
    //         );

    //         let sig = self
    //             .signer
    //             .sign(TapSighash::from_byte_array(kickoff_sig_hash));

    //         Ok((unused_kickoff_utxo, sig))
    //     } else {
    //         // 3. Create a kickoff transaction but do not broadcast it

    //         // To create a kickoff tx, we first need a funding utxo
    //         let funding_utxo = self.db.get_funding_utxo(Some(&mut tx)).await?.ok_or(
    //             BridgeError::OperatorFundingUtxoNotFound(self.signer.address.clone()),
    //         )?;

    //         // if the amount is not enough, return an error
    //         // The amount will be calculated as if the transaction has 1 input
    //         // and (num_kickoff_utxos + 2) outputs where the first k outputs are
    //         // the kickoff outputs, the penultimante output is the change output,
    //         // and the last output is the anyonecanpay output for fee bumping.
    //         let kickoff_tx_min_relay_fee = match self.config.operator_num_kickoff_utxos_per_tx {
    //             0..=250 => 154 + 43 * self.config.operator_num_kickoff_utxos_per_tx, // Handles all values from 0 to 250
    //             _ => 156 + 43 * self.config.operator_num_kickoff_utxos_per_tx, // Handles all other values
    //         };
    //         if funding_utxo.txout.value.to_sat()
    //             < (KICKOFF_UTXO_AMOUNT_SATS.to_sat()
    //                 * self.config.operator_num_kickoff_utxos_per_tx as u64
    //                 + kickoff_tx_min_relay_fee as u64
    //                 + 330)
    //         {
    //             return Err(BridgeError::OperatorFundingUtxoAmountNotEnough(
    //                 self.signer.address.clone(),
    //             ));
    //         }
    //         let mut kickoff_tx_handler = builder::transaction::create_kickoff_utxo_txhandler(
    //             &funding_utxo,
    //             self.nofn_xonly_pk,
    //             self.signer.xonly_public_key,
    //             self.config.network,
    //             self.config.operator_num_kickoff_utxos_per_tx,
    //         );
    //         tracing::debug!(
    //             "Funding UTXO found: {:?} kickoff UTXO is created for deposit UTXO: {:?}",
    //             funding_utxo,
    //             deposit_outpoint
    //         );
    //         let sig = self
    //             .signer
    //             .sign_taproot_pubkey_spend(&mut kickoff_tx_handler, 0, None)?;
    //         handle_taproot_witness_new(&mut kickoff_tx_handler, &[sig.as_ref()], 0, None)?;
    //         tracing::debug!(
    //             "Created kickoff tx with weight: {:#?}",
    //             kickoff_tx_handler.tx.weight()
    //         );
    //         // tracing::debug!(
    //         //     "Created kickoff tx: {:#?}",
    //         //     kickoff_tx_handler.tx.raw_hex()
    //         // );
    //         // tracing::debug!(
    //         //     "For operator index: {:?} Kickoff tx handler: {:#?}",
    //         //     self.idx,
    //         //     kickoff_tx_handler
    //         // );

    //         let change_utxo = UTXO {
    //             outpoint: OutPoint {
    //                 txid: kickoff_tx_handler.tx.compute_txid(),
    //                 vout: self.config.operator_num_kickoff_utxos_per_tx as u32,
    //             },
    //             txout: kickoff_tx_handler.tx.output[self.config.operator_num_kickoff_utxos_per_tx]
    //                 .clone(),
    //         };
    //         tracing::debug!(
    //             "Change UTXO: {:?} after new kickoff UTXOs are generated for deposit UTXO: {:?}",
    //             change_utxo,
    //             deposit_outpoint
    //         );

    //         let kickoff_utxo = UTXO {
    //             outpoint: OutPoint {
    //                 txid: kickoff_tx_handler.tx.compute_txid(),
    //                 vout: 0,
    //             },
    //             txout: kickoff_tx_handler.tx.output[0].clone(),
    //         };
    //         tracing::debug!(
    //             "Kickoff UTXO: {:?} after new kickoff UTXOs are generated for deposit UTXO: {:?}",
    //             kickoff_utxo,
    //             deposit_outpoint
    //         );

    //         // In a db tx, save the kickoff_utxo for this deposit_outpoint
    //         // and update the db with the new funding_utxo as the change

    //         // let db_transaction = self.db.begin_transaction().await?;

    //         // We save the funding txid and the kickoff txid to be able to track them later
    //         self.db
    //             .save_kickoff_utxo(Some(&mut tx), deposit_outpoint, kickoff_utxo.clone())
    //             .await?;

    //         self.db
    //             .add_deposit_kickoff_generator_tx(
    //                 Some(&mut tx),
    //                 kickoff_tx_handler.tx.compute_txid(),
    //                 kickoff_tx_handler.tx.raw_hex(),
    //                 self.config.operator_num_kickoff_utxos_per_tx,
    //                 funding_utxo.outpoint.txid,
    //             )
    //             .await?;

    //         self.db.set_funding_utxo(Some(&mut tx), change_utxo).await?;

    //         tx.commit().await?;

    //         let kickoff_sig_hash = crate::sha256_hash!(
    //             deposit_outpoint.txid,
    //             deposit_outpoint.vout.to_be_bytes(),
    //             kickoff_utxo.outpoint.txid,
    //             kickoff_utxo.outpoint.vout.to_be_bytes()
    //         );

    //         let sig = self
    //             .signer
    //             .sign(TapSighash::from_byte_array(kickoff_sig_hash));

    //         Ok((kickoff_utxo, sig))
    //     }
    // }

    // /// Saves funding UTXO to the database.
    // async fn set_funding_utxo(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
    //     self.db.set_funding_utxo(None, funding_utxo).await
    // }

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
        net_profit > operator_withdrawal_fee_sats
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
    /// - `user_sig`: User's signature that is going to be used for signing
    ///   withdrawal transaction input
    /// - `users_intent_outpoint`: User's input for the payout transaction
    /// - `users_intent_script_pubkey`: User's script pubkey which will be used
    ///   in the payout transaction's output
    /// - `users_intent_amount`: Payout transaction output's value
    ///
    /// # Returns
    ///
    /// - [`Txid`]: Payout transaction's txid
    pub async fn new_withdrawal_sig(
        &self,
        withdrawal_index: u32,
        user_signature: schnorr::Signature,
        users_intent_outpoint: OutPoint,
        users_intent_script_pubkey: ScriptBuf,
        users_intent_amount: Amount,
    ) -> Result<Txid, BridgeError> {
        // Prepare input and output of the payout transaction.
        let input_prevout = self
            .rpc
            .get_txout_from_outpoint(&users_intent_outpoint)
            .await?;
        let input_utxo = UTXO {
            outpoint: users_intent_outpoint,
            txout: input_prevout,
        };
        let output_txout = TxOut {
            value: users_intent_amount,
            script_pubkey: users_intent_script_pubkey,
        };

        // Check Citrea for the withdrawal state.
        if let Some(citrea_client) = &self.citrea_client {
            // See: https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80
            let params = rpc_params![
                json!({
                    "to": "0x3100000000000000000000000000000000000002",
                    "data": format!("0x471ba1e300000000000000000000000000000000000000000000000000000000{}",
                    hex::encode(withdrawal_index.to_be_bytes())),
                }),
                "latest"
            ];
            let response: String = citrea_client.request("eth_call", params).await?;

            let txid_response = &response[2..66];
            let txid = hex::decode(txid_response).map_err(|e| BridgeError::Error(e.to_string()))?;
            // txid.reverse(); // TODO: we should need to reverse this, test this with declareWithdrawalFiller

            let txid = Txid::from_slice(&txid)?;
            if txid != input_utxo.outpoint.txid || 0 != input_utxo.outpoint.vout {
                // TODO: Fix this, vout can be different from 0 as well
                return Err(BridgeError::InvalidInputUTXO(
                    txid,
                    input_utxo.outpoint.txid,
                ));
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
            self.config.bridge_amount_sats,
            operator_withdrawal_fee_sats,
        ) {
            return Err(BridgeError::NotEnoughFeeForOperator);
        }

        let user_xonly_pk =
            XOnlyPublicKey::from_slice(&input_utxo.txout.script_pubkey.as_bytes()[2..34])?;

        let payout_txhandler = builder::transaction::create_payout_txhandler(
            input_utxo,
            output_txout,
            self.idx,
            user_signature,
            self.config.network,
        )?;

        let sighash = payout_txhandler.calculate_pubkey_spend_sighash(
            0,
            bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
        )?;

        SECP.verify_schnorr(
            &user_signature,
            &Message::from_digest(*sighash.as_byte_array()),
            &user_xonly_pk,
        )?;

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
            .await?
            .hex;

        let signed_tx: Transaction = deserialize(
            &self
                .rpc
                .client
                .sign_raw_transaction_with_wallet(&funded_tx, None, None)
                .await?
                .hex,
        )?;

        Ok(self.rpc.client.send_raw_transaction(&signed_tx).await?)
    }

    /// Checks Citrea if a withdrawal is finalized.
    ///
    /// Calls `withdrawFillers(withdrawal_idx)` to check the returned id is our
    /// operator's id. Then calculates `move_txid` and calls
    /// `txIdToDepositId(move_txid)` to check if returned id is
    /// `withdrawal_idx`.
    pub async fn check_citrea_for_withdrawal(
        &self,
        withdrawal_idx: u32,
        _deposit_outpoint: OutPoint,
    ) -> Result<(), BridgeError> {
        // Don't check anything if Citrea client is not specified.
        let citrea_client = match &self.citrea_client {
            Some(c) => c,
            None => return Ok(()),
        };

        // Check for operator id.
        {
            // See: https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80
            let params = rpc_params![
                json!({
                    "to": "0x3100000000000000000000000000000000000002",
                    "data": format!("0xc045577b00000000000000000000000000000000000000000000000000000000{}",
                    hex::encode(withdrawal_idx.to_be_bytes())),
                }),
                "latest"
            ];
            let response: String = citrea_client.request("eth_call", params).await?;

            let operator_idx_as_vec = hex::decode(&response[58..66]).map_err(|_| {
                BridgeError::InvalidCitreaResponse(format!(
                    "Failed to decode operator_idx hex from response: OperatorIdx = {}",
                    &response[58..66]
                ))
            })?;
            let operator_idx = u32::from_be_bytes(
                operator_idx_as_vec
                    .try_into()
                    .expect("length statically known"),
            );

            if operator_idx - 1 != self.idx as u32 {
                return Err(BridgeError::InvalidOperatorIndex(
                    operator_idx as usize,
                    self.idx,
                ));
            }
        }

        // Check for withdrawal idx.
        {
            // let move_txid = builder::transaction::create_move_to_vault_tx(
            //     deposit_outpoint,
            //     self.nofn_xonly_pk,
            //     self.config.bridge_amount_sats,
            //     self.config.network,
            // )
            // .compute_txid();

            // See: https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80
            let params = rpc_params![json!({
                "to": "0x3100000000000000000000000000000000000002",
                "data": format!("0x11e53a01{}",
                // hex::encode(move_txid.to_byte_array())),
                hex::encode([0]))
            })];
            let response: String = citrea_client.request("eth_call", params).await?;

            let deposit_idx_response = &response[58..66];
            let deposit_idx_as_vec = hex::decode(deposit_idx_response).map_err(|_| {
                BridgeError::InvalidCitreaResponse(format!(
                    "Invalid deposit idx response from Citrea, deposit idx = {}",
                    &response[58..66]
                ))
            })?;
            let deposit_idx = u32::from_be_bytes(
                deposit_idx_as_vec
                    .try_into()
                    .expect("length statically known"),
            );

            if deposit_idx - 1 != withdrawal_idx {
                return Err(BridgeError::InvalidDepositOutpointGiven(
                    deposit_idx as usize - 1,
                    withdrawal_idx as usize,
                ));
            }
        }

        Ok(())
    }

    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub(crate) async fn withdrawal_proved_on_citrea(
    //     &self,
    //     withdrawal_idx: u32,
    //     deposit_outpoint: OutPoint,
    // ) -> Result<Vec<String>, BridgeError> {
    //     self.check_citrea_for_withdrawal(withdrawal_idx, deposit_outpoint)
    //         .await?;

    //     let kickoff_utxo = self
    //         .db
    //         .get_kickoff_utxo(None, deposit_outpoint)
    //         .await?
    //         .ok_or(BridgeError::KickoffOutpointsNotFound)?;
    //     tracing::debug!("Kickoff UTXO FOUND after withdrawal: {:?}", kickoff_utxo);

    //     // Check if current TxId is onchain or in mempool.
    //     let mut txs_to_be_sent = vec![];
    //     let mut current_searching_txid = kickoff_utxo.outpoint.txid;
    //     let mut found_txid = false;
    //     for _ in 0..25 {
    //         if self
    //             .rpc
    //             .client
    //             .get_raw_transaction(&current_searching_txid, None)
    //             .await
    //             .is_ok()
    //         {
    //             found_txid = true;
    //             break;
    //         }

    //         // Fetch the transaction and continue the loop.
    //         let (raw_signed_tx, _, _, funding_txid) = self
    //             .db
    //             .get_deposit_kickoff_generator_tx(current_searching_txid)
    //             .await?
    //             .ok_or(BridgeError::KickoffGeneratorTxNotFound)?;

    //         txs_to_be_sent.push(raw_signed_tx);
    //         current_searching_txid = funding_txid;
    //     }
    //     txs_to_be_sent.reverse();

    //     if !found_txid {
    //         return Err(BridgeError::KickoffGeneratorTxsTooManyIterations); // TODO: Fix this error
    //     }

    //     let mut slash_or_take_tx_handler = builder::transaction::create_slash_or_take_tx(
    //         deposit_outpoint,
    //         kickoff_utxo.clone(),
    //         self.signer.xonly_public_key,
    //         self.idx,
    //         self.nofn_xonly_pk,
    //         self.config.network,
    //         self.config.user_takes_after,
    //         self.config.operator_takes_after,
    //         self.config.bridge_amount_sats,
    //     );

    //     let slash_or_take_utxo = UTXO {
    //         outpoint: OutPoint {
    //             txid: slash_or_take_tx_handler.tx.compute_txid(),
    //             vout: 0,
    //         },
    //         txout: slash_or_take_tx_handler.tx.output[0].clone(),
    //     };

    //     let nofn_sig = self
    //         .db
    //         .get_slash_or_take_sig(deposit_outpoint, kickoff_utxo.clone())
    //         .await?
    //         .ok_or(BridgeError::OperatorSlashOrTakeSigNotFound)?;

    //     let our_sig =
    //         self.signer
    //             .sign_taproot_script_spend_tx(&mut slash_or_take_tx_handler, 0, 0)?;

    //     handle_taproot_witness_new(
    //         &mut slash_or_take_tx_handler,
    //         &[our_sig.as_ref(), nofn_sig.as_ref()],
    //         0,
    //         Some(0),
    //     )?;

    //     txs_to_be_sent.push(slash_or_take_tx_handler.tx.raw_hex());

    //     let move_tx = builder::transaction::create_move_to_vault_tx(
    //         deposit_outpoint,
    //         self.nofn_xonly_pk,
    //         self.config.bridge_amount_sats,
    //         self.config.network,
    //     );
    //     let bridge_fund_outpoint = OutPoint {
    //         txid: move_tx.compute_txid(),
    //         vout: 0,
    //     };

    //     let mut operator_takes_tx = builder::transaction::create_operator_takes_tx(
    //         bridge_fund_outpoint,
    //         slash_or_take_utxo,
    //         self.signer.xonly_public_key,
    //         self.nofn_xonly_pk,
    //         self.config.network,
    //         self.config.operator_takes_after,
    //         self.config.bridge_amount_sats,
    //         self.config.operator_wallet_addresses[self.idx].clone(),
    //     );

    //     let operator_takes_nofn_sig = self
    //         .db
    //         .get_operator_take_sig(deposit_outpoint, kickoff_utxo)
    //         .await?
    //         .ok_or(BridgeError::OperatorTakesSigNotFound)?;
    //     tracing::debug!("Operator Found nofn sig: {:?}", operator_takes_nofn_sig);

    //     let our_sig = self
    //         .signer
    //         .sign_taproot_script_spend_tx(&mut operator_takes_tx, 1, 0)?;

    //     handle_taproot_witness_new(
    //         &mut operator_takes_tx,
    //         &[operator_takes_nofn_sig.as_ref()],
    //         0,
    //         None,
    //     )?;
    //     handle_taproot_witness_new(&mut operator_takes_tx, &[our_sig.as_ref()], 1, Some(0))?;

    //     txs_to_be_sent.push(operator_takes_tx.tx.raw_hex());

    //     Ok(txs_to_be_sent)
    // }

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
        // TODO: Misleading name
        let mut winternitz_pubkeys =
            Vec::with_capacity(self.config.get_num_assert_winternitz_pks());

        for (intermediate_step, intermediate_step_size) in
            crate::utils::BITVM_CACHE.intermediate_variables.iter()
        {
            let path = WinternitzDerivationPath::BitvmAssert(
                *intermediate_step_size as u32 * 2,
                intermediate_step.to_owned(),
                deposit_txid,
            );
            winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
        }

        if winternitz_pubkeys.len() != self.config.get_num_assert_winternitz_pks() {
            return Err(BridgeError::Error(format!(
                "Expected {} number of assert winternitz pubkeys, but got {}",
                self.config.get_num_assert_winternitz_pks(),
                winternitz_pubkeys.len()
            )));
        }

        Ok(winternitz_pubkeys)
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
        for round_idx in 0..self.config.num_round_txs + 1 {
            for kickoff_idx in 0..self.config.num_kickoffs_per_round {
                let path = WinternitzDerivationPath::Kickoff(round_idx as u32, kickoff_idx as u32);
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
        for idx in 0..self.config.num_round_txs {
            let txhandlers = create_round_txhandlers(
                &self.config,
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

        for watchtower_idx in 0..self.config.num_watchtowers {
            let path =
                WinternitzDerivationPath::ChallengeAckHash(watchtower_idx as u32, deposit_txid);
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
}

#[cfg(test)]
mod tests {
    use crate::operator::Operator;
    use crate::test::common::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    // #[tokio::test]
    // async fn set_funding_utxo() {
    //     let mut config = create_test_config_with_thread_name(None).await;
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
    //     let mut config = create_test_config_with_thread_name(None).await;
    //     let rpc = ExtendedRpc::connect(
    //         config.bitcoin_rpc_url.clone(),
    //         config.bitcoin_rpc_user.clone(),
    //         config.bitcoin_rpc_password.clone(),
    //     )
    //     .await;

    //     config.bridge_amount_sats = Amount::from_sat(0x45);
    //     config.operator_withdrawal_fee_sats = Some(Amount::from_sat(0x1F));

    //     let operator = Operator::new(config.clone(), rpc).await.unwrap();

    //     // Smaller input amount must not cause a panic.
    //     operator.is_profitable(Amount::from_sat(3), Amount::from_sat(1));
    //     // Bigger input amount must not cause a panic.
    //     operator.is_profitable(Amount::from_sat(6), Amount::from_sat(9));

    //     // False because difference between input and withdrawal amount is
    //     // bigger than `config.bridge_amount_sats`.
    //     assert!(!operator.is_profitable(Amount::from_sat(6), Amount::from_sat(90)));

    //     // False because net profit is smaller than
    //     // `config.operator_withdrawal_fee_sats`.
    //     assert!(!operator.is_profitable(Amount::from_sat(0), config.bridge_amount_sats));

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
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let operator = Operator::new(config.clone(), rpc.clone()).await.unwrap();

        let winternitz_public_key = operator
            .generate_assert_winternitz_pubkeys(Txid::all_zeros())
            .unwrap();
        assert_eq!(
            winternitz_public_key.len(),
            config.num_round_txs * config.num_kickoffs_per_round
        );
    }

    #[tokio::test]
    async fn test_generate_preimages_and_hashes() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let operator = Operator::new(config.clone(), rpc.clone()).await.unwrap();

        let preimages = operator
            .generate_challenge_ack_preimages_and_hashes(Txid::all_zeros())
            .unwrap();
        assert_eq!(preimages.len(), config.num_watchtowers);
    }

    #[tokio::test]
    async fn operator_get_params() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let operator = Operator::new(config.clone(), rpc.clone()).await.unwrap();
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
