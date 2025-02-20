use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::sighash::create_operator_sighash_stream;
use crate::builder::transaction::{create_seq_collat_reimburse_gen_nth_txhandler, create_txhandlers, DepositData};
use crate::config::BridgeConfig;
use crate::database::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::tx_sender::{ActivedWithOutpoint, TxSender};
use crate::utils::SECP;
use crate::{builder, UTXO};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::{
    Address, Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
};
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
    pub async fn get_params(&self) -> Result<mpsc::Receiver<winternitz::PublicKey>, BridgeError> {
        let wpks = self.generate_kickoff_winternitz_pubkeys()?;
        let wpk_channel = mpsc::channel(wpks.len());

        tokio::spawn(async move {
            for wpk in wpks {
                wpk_channel
                    .0
                    .send(wpk)
                    .await
                    .map_err(|e| BridgeError::SendError("winternitz public key", e.to_string()))?;
            }

            Ok::<(), BridgeError>(())
        });

        Ok(wpk_channel.1)
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
        let mut winternitz_pubkeys = Vec::new();

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

        Ok(winternitz_pubkeys)
    }
    /// Generates Winternitz public keys for every blockhash commit to be used in kickoff utxos.
    /// Unique for each kickoff utxo of operator.
    ///
    /// # Returns
    ///
    /// - [`Vec<Vec<winternitz::PublicKey>>`]: Winternitz public keys for
    ///   `sequential_collateral_index` row and `kickoff_idx` column.
    pub fn generate_kickoff_winternitz_pubkeys(
        &self,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let mut winternitz_pubkeys = Vec::new();

        for sequential_collateral_idx in 0..self.config.num_sequential_collateral_txs {
            for kickoff_idx in 0..self.config.num_kickoffs_per_sequential_collateral_tx {
                let path = WinternitzDerivationPath::Kickoff(
                    sequential_collateral_idx as u32,
                    kickoff_idx as u32,
                );
                winternitz_pubkeys.push(self.signer.derive_winternitz_pk(path)?);
            }
        }

        Ok(winternitz_pubkeys)
    }

    pub fn generate_challenge_ack_preimages_and_hashes(
        &self,
        deposit_txid: Txid,
    ) -> Result<Vec<PublicHash>, BridgeError> {
        let mut hashes = Vec::new();

        for watchtower_idx in 0..self.config.num_watchtowers {
            let path =
                WinternitzDerivationPath::ChallengeAckHash(watchtower_idx as u32, deposit_txid);
            let hash = self.signer.generate_public_hash_from_path(path)?;
            hashes.push(hash);
        }
        tracing::info!("Public hashes len: {:?}", hashes.len());
        Ok(hashes)
    }

    pub async fn handle_finalized_payout(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        deposit_id: u32,
        payout_tx_blockhash: BlockHash,
    ) -> Result<(), BridgeError> {
        // get unsused kickoff connector
        let (round_idx, kickoff_connector_idx, signatures) = self
            .db
            .get_signatures_for_unused_and_signed_kickoff_connector(Some(dbtx), deposit_id)
            .await?
            .ok_or(BridgeError::DatabaseError(sqlx::Error::RowNotFound))?;

        // get signed txs,

        let kickoff_txid = Txid::all_zeros();

        // try to send them

        // mark the kickoff connector as used
        self.db
            .set_kickoff_connector_as_used(
                Some(dbtx),
                round_idx,
                kickoff_connector_idx,
                Some(kickoff_txid),
            )
            .await?;

        Ok(())
    }

    pub async fn end_round(&self, dbtx: DatabaseTransaction<'_, '_>) -> Result<(), BridgeError> {
        // get current round index
        let current_round_index = self.db.get_current_round_index(Some(dbtx)).await?;
        let current_round_index = current_round_index.unwrap_or(0);

        let mut activation_prerequisites = Vec::new();

        let txhandlers = create_txhandlers(self.config.clone(), deposit_id, self.nofn_xonly_pk, transaction_type, kickoff_id, operator_data, prev_reimburse_generator, db_data);
        // get kickoff txid for used kickoff connector
        for kickoff_connector_idx in 0..self.config.num_kickoffs_per_sequential_collateral_tx as u32
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
                    activation_prerequisites.push(ActivedWithOutpoint {
                        outpoint: OutPoint::new(kickoff_txid, 2),
                        timelock: bitcoin::Sequence(self.config.confirmation_threshold),
                    });
                }
                None => {
                    self.db
                        .set_kickoff_connector_as_used(
                            Some(dbtx),
                            current_round_index,
                            kickoff_connector_idx,
                            None,
                        )
                        .await?;
                }
            }
        }
        // update current round index
        self.db
            .update_current_round_index(Some(dbtx), current_round_index + 1)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::create_regtest_rpc;
    use crate::{
        config::BridgeConfig, database::Database, initialize_database, utils::initialize_logger,
    };
    use crate::{
        create_test_config_with_thread_name, extended_rpc::ExtendedRpc, operator::Operator,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    #[tokio::test]
    #[ignore = "Design changes in progress"]
    async fn get_winternitz_public_keys() {
        let mut config = create_test_config_with_thread_name!(None);
        let regtest = create_regtest_rpc!(config);
        let rpc = regtest.rpc();

        let operator = Operator::new(config.clone(), rpc.clone()).await.unwrap();

        let winternitz_public_key = operator
            .generate_assert_winternitz_pubkeys(Txid::all_zeros())
            .unwrap();
        assert_eq!(
            winternitz_public_key.len(),
            config.num_sequential_collateral_txs * config.num_kickoffs_per_sequential_collateral_tx
        );
    }

    #[tokio::test]
    async fn test_generate_preimages_and_hashes() {
        let mut config = create_test_config_with_thread_name!(None);
        let regtest = create_regtest_rpc!(config);
        let rpc = regtest.rpc();

        let operator = Operator::new(config.clone(), rpc.clone()).await.unwrap();

        let preimages = operator
            .generate_challenge_ack_preimages_and_hashes(Txid::all_zeros())
            .unwrap();
        assert_eq!(preimages.len(), config.num_watchtowers);
    }

    #[tokio::test]
    async fn operator_get_params() {
        let mut config = create_test_config_with_thread_name!(None);
        let regtest = create_regtest_rpc!(config);
        let rpc = regtest.rpc();

        let operator = Operator::new(config.clone(), rpc.clone()).await.unwrap();
        let actual_wpks = operator.generate_kickoff_winternitz_pubkeys().unwrap();

        let mut wpk_rx = operator.get_params().await.unwrap();
        let mut idx = 0;
        while let Some(wpk) = wpk_rx.recv().await {
            assert_eq!(actual_wpks[idx], wpk);
            idx += 1;
        }
        assert_eq!(idx, actual_wpks.len());
    }
}
