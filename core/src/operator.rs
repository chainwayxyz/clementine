use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::operator::OperatorDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::traits::rpc::OperatorRpcServer;
use crate::transaction_builder::{TransactionBuilder, KICKOFF_UTXO_AMOUNT_SATS};
use crate::utils::handle_taproot_witness_new;
use crate::{script_builder, utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, OutPoint, TapSighash, Transaction, TxOut, Txid};
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::RawTx;
use jsonrpsee::core::async_trait;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use secp256k1::{schnorr, Message};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct Operator<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    db: OperatorDB,
    signer: Actor,
    config: BridgeConfig,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    idx: usize,
    citrea_client: Option<jsonrpsee::http_client::HttpClient>,
}

impl<R> Operator<R>
where
    R: RpcApiWrapper,
{
    /// Creates a new `Operator`.
    pub async fn new(config: BridgeConfig, rpc: ExtendedRpc<R>) -> Result<Self, BridgeError> {
        // let num_verifiers = config.verifiers_public_keys.len();

        let signer = Actor::new(config.secret_key, config.network);

        let db = OperatorDB::new(config.clone()).await;

        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
            false,
        );
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

        let mut tx = db.begin_transaction().await?;
        // check if funding utxo is already set
        if db.get_funding_utxo(Some(&mut tx)).await?.is_none() {
            let outpoint = rpc.send_to_address(&signer.address, config.bridge_amount_sats * 2)?;
            let funding_utxo = UTXO {
                outpoint,
                txout: TxOut {
                    value: bitcoin::Amount::from_sat(config.bridge_amount_sats * 2),
                    script_pubkey: signer.address.script_pubkey(),
                },
            };
            db.set_funding_utxo(Some(&mut tx), funding_utxo).await?;
        }
        tx.commit().await?;

        let citrea_client = if !config.citrea_rpc_url.is_empty() {
            Some(
                HttpClientBuilder::default()
                    .build(config.citrea_rpc_url.clone())
                    .unwrap(),
            )
        } else {
            None
        };

        Ok(Self {
            rpc,
            db,
            signer,
            config,
            nofn_xonly_pk,
            idx,
            citrea_client,
        })
    }

    /// Public endpoint for every depositor to call.
    ///
    /// It will get signatures from all verifiers:
    ///
    /// 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    /// 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
    /// 3. Create a kickoff transaction but do not broadcast it
    ///
    /// TODO: Create multiple kickoffs in single transaction
    pub async fn new_deposit(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError> {
        tracing::info!(
            "New deposit request for UTXO: {:?}, EVM address: {:?} and recovery taproot address of: {:?}",
            deposit_outpoint,
            evm_address,
            recovery_taproot_address
        );

        // 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
        self.rpc.check_deposit_utxo(
            &self.nofn_xonly_pk,
            &deposit_outpoint,
            &recovery_taproot_address,
            &evm_address,
            self.config.bridge_amount_sats,
            self.config.confirmation_threshold,
            self.config.network,
            self.config.user_takes_after,
        )?;

        let mut tx = self.db.begin_transaction().await?;

        self.db.lock_operators_kickoff_utxo_table(&mut tx).await?;

        // 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
        let kickoff_utxo = self
            .db
            .get_kickoff_utxo(Some(&mut tx), deposit_outpoint)
            .await?;
        // if we already have a kickoff UTXO for this deposit UTXO, return it
        if let Some(kickoff_utxo) = kickoff_utxo {
            tracing::debug!(
                "Kickoff UTXO found: {:?} already exists for deposit UTXO: {:?}",
                kickoff_utxo,
                deposit_outpoint
            );
            let kickoff_sig_hash = crate::sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                kickoff_utxo.outpoint.txid,
                kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            let sig = self
                .signer
                .sign(TapSighash::from_byte_array(kickoff_sig_hash));

            // self.db.unlock_operators_kickoff_utxo_table(&mut tx).await?;
            tx.commit().await?;
            return Ok((kickoff_utxo, sig));
        }

        // Check if we already have an unused kickoff UTXO available
        let unused_kickoff_utxo = self
            .db
            .get_unused_kickoff_utxo_and_increase_idx(Some(&mut tx))
            .await?;
        if let Some(unused_kickoff_utxo) = unused_kickoff_utxo {
            self.db
                .save_kickoff_utxo(Some(&mut tx), deposit_outpoint, unused_kickoff_utxo.clone())
                .await?;

            // self.db.unlock_operators_kickoff_utxo_table(&mut tx).await?;
            tx.commit().await?;

            tracing::debug!(
                "Unused kickoff UTXO found: {:?} found for deposit UTXO: {:?}",
                unused_kickoff_utxo,
                deposit_outpoint
            );
            let kickoff_sig_hash = crate::sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                unused_kickoff_utxo.outpoint.txid,
                unused_kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            let sig = self
                .signer
                .sign(TapSighash::from_byte_array(kickoff_sig_hash));

            Ok((unused_kickoff_utxo, sig))
        } else {
            // 3. Create a kickoff transaction but do not broadcast it

            // To create a kickoff tx, we first need a funding utxo
            let funding_utxo = self.db.get_funding_utxo(Some(&mut tx)).await?.ok_or(
                BridgeError::OperatorFundingUtxoNotFound(self.signer.address.clone()),
            )?;

            // if the amount is not enough, return an error
            // The amount will be calculated as if the transaction has 1 input
            // and (num_kickoff_utxos + 2) outputs where the first k outputs are
            // the kickoff outputs, the penultimante output is the change output,
            // and the last output is the anyonecanpay output for fee bumping.
            let kickoff_tx_min_relay_fee = match self.config.operator_num_kickoff_utxos_per_tx {
                0..=250 => 154 + 43 * self.config.operator_num_kickoff_utxos_per_tx, // Handles all values from 0 to 250
                _ => 156 + 43 * self.config.operator_num_kickoff_utxos_per_tx, // Handles all other values
            };
            if funding_utxo.txout.value.to_sat()
                < (KICKOFF_UTXO_AMOUNT_SATS * self.config.operator_num_kickoff_utxos_per_tx as u64
                    + kickoff_tx_min_relay_fee as u64
                    + 330)
            {
                return Err(BridgeError::OperatorFundingUtxoAmountNotEnough(
                    self.signer.address.clone(),
                ));
            }
            let mut kickoff_tx_handler = TransactionBuilder::create_kickoff_utxo_tx(
                &funding_utxo,
                &self.nofn_xonly_pk,
                &self.signer.xonly_public_key,
                self.config.network,
                self.config.operator_num_kickoff_utxos_per_tx,
            );
            tracing::debug!(
                "Funding UTXO found: {:?} kickoff UTXO is created for deposit UTXO: {:?}",
                funding_utxo,
                deposit_outpoint
            );
            let sig = self
                .signer
                .sign_taproot_pubkey_spend(&mut kickoff_tx_handler, 0, None)?;
            handle_taproot_witness_new(&mut kickoff_tx_handler, &[sig.as_ref()], 0, None)?;
            tracing::debug!(
                "Created kickoff tx with weight: {:#?}",
                kickoff_tx_handler.tx.weight()
            );
            // tracing::debug!(
            //     "Created kickoff tx: {:#?}",
            //     kickoff_tx_handler.tx.raw_hex()
            // );
            // tracing::debug!(
            //     "For operator index: {:?} Kickoff tx handler: {:#?}",
            //     self.idx,
            //     kickoff_tx_handler
            // );

            let change_utxo = UTXO {
                outpoint: OutPoint {
                    txid: kickoff_tx_handler.tx.compute_txid(),
                    vout: self.config.operator_num_kickoff_utxos_per_tx as u32,
                },
                txout: kickoff_tx_handler.tx.output[self.config.operator_num_kickoff_utxos_per_tx]
                    .clone(),
            };
            tracing::debug!(
                "Change UTXO: {:?} after new kickoff UTXOs are generated for deposit UTXO: {:?}",
                change_utxo,
                deposit_outpoint
            );

            let kickoff_utxo = UTXO {
                outpoint: OutPoint {
                    txid: kickoff_tx_handler.tx.compute_txid(),
                    vout: 0,
                },
                txout: kickoff_tx_handler.tx.output[0].clone(),
            };
            tracing::debug!(
                "Kickoff UTXO: {:?} after new kickoff UTXOs are generated for deposit UTXO: {:?}",
                kickoff_utxo,
                deposit_outpoint
            );

            // In a db tx, save the kickoff_utxo for this deposit_outpoint
            // and update the db with the new funding_utxo as the change

            // let db_transaction = self.db.begin_transaction().await?;

            // We save the funding txid and the kickoff txid to be able to track them later
            self.db
                .save_kickoff_utxo(Some(&mut tx), deposit_outpoint, kickoff_utxo.clone())
                .await?;

            self.db
                .add_deposit_kickoff_generator_tx(
                    Some(&mut tx),
                    kickoff_tx_handler.tx.compute_txid(),
                    kickoff_tx_handler.tx.raw_hex(),
                    self.config.operator_num_kickoff_utxos_per_tx,
                    funding_utxo.outpoint.txid,
                )
                .await?;

            self.db.set_funding_utxo(Some(&mut tx), change_utxo).await?;

            tx.commit().await?;

            let kickoff_sig_hash = crate::sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                kickoff_utxo.outpoint.txid,
                kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            let sig = self
                .signer
                .sign(TapSighash::from_byte_array(kickoff_sig_hash));

            Ok((kickoff_utxo, sig))
        }
    }

    /// Checks if utxo is valid, spendable by operator and not spent
    /// Saves the utxo to the db
    async fn set_funding_utxo(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        self.db.set_funding_utxo(None, funding_utxo).await?;
        Ok(())
    }

    async fn is_profitable(
        &self,
        input_amount: u64,
        withdrawal_amount: u64,
    ) -> Result<bool, BridgeError> {
        // Check if the withdrawal amount is within the acceptable range
        if (withdrawal_amount - input_amount) > self.config.bridge_amount_sats {
            Ok(false)
        } else {
            // Calculate net profit after the withdrawal
            let net_profit = self.config.bridge_amount_sats - withdrawal_amount;
            Ok(net_profit > self.config.operator_withdrawal_fee_sats.unwrap())
        }
    }

    async fn new_withdrawal_sig(
        &self,
        withdrawal_idx: u32,
        user_sig: schnorr::Signature,
        input_utxo: UTXO,
        output_txout: TxOut,
    ) -> Result<Txid, BridgeError> {
        if let Some(citrea_client) = &self.citrea_client {
            let params = rpc_params![
                json!({
                    "to": "0x3100000000000000000000000000000000000002",
                    "data": format!("0x471ba1e300000000000000000000000000000000000000000000000000000000{}", hex::encode(withdrawal_idx.to_be_bytes())), // See: https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80
                }),
                "latest"
            ];
            let response: String = citrea_client.request("eth_call", params).await?;
            let txid_response = &response[2..66];
            let txid = hex::decode(txid_response).unwrap();
            // txid.reverse(); // TODO: we should need to reverse this, test this with declareWithdrawalFiller
            let txid = Txid::from_slice(&txid).unwrap();
            if txid != input_utxo.outpoint.txid || 0 != input_utxo.outpoint.vout {
                // TODO: Fix this, vout can be different from 0 as well
                return Err(BridgeError::InvalidInputUTXO(
                    txid,
                    input_utxo.outpoint.txid,
                ));
            }
        }

        if !self
            .is_profitable(input_utxo.txout.value.to_sat(), output_txout.value.to_sat())
            .await?
        {
            return Err(BridgeError::NotEnoughFeeForOperator);
        }
        let tx_ins = TransactionBuilder::create_tx_ins(vec![input_utxo.outpoint]);
        let user_xonly_pk = secp256k1::XOnlyPublicKey::from_slice(
            &input_utxo.txout.script_pubkey.as_bytes()[2..34],
        )?;
        let tx_outs = vec![output_txout.clone()];
        let mut tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        let mut sighash_cache = SighashCache::new(tx.clone());
        let sighash = sighash_cache.taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::One(0, &input_utxo.txout),
            bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
        )?;
        let user_sig_wrapped = bitcoin::taproot::Signature {
            signature: user_sig,
            sighash_type: bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
        };
        tx.input[0].witness.push(user_sig_wrapped.serialize());
        utils::SECP.verify_schnorr(
            &user_sig,
            &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
            &user_xonly_pk,
        )?;
        let mut push_bytes = PushBytesBuf::new();
        push_bytes
            .extend_from_slice(&utils::usize_to_var_len_bytes(self.idx))
            .unwrap();
        let op_return_txout = script_builder::op_return_txout(push_bytes);
        tx.output.push(op_return_txout.clone());
        let funded_tx = self
            .rpc
            .fund_raw_transaction(
                &tx,
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
            )?
            .hex;

        let signed_tx: Transaction = deserialize(
            &self
                .rpc
                .sign_raw_transaction_with_wallet(&funded_tx, None, None)?
                .hex,
        )?;
        let final_txid = self.rpc.send_raw_transaction(&signed_tx)?;
        Ok(final_txid)
    }

    async fn withdrawal_proved_on_citrea(
        &self,
        withdrawal_idx: u32,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<String>, BridgeError> {
        // call withdrawFillers(withdrawal_idx) check the returned id is our operator id.
        // calculate the move_txid, txIdToDepositId(move_txid) check the returned id is withdrawal_idx
        if let Some(citrea_client) = &self.citrea_client {
            let params = rpc_params![
                json!({
                    "to": "0x3100000000000000000000000000000000000002",
                    "data": format!("0xc045577b00000000000000000000000000000000000000000000000000000000{}", hex::encode(withdrawal_idx.to_be_bytes())), // See: https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80
                }),
                "latest"
            ];
            let response: String = citrea_client.request("eth_call", params).await?;
            let operator_idx_response = &response[58..66];
            let operator_idx_as_vec = hex::decode(operator_idx_response).unwrap();
            let operator_idx = u32::from_be_bytes(operator_idx_as_vec.try_into().unwrap());
            if operator_idx - 1 != self.idx as u32 {
                return Err(BridgeError::InvalidOperatorIndex(
                    operator_idx as usize,
                    self.idx,
                ));
            }
        }

        let kickoff_utxo = self
            .db
            .get_kickoff_utxo(None, deposit_outpoint)
            .await?
            .ok_or(BridgeError::KickoffOutpointsNotFound)?;
        tracing::debug!("Kickoff UTXO FOUND: {:?}", kickoff_utxo);
        let mut txs_to_be_sent = vec![];
        let mut current_searching_txid = kickoff_utxo.outpoint.txid;
        let mut found_txid = false;

        for _ in 0..25 {
            // Check if the current txid is onchain or in mempool
            if self
                .rpc
                .get_raw_transaction(&current_searching_txid, None)
                .is_ok()
            {
                found_txid = true;
                break;
            }

            // Fetch the transaction and continue the loop
            let (raw_signed_tx, _, _, funding_txid) = self
                .db
                .get_deposit_kickoff_generator_tx(current_searching_txid)
                .await?
                .ok_or(BridgeError::KickoffOutpointsNotFound)?; // TODO: Fix this error

            txs_to_be_sent.push(raw_signed_tx);
            current_searching_txid = funding_txid;
        }

        // Handle the case where no transaction was found in 25 iterations
        if !found_txid {
            return Err(BridgeError::KickoffOutpointsNotFound); // TODO: Fix this error
        }
        // tracing::debug!("Found txs to be sent: {:?}", txs_to_be_sent);

        let mut slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
            deposit_outpoint,
            kickoff_utxo.clone(),
            &self.signer.xonly_public_key,
            self.idx,
            &self.nofn_xonly_pk,
            self.config.network,
            self.config.user_takes_after,
            self.config.operator_takes_after,
            self.config.bridge_amount_sats,
        );

        let slash_or_take_utxo = UTXO {
            outpoint: OutPoint {
                txid: slash_or_take_tx_handler.tx.compute_txid(),
                vout: 0,
            },
            txout: slash_or_take_tx_handler.tx.output[0].clone(),
        };

        // tracing::debug!(
        //     "Created slash or take tx handler: {:#?}",
        //     slash_or_take_tx_handler
        // );
        let nofn_sig = self
            .db
            .get_slash_or_take_sig(deposit_outpoint, kickoff_utxo.clone())
            .await?
            .ok_or(BridgeError::KickoffOutpointsNotFound)?; // TODO: Fix this error

        // tracing::debug!("Found nofn sig: {:?}", nofn_sig);

        let our_sig =
            self.signer
                .sign_taproot_script_spend_tx_new(&mut slash_or_take_tx_handler, 0, 0)?;
        // tracing::debug!("slash_or_take_tx_handler: {:#?}", slash_or_take_tx_handler);
        handle_taproot_witness_new(
            &mut slash_or_take_tx_handler,
            &[our_sig.as_ref(), nofn_sig.as_ref()],
            0,
            Some(0),
        )?;

        txs_to_be_sent.push(slash_or_take_tx_handler.tx.raw_hex());

        tracing::debug!(
            "Found txs to be sent with slash_or_take_tx: {:?}",
            txs_to_be_sent
        );

        let move_tx_handler = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            &EVMAddress([0u8; 20]),
            Address::p2tr(
                &utils::SECP,
                *utils::UNSPENDABLE_XONLY_PUBKEY,
                None,
                self.config.network,
            )
            .as_unchecked(),
            &self.nofn_xonly_pk,
            self.config.network,
            self.config.user_takes_after,
            self.config.bridge_amount_sats,
        );
        let bridge_fund_outpoint = OutPoint {
            txid: move_tx_handler.tx.compute_txid(),
            vout: 0,
        };

        let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
            bridge_fund_outpoint,
            slash_or_take_utxo,
            &self.signer.xonly_public_key,
            &self.nofn_xonly_pk,
            self.config.network,
            self.config.operator_takes_after,
            self.config.bridge_amount_sats,
            self.config.operator_wallet_addresses[self.idx].clone(),
        );

        let operator_takes_nofn_sig = self
            .db
            .get_operator_take_sig(deposit_outpoint, kickoff_utxo)
            .await?
            .ok_or(BridgeError::KickoffOutpointsNotFound)?; // TODO: Fix this error
        tracing::debug!("Operator Found nofn sig: {:?}", operator_takes_nofn_sig);

        let our_sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut operator_takes_tx, 1, 0)?;

        handle_taproot_witness_new(
            &mut operator_takes_tx,
            &[operator_takes_nofn_sig.as_ref()],
            0,
            None,
        )?;
        handle_taproot_witness_new(&mut operator_takes_tx, &[our_sig.as_ref()], 1, Some(0))?;

        txs_to_be_sent.push(operator_takes_tx.tx.raw_hex());

        // let input_0_sighash = Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0)?;
        // let input_0_message = Message::from_digest_slice(input_0_sighash.as_byte_array())?;
        // tracing::debug!("Trying to verify signatures for operator_takes_tx");
        // let res_0 = utils::SECP.verify_schnorr(
        //     &operator_takes_nofn_sig,
        //     &input_0_message,
        //     &self.nofn_xonly_pk,
        // )?;
        // tracing::debug!("Signature verified successfully for input 0!");

        // let input_1_sighash =
        //     Actor::convert_tx_to_sighash_script_spend(&mut operator_takes_tx, 1, 0)?;
        // let input_1_message = Message::from_digest_slice(input_1_sighash.as_byte_array())?;
        // let res_1 = utils::SECP.verify_schnorr(
        //     &our_sig,
        //     &input_1_message,
        //     &self.signer.xonly_public_key,
        // )?;
        // tracing::debug!("Signature verified successfully for input 1!");

        // tracing::debug!(
        //     "Found txs to be sent with operator_takes_tx: {:?}",
        //     txs_to_be_sent
        // );
        // let kickoff_txid = self
        //     .rpc
        //     .send_raw_transaction(&deserialize_hex(&txs_to_be_sent[0])?)?;
        // tracing::debug!("Kickoff txid: {:?}", kickoff_txid);
        // let slash_or_take_txid = self
        //     .rpc
        //     .send_raw_transaction(&deserialize_hex(&txs_to_be_sent[1])?)?;
        // tracing::debug!("Slash or take txid: {:?}", slash_or_take_txid);
        // let operator_takes_tx: Transaction = deserialize_hex(&txs_to_be_sent[2])?;
        // tracing::debug!("Operator takes tx: {:#?}", operator_takes_tx);
        // let operator_takes_txid = self.rpc.send_raw_transaction(&operator_takes_tx)?;
        // tracing::debug!("Operator takes txid: {:?}", operator_takes_txid);
        Ok(txs_to_be_sent)
    }
}

#[async_trait]
impl<R> OperatorRpcServer for Operator<R>
where
    R: RpcApiWrapper,
{
    async fn new_deposit_rpc(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError> {
        self.new_deposit(deposit_outpoint, recovery_taproot_address, evm_address)
            .await
    }

    async fn set_funding_utxo_rpc(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        self.set_funding_utxo(funding_utxo).await
    }

    async fn new_withdrawal_sig_rpc(
        &self,
        withdrawal_idx: u32,
        user_sig: schnorr::Signature,
        input_utxo: UTXO,
        output_txout: TxOut,
    ) -> Result<Txid, BridgeError> {
        self.new_withdrawal_sig(withdrawal_idx, user_sig, input_utxo, output_txout)
            .await
    }

    async fn withdrawal_proved_on_citrea_rpc(
        &self,
        withdrawal_idx: u32,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<String>, BridgeError> {
        self.withdrawal_proved_on_citrea(withdrawal_idx, deposit_outpoint)
            .await
    }
}
