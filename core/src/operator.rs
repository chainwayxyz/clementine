use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::operator::OperatorDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::traits::rpc::OperatorRpcServer;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::handle_taproot_witness_new;
use crate::{script_builder, utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, OutPoint, TapSighash, Transaction, TxOut, Txid};
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::RawTx;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_circuits::sha256_hash;
use jsonrpsee::core::async_trait;
use secp256k1::{schnorr, Message};

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
            .unwrap();

        Ok(Self {
            rpc,
            db,
            signer,
            config,
            nofn_xonly_pk,
            idx,
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
            BRIDGE_AMOUNT_SATS,
            self.config.confirmation_threshold,
            self.config.network,
        )?;

        // 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
        let kickoff_utxo = self.db.get_kickoff_utxo(deposit_outpoint).await?;

        tracing::debug!(
            "Kickoff UTXO for deposit UTXO: {:?} is: {:?}",
            deposit_outpoint,
            kickoff_utxo
        );
        // if we already have a kickoff UTXO for this deposit UTXO, return it
        if let Some(kickoff_utxo) = kickoff_utxo {
            tracing::debug!(
                "Kickoff UTXO already exists for deposit UTXO: {:?}",
                deposit_outpoint
            );
            let kickoff_sig_hash = sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                kickoff_utxo.outpoint.txid,
                kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            let sig = self
                .signer
                .sign(TapSighash::from_byte_array(kickoff_sig_hash));

            return Ok((kickoff_utxo, sig));
        }
        // TODO: Later we can check if we have unused kickkoff UTXOs and use them instead of creating a new one
        // 3. Create a kickoff transaction but do not broadcast it

        // To create a kickoff tx, we first need a funding utxo
        let funding_utxo =
            self.db
                .get_funding_utxo()
                .await?
                .ok_or(BridgeError::OperatorFundingUtxoNotFound(
                    self.signer.address.clone(),
                ))?;

        // if the amount is not enough, return an error
        if funding_utxo.txout.value.to_sat() < 150_000 {
            // TODO: Change this amount
            return Err(BridgeError::OperatorFundingUtxoAmountNotEnough(
                self.signer.address.clone(),
            ));
        }

        let mut kickoff_tx_handler = TransactionBuilder::create_kickoff_utxo_tx(
            &funding_utxo,
            &self.nofn_xonly_pk,
            &self.signer.xonly_public_key,
            self.config.network,
        );
        let sig = self
            .signer
            .sign_taproot_pubkey_spend(&mut kickoff_tx_handler, 0, None)?;
        handle_taproot_witness_new(&mut kickoff_tx_handler, &[sig.as_ref()], 0, None)?;

        // tracing::debug!(
        //     "For operator index: {:?} Kickoff tx handler: {:#?}",
        //     self.idx,
        //     kickoff_tx_handler
        // );

        let change_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_tx_handler.tx.compute_txid(),
                vout: 1, // TODO: This will equal to the number of kickoff_outputs in the kickoff tx
            },
            txout: kickoff_tx_handler.tx.output[1].clone(),
        };

        let kickoff_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_tx_handler.tx.compute_txid(),
                vout: 0,
            },
            txout: kickoff_tx_handler.tx.output[0].clone(),
        };

        let kickoff_sig_hash = sha256_hash!(
            deposit_outpoint.txid,
            deposit_outpoint.vout.to_be_bytes(),
            kickoff_utxo.outpoint.txid,
            kickoff_utxo.outpoint.vout.to_be_bytes()
        );

        let sig = self
            .signer
            .sign(TapSighash::from_byte_array(kickoff_sig_hash));

        // In a db tx, save the kickoff_utxo for this deposit_utxo
        // and update the db with the new funding_utxo as the change

        let transaction = self.db.begin_transaction().await?;

        // We save the funding txid and the kickoff txid to be able to track them later
        self.db
            .save_kickoff_utxo(deposit_outpoint, kickoff_utxo.clone())
            .await?;

        self.db
            .add_deposit_kickoff_generator_tx(
                kickoff_tx_handler.tx.compute_txid(),
                kickoff_tx_handler.tx.raw_hex(),
                1,
                1,
                funding_utxo.outpoint.txid,
            )
            .await?;

        self.db.set_funding_utxo(change_utxo).await?;

        transaction.commit().await?;

        Ok((kickoff_utxo, sig))
    }

    /// Checks if utxo is valid, spendable by operator and not spent
    /// Saves the utxo to the db
    async fn set_funding_utxo(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        self.db.set_funding_utxo(funding_utxo).await?;
        Ok(())
    }

    async fn is_profitable(&self, _withdrawal_idx: usize) -> Result<bool, BridgeError> {
        // check that withdrawal_idx has the input_utxo.outpoint
        // call is_profitable
        // if is profitable, pay the withdrawal
        // TODO: Implement this
        Ok(true)
    }

    async fn new_withdrawal_sig(
        &self,
        withdrawal_idx: usize,
        user_sig: schnorr::Signature,
        input_utxo: UTXO,
        output_txout: TxOut,
    ) -> Result<Option<Txid>, BridgeError> {
        // TODO: check that withdrawal_idx has the input_utxo.outpoint

        if !self.is_profitable(withdrawal_idx).await? {
            return Ok(None);
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
        let op_return_txout = script_builder::op_return_txout(self.idx.to_be_bytes());
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
        Ok(Some(final_txid))
    }

    async fn withdrawal_proved_on_citrea(
        &self,
        _withdrawal_idx: usize,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<String>, BridgeError> {
        let kickoff_utxo = self
            .db
            .get_kickoff_utxo(deposit_outpoint)
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
        deposit_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError> {
        self.new_deposit(deposit_utxo, recovery_taproot_address, evm_address)
            .await
    }

    async fn set_funding_utxo_rpc(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        self.set_funding_utxo(funding_utxo).await
    }

    async fn new_withdrawal_sig_rpc(
        &self,
        withdrawal_idx: usize,
        user_sig: schnorr::Signature,
        input_utxo: UTXO,
        output_txout: TxOut,
    ) -> Result<Option<Txid>, BridgeError> {
        self.new_withdrawal_sig(withdrawal_idx, user_sig, input_utxo, output_txout)
            .await
    }

    async fn withdrawal_proved_on_citrea_rpc(
        &self,
        withdrawal_idx: usize,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<String>, BridgeError> {
        self.withdrawal_proved_on_citrea(withdrawal_idx, deposit_outpoint)
            .await
    }
}
