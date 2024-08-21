use std::borrow::Borrow;
use std::mem::swap;

use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::operator::OperatorDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::traits::rpc::OperatorRpcServer;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::parse_hex_to_btc_tx;
use crate::{script_builder, utils, EVMAddress, UTXO};
use ::musig2::secp::Point;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, OutPoint, TapSighash, Transaction, TxOut, Txid};
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::json::SigHashType;
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
}

impl<R> Operator<R>
where
    R: RpcApiWrapper,
{
    /// Creates a new `Operator`.
    pub async fn new(config: BridgeConfig, rpc: ExtendedRpc<R>) -> Result<Self, BridgeError> {
        let num_verifiers = config.verifiers_public_keys.len();

        let signer = Actor::new(config.secret_key, config.network);
        if signer.public_key != config.verifiers_public_keys[num_verifiers - 1] {
            return Err(BridgeError::InvalidOperatorKey);
        }

        let db = OperatorDB::new(config.clone()).await;

        let key_agg_context =
            musig2::create_key_agg_ctx(config.verifiers_public_keys.clone(), None)?;
        let agg_point: Point = key_agg_context.aggregated_pubkey_untweaked();
        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_slice(&agg_point.serialize_xonly())?;

        Ok(Self {
            rpc,
            db,
            signer,
            config,
            nofn_xonly_pk,
        })
    }

    /// Public endpoint for every depositor to call.
    ///
    /// It will get signatures from all verifiers:
    ///
    /// 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    /// 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
    /// 3. Create a kickoff transaction but do not broadcast it
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
            self.config.user_takes_after,
            self.config.confirmation_treshold,
            self.config.network,
        )?;

        // 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
        let kickoff_utxo = self.db.get_kickoff_utxo(deposit_outpoint).await?;

        // if we already have a kickoff UTXO for this deposit UTXO, return it
        if let Some(kickoff_utxo) = kickoff_utxo {
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

        let kickoff_tx_handler =
            TransactionBuilder::create_kickoff_tx(&funding_utxo, &self.signer.address);

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
    async fn set_operator_funding_utxo(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
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
        // let user_xonly_pk = secp256k1::XOnlyPublicKey::from_slice(
        //     &input_utxo.txout.script_pubkey.as_bytes()[2..34],
        // )?;
        let tx_outs = vec![output_txout];
        let mut tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        // let mut sighash_cache = SighashCache::new(tx.clone());
        // let sighash = sighash_cache.taproot_key_spend_signature_hash(
        //     0,
        //     &bitcoin::sighash::Prevouts::One(0, &input_utxo.txout),
        //     bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
        // )?;
        tx.input[0].witness.push(user_sig.as_ref());

        tx.verify(|_| Some(input_utxo.txout.clone())).unwrap();
        // utils::SECP.verify_schnorr(
        //     &user_sig,
        //     &Message::from_digest_slice(sighash.as_byte_array()).expect("should be hash"),
        //     &user_xonly_pk,
        // )?;
        let op_return_txout = script_builder::op_return_txout(5u32.to_be_bytes()); // TODO: Instead of 5u32 use the index of the operator.
        tx.output.push(op_return_txout.clone());
        let mut funded_tx: Transaction =
            deserialize(&self.rpc.fundrawtransaction(&tx, None, None)?.hex)?;
        // OP_RETURN should be the last output
        if funded_tx.output[funded_tx.output.len() - 1] != op_return_txout.clone() {
            // it should be one previous to the last
            if funded_tx.output[funded_tx.output.len() - 2] != op_return_txout {
                return Err(BridgeError::TxInputNotFound); // TODO: Fix ths error
            }

            let len = funded_tx.output.len();
            if len >= 2 {
                let (left, right) = funded_tx.output.split_at_mut(len - 1);
                swap(&mut left[len - 2], &mut right[0]);
            }
        }
        let signed_tx: Transaction = deserialize(
            &self
                .rpc
                .sign_raw_transaction_with_wallet(&funded_tx, None, None)?
                .hex,
        )?;
        self.rpc.send_raw_transaction(&signed_tx)?;
        Ok(Some(signed_tx.compute_txid()))
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

    async fn set_operator_funding_utxo_rpc(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        self.set_operator_funding_utxo(funding_utxo).await
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
}
