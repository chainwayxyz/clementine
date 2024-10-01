//! # Extended Remote Procedure Call
//!
//! This module provides helpful functions for Bitcoin RPC.

use crate::builder;
use crate::errors::BridgeError;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::Auth;

#[derive(Debug)]
pub struct ExtendedRpc<R> {
    url: String,
    auth: Auth,
    pub client: R,
}

impl<R> ExtendedRpc<R>
where
    R: RpcApiWrapper,
{
    /// Connects to Bitcoin RPC and returns a new `ExtendedRpc`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot connect to Bitcoin RPC.
    pub fn new(url: String, user: String, password: String) -> Self {
        let auth = Auth::UserPass(user, password);

        let rpc = R::new(&url, auth.clone())
            .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

        Self {
            url,
            auth,
            client: rpc,
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        let raw_transaction_results = self.client.get_raw_transaction_info(txid, None)?;

        raw_transaction_results
            .confirmations
            .ok_or(BridgeError::NoConfirmationData)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: Amount,
    ) -> Result<bool, BridgeError> {
        let tx = self.client.get_raw_transaction(&outpoint.txid, None)?;

        let current_output = tx.output[outpoint.vout as usize].clone();

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: amount_sats,
        };

        Ok(expected_output == current_output)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError> {
        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))?;

        Ok(res.is_none())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn mine_blocks(&self, block_num: u64) -> Result<(), BridgeError> {
        let new_address = self.client.get_new_address(None, None)?.assume_checked();

        self.client.generate_to_address(block_num, &new_address)?;

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint, BridgeError> {
        let txid = self.client.send_to_address(
            address,
            amount_sats,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        let tx_result = self.client.get_transaction(&txid, None)?;
        let vout = tx_result.details[0].vout;

        Ok(OutPoint { txid, vout })
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn get_txout_from_outpoint(&self, outpoint: &OutPoint) -> Result<TxOut, BridgeError> {
        let tx = self.client.get_raw_transaction(&outpoint.txid, None)?;
        let txout = tx.output[outpoint.vout as usize].clone();

        Ok(txout)
    }

    // Following methods are just wrappers around the bitcoincore_rpc::Client methods
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn fund_raw_transaction(
        &self,
        tx: &Transaction,
        options: Option<&bitcoincore_rpc::json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::FundRawTransactionResult, bitcoincore_rpc::Error> {
        self.client.fund_raw_transaction(tx, options, is_witness)
    }

    #[tracing::instrument(skip(self, tx, sighash_type), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn sign_raw_transaction_with_wallet<T: bitcoincore_rpc::RawTx>(
        &self,
        tx: T,
        utxos: Option<&[bitcoincore_rpc::json::SignRawTransactionInput]>,
        sighash_type: Option<bitcoincore_rpc::json::SigHashType>,
    ) -> Result<bitcoincore_rpc::json::SignRawTransactionResult, bitcoincore_rpc::Error> {
        self.client
            .sign_raw_transaction_with_wallet(tx, utxos, sighash_type)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin::Transaction, bitcoincore_rpc::Error> {
        self.client.get_raw_transaction(txid, block_hash)
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn send_raw_transaction<T: bitcoincore_rpc::RawTx>(
        &self,
        tx: T,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error> {
        self.client.send_raw_transaction(tx)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub fn check_deposit_utxo(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        amount_sats: Amount,
        confirmation_block_count: u32,
        network: bitcoin::Network,
        user_takes_after: u32,
    ) -> Result<(), BridgeError> {
        if self.confirmation_blocks(&deposit_outpoint.txid)? < confirmation_block_count {
            return Err(BridgeError::DepositNotFinalized);
        }

        let (deposit_address, _) = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            recovery_taproot_address,
            evm_address,
            amount_sats,
            network,
            user_takes_after,
        );

        if !self.check_utxo_address_and_amount(
            deposit_outpoint,
            &deposit_address.script_pubkey(),
            amount_sats,
        )? {
            return Err(BridgeError::InvalidDepositUTXO);
        }

        if self.is_utxo_spent(deposit_outpoint)? {
            return Err(BridgeError::UTXOSpent);
        }

        Ok(())
    }
}

impl<R> Clone for ExtendedRpc<R>
where
    R: RpcApiWrapper,
{
    fn clone(&self) -> Self {
        let new_client = R::new(&self.url, self.auth.clone())
            .unwrap_or_else(|e| panic!("Failed to clone Bitcoin RPC client: {}", e));

        Self {
            url: self.url.clone(),
            auth: self.auth.clone(),
            client: new_client,
        }
    }
}
