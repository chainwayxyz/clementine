//! # Extended Remote Procedure Call
//!
//! This module provides helpful functions for Bitcoin RPC.

use crate::builder;
use crate::errors::BridgeError;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

#[derive(Debug)]
pub struct ExtendedRpc {
    url: String,
    auth: Auth,
    pub client: Client,
}

impl ExtendedRpc {
    /// Connects to Bitcoin RPC and returns a new `ExtendedRpc`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot connect to Bitcoin RPC.
    pub async fn new(url: String, user: String, password: String) -> Self {
        let auth = Auth::UserPass(user, password);

        let rpc = Client::new(&url, auth.clone())
            .await
            .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

        Self {
            url,
            auth,
            client: rpc,
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        let raw_transaction_results = self.client.get_raw_transaction_info(txid, None).await?;

        raw_transaction_results
            .confirmations
            .ok_or(BridgeError::NoConfirmationData)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: Amount,
    ) -> Result<bool, BridgeError> {
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await?;

        let current_output = tx.output[outpoint.vout as usize].clone();

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: amount_sats,
        };

        Ok(expected_output == current_output)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError> {
        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
            .await?;

        Ok(res.is_none())
    }

    /// Mines blocks to a new address.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn mine_blocks(&self, block_num: u64) -> Result<Vec<BlockHash>, BridgeError> {
        let new_address = self
            .client
            .get_new_address(None, None)
            .await?
            .assume_checked();

        Ok(self
            .client
            .generate_to_address(block_num, &new_address)
            .await?)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint, BridgeError> {
        let txid = self
            .client
            .send_to_address(address, amount_sats, None, None, None, None, None, None)
            .await?;

        let tx_result = self.client.get_transaction(&txid, None).await?;
        let vout = tx_result.details[0].vout;

        Ok(OutPoint { txid, vout })
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_txout_from_outpoint(&self, outpoint: &OutPoint) -> Result<TxOut, BridgeError> {
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await?;
        let txout = tx.output[outpoint.vout as usize].clone();

        Ok(txout)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn check_deposit_utxo(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        amount_sats: Amount,
        confirmation_block_count: u32,
        network: bitcoin::Network,
        user_takes_after: u16,
    ) -> Result<(), BridgeError> {
        if self.confirmation_blocks(&deposit_outpoint.txid).await? < confirmation_block_count {
            return Err(BridgeError::DepositNotFinalized);
        }

        let (deposit_address, _) = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            recovery_taproot_address,
            evm_address,
            amount_sats,
            network,
            user_takes_after,
        )?;

        if !self
            .check_utxo_address_and_amount(
                deposit_outpoint,
                &deposit_address.script_pubkey(),
                amount_sats,
            )
            .await?
        {
            return Err(BridgeError::InvalidDepositUTXO);
        }

        if self.is_utxo_spent(deposit_outpoint).await? {
            return Err(BridgeError::UTXOSpent);
        }

        Ok(())
    }
}

impl Clone for ExtendedRpc {
    fn clone(&self) -> Self {
        let new_client = futures::executor::block_on(Client::new(&self.url, self.auth.clone()))
            .unwrap_or_else(|e| panic!("Failed to clone Bitcoin RPC client: {}", e));

        Self {
            url: self.url.clone(),
            auth: self.auth.clone(),
            client: new_client,
        }
    }
}
