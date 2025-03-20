//! # Extended Remote Procedure Call
//!
//! This module provides helpful functions for Bitcoin RPC.

use std::str::FromStr;
use std::sync::Arc;

use crate::builder;
use crate::errors::BridgeError;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use eyre::Context;

#[derive(Debug, Clone)]
pub struct ExtendedRpc {
    pub url: String,
    auth: Auth,
    pub client: Arc<Client>,
}

impl ExtendedRpc {
    /// Connects to Bitcoin RPC and returns a new `ExtendedRpc`.
    pub async fn connect(url: String, user: String, password: String) -> Result<Self, BridgeError> {
        let auth = Auth::UserPass(user, password);

        let rpc = Client::new(&url, auth.clone())
            .await
            .wrap_err("Failed to connect to Bitcoin RPC")?;

        Ok(Self {
            url,
            auth,
            client: Arc::new(rpc),
        })
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        let raw_transaction_results = self
            .client
            .get_raw_transaction_info(txid, None)
            .await
            .wrap_err("Failed to get transaction info")?;

        raw_transaction_results
            .confirmations
            .ok_or(BridgeError::NoConfirmationData)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_blockhash_of_tx(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<bitcoin::BlockHash, BridgeError> {
        let raw_transaction_results = self
            .client
            .get_raw_transaction_info(txid, None)
            .await
            .wrap_err("Failed to get transaction info")?;
        let Some(blockhash) = raw_transaction_results.blockhash else {
            return Err(BridgeError::TransactionNotConfirmed(*txid));
        };
        Ok(blockhash)
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
            .await
            .wrap_err("Failed to get transaction")?;

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
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
            .await
            .wrap_err("Failed to get transaction output")?;

        Ok(res.is_none())
    }

    /// Mines blocks to a new address.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn mine_blocks(&self, block_num: u64) -> Result<Vec<BlockHash>, BridgeError> {
        let new_address = self
            .client
            .get_new_address(None, None)
            .await
            .wrap_err("Failed to get new address")?
            .assume_checked();

        Ok(self
            .client
            .generate_to_address(block_num, &new_address)
            .await
            .wrap_err("Failed to generate to address")?)
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
            .await
            .wrap_err("Failed to send to address")?;

        let tx_result = self
            .client
            .get_transaction(&txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        let vout = tx_result.details[0].vout; // TODO: this might be incorrect

        Ok(OutPoint { txid, vout })
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_txout_from_outpoint(&self, outpoint: &OutPoint) -> Result<TxOut, BridgeError> {
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
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
    ) -> Result<(), eyre::Report> {
        if self.confirmation_blocks(&deposit_outpoint.txid).await? < confirmation_block_count {
            eyre::bail!("Deposit not finalized");
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
            eyre::bail!("Invalid deposit UTXO");
        }

        if self.is_utxo_spent(deposit_outpoint).await? {
            eyre::bail!("Deposit UTXO has already spent");
        }

        Ok(())
    }

    /// Bumps the fee of a transaction with a given fee rate.
    /// Returns the txid of the bumped transaction.
    pub async fn bump_fee_with_fee_rate(
        &self,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> Result<Txid, BridgeError> {
        let transaction_info = self
            .client
            .get_transaction(&txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        if transaction_info.info.blockhash.is_some() {
            return Err(BridgeError::TransactionAlreadyInBlock(
                transaction_info
                    .info
                    .blockhash
                    .expect("Blockhash should be present"),
            ));
        }
        let tx = transaction_info
            .transaction()
            .wrap_err("Failed to get transaction")?;
        let tx_size = tx.weight().to_vbytes_ceil();
        let current_fee_sat = u64::try_from(
            -transaction_info
                .fee
                .expect("Fee should be present")
                .to_sat(),
        )
        .wrap_err("Failed to convert fee to sat")?;
        let current_fee_rate = FeeRate::from_sat_per_kwu(1000 * current_fee_sat / tx_size);
        if current_fee_rate >= fee_rate {
            return Ok(txid);
        }
        let network_info = self
            .client
            .get_network_info()
            .await
            .wrap_err("Failed to get network info")?;
        let incremental_fee = network_info.incremental_fee;
        let incremental_fee_rate: FeeRate = FeeRate::from_sat_per_kwu(incremental_fee.to_sat());
        let new_fee_rate = FeeRate::from_sat_per_kwu(
            current_fee_rate.to_sat_per_kwu() + incremental_fee_rate.to_sat_per_kwu(),
        );
        let bump_fee_result = match self
            .client
            .bump_fee(
                &txid,
                Some(&bitcoincore_rpc::json::BumpFeeOptions {
                    fee_rate: Some(bitcoincore_rpc::json::FeeRate::per_vbyte(Amount::from_sat(
                        new_fee_rate.to_sat_per_vb_ceil(),
                    ))),
                    replaceable: Some(true),
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(bump_fee_result) => bump_fee_result,
            Err(e) => match e {
                bitcoincore_rpc::Error::JsonRpc(json_rpc_error) => match json_rpc_error {
                    bitcoincore_rpc::RpcError::Rpc(rpc_error) => {
                        if rpc_error.message.ends_with(" is already spent") {
                            let outpoint_str = rpc_error
                                .message
                                .split(" is already spent")
                                .next()
                                .expect("Outpoint string should be present");
                            let outpoint = OutPoint::from_str(outpoint_str).map_err(|e| {
                                BridgeError::BumpFeeError(
                                    txid,
                                    fee_rate,
                                    format!(
                                        "Failed to parse an outpoint from {}: {}",
                                        outpoint_str, e
                                    ),
                                )
                            })?;

                            return Err(BridgeError::BumpFeeUTXOSpent(outpoint));
                        }

                        return Err(BridgeError::BumpFeeError(txid, fee_rate, rpc_error.message));
                    }
                    _ => {
                        return Err(BridgeError::BumpFeeError(
                            txid,
                            fee_rate,
                            json_rpc_error.to_string(),
                        ))
                    }
                },
                _ => return Err(BridgeError::BumpFeeError(txid, fee_rate, e.to_string())),
            },
        };

        bump_fee_result.txid.ok_or({
            BridgeError::BumpFeeError(
                txid,
                fee_rate,
                "Can't get Txid from bump_fee_result".to_string(),
            )
        })
    }

    pub async fn clone_inner(&self) -> Result<Self, bitcoincore_rpc::Error> {
        let new_client = Client::new(&self.url, self.auth.clone()).await?;

        Ok(Self {
            url: self.url.clone(),
            auth: self.auth.clone(),
            client: Arc::new(new_client),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}
