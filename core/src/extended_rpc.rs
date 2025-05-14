//! # Extended Remote Procedure Call
//!
//! This module provides helpful functions for Bitcoin RPC.

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use eyre::Context;
use eyre::OptionExt;

/// Extended RPC client that provides additional functionality beyond the standard Bitcoin Core RPC.
#[derive(Debug, Clone)]
pub struct ExtendedRpc {
    pub url: String,
    auth: Auth,
    pub client: Arc<Client>,
}

/// Errors that can occur during Bitcoin RPC operations.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinRPCError {
    #[error("Failed to bump fee for Txid of {0} and feerate of {1}")]
    BumpFeeError(Txid, FeeRate),
    #[error("Failed to bump fee: UTXO is already spent")]
    BumpFeeUTXOSpent(OutPoint),
    #[error("Transaction is already in block: {0}")]
    TransactionAlreadyInBlock(BlockHash),

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

type Result<T> = std::result::Result<T, BitcoinRPCError>;

impl ExtendedRpc {
    /// Connects to Bitcoin RPC and returns a new `ExtendedRpc`.
    pub async fn connect(url: String, user: String, password: String) -> Result<Self> {
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

    /// Returns the number of confirmations for a transaction.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID to check
    ///
    /// # Returns
    /// The number of confirmations for the transaction, or an error if the transaction cannot be found.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32> {
        let raw_transaction_results = self
            .client
            .get_raw_transaction_info(txid, None)
            .await
            .wrap_err("Failed to get transaction info")?;

        raw_transaction_results
            .confirmations
            .ok_or_eyre("No confirmation data")
            .map_err(Into::into)
    }

    pub async fn get_current_chain_height(&self) -> Result<u32> {
        let height = self
            .client
            .get_block_count()
            .await
            .wrap_err("Failed to get block count")?;
        Ok(u32::try_from(height).wrap_err("Failed to convert block count to u32")?)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_blockhash_of_tx(&self, txid: &bitcoin::Txid) -> Result<bitcoin::BlockHash> {
        let raw_transaction_results = self
            .client
            .get_raw_transaction_info(txid, None)
            .await
            .wrap_err("Failed to get transaction info")?;
        let Some(blockhash) = raw_transaction_results.blockhash else {
            return Err(eyre::eyre!("Transaction not confirmed: {0}", txid).into());
        };
        Ok(blockhash)
    }

    pub async fn get_block_header_by_height(
        &self,
        height: u64,
    ) -> Result<(bitcoin::BlockHash, bitcoin::block::Header)> {
        let block_hash = self.client.get_block_hash(height).await.wrap_err(format!(
            "Couldn't retrieve block hash from height {} from rpc",
            height
        ))?;
        let block_header = self
            .client
            .get_block_header(&block_hash)
            .await
            .wrap_err(format!(
                "Couldn't retrieve block header with block hash {} from rpc",
                block_hash
            ))?;
        Ok((block_hash, block_header))
    }

    /// Gets the transactions that created the inputs of a given transaction.
    ///
    /// # Arguments
    /// * `tx` - The transaction to get the previous transactions for
    ///
    /// # Returns
    /// A vector of transactions that created the inputs of the given transaction.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_prevout_txs(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<Vec<bitcoin::Transaction>> {
        let mut prevout_txs = Vec::new();
        for input in &tx.input {
            let txid = input.previous_output.txid;
            prevout_txs.push(self.get_tx_of_txid(&txid).await?);
        }
        Ok(prevout_txs)
    }

    /// Gets the transaction data for a given transaction ID.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID to retrieve
    ///
    /// # Returns
    /// The transaction data, or an error if the transaction cannot be found.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_tx_of_txid(&self, txid: &bitcoin::Txid) -> Result<bitcoin::Transaction> {
        let raw_transaction = self
            .client
            .get_raw_transaction(txid, None)
            .await
            .wrap_err("Failed to get raw transaction")?;
        Ok(raw_transaction)
    }

    pub async fn is_txid_in_chain(&self, txid: &bitcoin::Txid) -> Result<bool> {
        Ok(self
            .client
            .get_raw_transaction_info(txid, None)
            .await
            .ok()
            .and_then(|s| s.blockhash)
            .is_some())
    }

    /// Checks if a UTXO has the expected address and amount.
    ///
    /// # Arguments
    /// * `outpoint` - The outpoint to check
    /// * `address` - The expected script pubkey
    /// * `amount_sats` - The expected amount in satoshis
    ///
    /// # Returns
    /// `true` if the UTXO has the expected address and amount, `false` otherwise.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: Amount,
    ) -> Result<bool> {
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
    pub async fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool> {
        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
            .await
            .wrap_err("Failed to get transaction output")?;

        Ok(res.is_none())
    }

    /// Mines a specified number of blocks to a new address.
    ///
    /// This is primarily for testing purposes in regtest mode.
    ///
    /// # Arguments
    /// * `block_num` - The number of blocks to mine
    ///
    /// # Returns
    /// A vector of block hashes for the newly mined blocks.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[cfg(test)]
    pub async fn mine_blocks(&self, block_num: u64) -> Result<Vec<BlockHash>> {
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

    /// Sends a specified amount of bitcoin to a given address.
    ///
    /// # Arguments
    /// * `address` - The recipient address
    /// * `amount_sats` - The amount to send in satoshis
    ///
    /// # Returns
    /// The outpoint (txid and vout) of the newly created output.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint> {
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

    /// Retrieves the transaction output for a given outpoint.
    ///
    /// # Arguments
    /// * `outpoint` - The outpoint (txid and vout) to retrieve
    ///
    /// # Returns
    /// The transaction output at the specified outpoint.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_txout_from_outpoint(&self, outpoint: &OutPoint) -> Result<TxOut> {
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        let txout = tx.output[outpoint.vout as usize].clone();

        Ok(txout)
    }

    /// Bumps the fee of a transaction to meet or exceed a target fee rate. Does
    /// nothing if the transaction is already confirmed. Returns the original
    /// txid if no bump was needed.
    ///
    /// This function implements Replace-By-Fee (RBF) to increase the fee of an unconfirmed transaction.
    /// It works as follows:
    /// 1. If the transaction is already confirmed, returns Err(TransactionAlreadyInBlock)
    /// 2. If the current fee rate is already >= the requested fee rate, returns the original txid
    /// 3. Otherwise, increases the fee rate by adding the node's incremental fee to the current fee rate, then `bump_fee`s the transaction
    ///
    /// Note: This function currently only supports fee payer TXs.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID to bump
    /// * `fee_rate` - The target fee rate to achieve
    ///
    /// # Returns
    /// The txid of the bumped transaction (which may be the same as the input txid if no bump was needed).
    ///
    /// # Errors
    /// * `TransactionAlreadyInBlock` - If the transaction is already confirmed
    /// * `BumpFeeUTXOSpent` - If the UTXO being spent by the transaction is already spent
    /// * `BumpFeeError` - For other errors with fee bumping
    pub async fn bump_fee_with_fee_rate(&self, txid: Txid, fee_rate: FeeRate) -> Result<Txid> {
        // Check if transaction is already confirmed
        let transaction_info = self
            .client
            .get_transaction(&txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        if transaction_info.info.blockhash.is_some() {
            return Err(BitcoinRPCError::TransactionAlreadyInBlock(
                transaction_info
                    .info
                    .blockhash
                    .expect("Blockhash should be present"),
            ));
        }

        // Calculate current fee rate
        let tx = transaction_info
            .transaction()
            .wrap_err("Failed to get transaction")?;
        let tx_size = tx.weight().to_vbytes_ceil();
        let current_fee_sat = u64::try_from(
            transaction_info
                .fee
                .expect("Fee should be present")
                .to_sat()
                .abs(),
        )
        .wrap_err("Failed to convert fee to sat")?;

        let current_fee_rate = FeeRate::from_sat_per_kwu(1000 * current_fee_sat / tx_size);

        // If current fee rate is already sufficient, return original txid
        if current_fee_rate >= fee_rate {
            return Ok(txid);
        }

        // Get node's incremental fee to determine how much to increase
        let network_info = self
            .client
            .get_network_info()
            .await
            .wrap_err("Failed to get network info")?;
        let incremental_fee = network_info.incremental_fee;
        let incremental_fee_rate: FeeRate = FeeRate::from_sat_per_kwu(incremental_fee.to_sat());

        // Calculate new fee rate by adding incremental fee to current fee rate
        let new_fee_rate = FeeRate::from_sat_per_kwu(
            current_fee_rate.to_sat_per_kwu() + incremental_fee_rate.to_sat_per_kwu(),
        );

        tracing::debug!(
            "Bumping fee for txid: {txid} from {current_fee_rate} to {new_fee_rate} with incremental fee {incremental_fee_rate} - Final fee rate: {new_fee_rate}"
        );

        // Call Bitcoin Core's bumpfee RPC
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
            // Attempt to parse the error message to get the outpoint if the UTXO is already spent
            Err(e) => match e {
                bitcoincore_rpc::Error::JsonRpc(json_rpc_error) => match json_rpc_error {
                    bitcoincore_rpc::RpcError::Rpc(rpc_error) => {
                        if let Some((outpoint_str, _)) =
                            rpc_error.message.split_once(" is already spent")
                        {
                            let outpoint = OutPoint::from_str(outpoint_str)
                                .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))?;

                            return Err(BitcoinRPCError::BumpFeeUTXOSpent(outpoint));
                        }

                        return Err(eyre::eyre!(format!("{:?}", rpc_error))
                            .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))
                            .into());
                    }
                    _ => {
                        return Err(eyre::eyre!(json_rpc_error)
                            .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))
                            .into());
                    }
                },
                _ => {
                    return Err(eyre::eyre!(e)
                        .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))
                        .into())
                }
            },
        };

        // Return the new txid
        Ok(bump_fee_result
            .txid
            .ok_or_eyre("Failed to get Txid from bump_fee_result")?)
    }

    /// Creates a new instance of the ExtendedRpc with a new client connection.
    ///
    /// This is useful when you need a separate connection to the Bitcoin RPC server.
    ///
    /// # Returns
    /// A new `ExtendedRpc` instance on success, or an error if the connection fails.
    pub async fn clone_inner(&self) -> std::result::Result<Self, bitcoincore_rpc::Error> {
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
