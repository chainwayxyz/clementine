//! # Bitcoin Extended RPC Interface
//!
//! Extended RPC interface communicates with the Bitcoin node. It features some
//! common wrappers around typical RPC operations as well as direct
//! communication interface with the Bitcoin node.
//!
//! ## Tests
//!
//! In tests, Bitcoind node and client are usually created using
//! [`crate::test::common::create_regtest_rpc`]. Please refer to
//! [`crate::test::common`] for using [`ExtendedRpc`] in tests.

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
use std::str::FromStr;
use std::sync::Arc;

type Result<T> = std::result::Result<T, BitcoinRPCError>;

/// Bitcoin RPC wrapper. Extended RPC provides useful wrapper functions for
/// common operations, as well as direct access to Bitcoin RPC. Bitcoin RPC can
/// be directly accessed via `client` member.
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
    #[error("Transaction is not confirmed")]
    TransactionNotConfirmed,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

impl ExtendedRpc {
    /// Connects to Bitcoin RPC and returns a new [`ExtendedRpc`].
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
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`u32`]: The number of confirmations for the transaction.
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If the transaction is not confirmed (0) or if
    ///   there was an error retrieving the transaction info.
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

    /// Retrieves the current blockchain height (number of blocks).
    ///
    /// # Returns
    /// The current block height as a `u32`, or an error if it cannot be retrieved or converted.
    pub async fn get_current_chain_height(&self) -> Result<u32> {
        let height = self
            .client
            .get_block_count()
            .await
            .wrap_err("Failed to get block count")?;
        Ok(u32::try_from(height).wrap_err("Failed to convert block count to u32")?)
    }

    /// Returns block hash of a transaction, if confirmed.
    ///
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`bitcoin::BlockHash`]: Block hash of the block that the transaction
    ///   is in.
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If the transaction is not confirmed (0) or if
    ///   there was an error retrieving the transaction info.
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

    /// Retrieves the block header for a given block height.
    ///
    /// # Arguments
    /// * `height` - The block height for which to retrieve the header.
    ///
    /// # Returns
    /// A tuple containing the `bitcoin::BlockHash` and `bitcoin::block::Header`,
    /// or an error if the block or header cannot be retrieved.
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
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`bitcoin::Transaction`]: Transaction itself.
    pub async fn get_tx_of_txid(&self, txid: &bitcoin::Txid) -> Result<bitcoin::Transaction> {
        let raw_transaction = self
            .client
            .get_raw_transaction(txid, None)
            .await
            .wrap_err("Failed to get raw transaction")?;
        Ok(raw_transaction)
    }

    /// Checks if a transaction is on-chain.
    ///
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the transaction is on-chain, `false` otherwise.
    pub async fn is_tx_on_chain(&self, txid: &bitcoin::Txid) -> Result<bool> {
        Ok(self
            .client
            .get_raw_transaction_info(txid, None)
            .await
            .ok()
            .and_then(|s| s.blockhash)
            .is_some())
    }

    /// Checks if a transaction UTXO has expected address and amount.
    ///
    /// # Parameters
    ///
    /// * `outpoint` - The outpoint to check
    /// * `address` - Expected script pubkey
    /// * `amount_sats` - Expected amount in satoshis
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the UTXO has the expected address and amount, `false` otherwise.
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

    /// Checks if an UTXO is spent.
    ///
    /// # Parameters
    ///
    /// * `outpoint`: The outpoint to check
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the UTXO is spent, `false` otherwise.
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If the transaction is not confirmed or if there
    ///   was an error retrieving the transaction output.
    pub async fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool> {
        if !self.is_tx_on_chain(&outpoint.txid).await? {
            return Err(BitcoinRPCError::TransactionNotConfirmed);
        }

        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
            .await
            .wrap_err("Failed to get transaction output")?;

        Ok(res.is_none())
    }

    /// Mines a specified number of blocks to a new address.
    ///
    /// This is a test-only function that generates blocks and it will only work
    /// on regtest.
    ///
    /// # Parameters
    ///
    /// * `block_num`: The number of blocks to mine
    ///
    /// # Returns
    ///
    /// - [`Vec<BlockHash>`]: A vector of block hashes for the newly mined blocks.
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

    /// Sends a specified amount of Bitcoins to the given address.
    ///
    /// # Parameters
    ///
    /// * `address` - The recipient address
    /// * `amount_sats` - The amount to send in satoshis
    ///
    /// # Returns
    ///
    /// - [`OutPoint`]: The outpoint (txid and vout) of the newly created output.
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
    ///
    /// * `outpoint` - The outpoint (txid and vout) to retrieve
    ///
    /// # Returns
    ///
    /// - [`TxOut`]: The transaction output at the specified outpoint.
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
    ///
    /// - [`Txid`]: The txid of the bumped transaction (which may be the same as the input txid if no bump was needed).
    ///
    /// # Errors
    ///
    ///  * `TransactionAlreadyInBlock` - If the transaction is already confirmed
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

    /// Creates a new instance of the [`ExtendedRpc`] with a new client
    /// connection for cloning. This is needed when you need a separate
    /// connection to the Bitcoin RPC server.
    ///
    /// # Returns
    ///
    /// - [`ExtendedRpc`]: A new instance of ExtendedRpc with a new client connection.
    pub async fn clone_inner(&self) -> std::result::Result<Self, bitcoincore_rpc::Error> {
        let new_client = Client::new(&self.url, self.auth.clone()).await?;

        Ok(Self {
            url: self.url.clone(),
            auth: self.auth.clone(),
            client: Arc::new(new_client),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bitvm_client::SECP,
        extended_rpc::BitcoinRPCError,
        test::common::{create_regtest_rpc, create_test_config_with_thread_name},
    };
    use bitcoin::{amount, key::Keypair, Address, FeeRate, XOnlyPublicKey};
    use bitcoincore_rpc::RpcApi;

    #[tokio::test]
    async fn new_extended_rpc() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let _should_not_panic = regtest.rpc();
    }

    #[tokio::test]
    async fn tx_checks_in_mempool_and_on_chain() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);

        let amount = amount::Amount::from_sat(10000);

        // Prepare a transaction.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        let tx = rpc.get_tx_of_txid(&utxo.txid).await.unwrap();
        let txid = tx.compute_txid();
        tracing::debug!("TXID: {}", txid);

        assert_eq!(tx.output[utxo.vout as usize].value, amount);
        assert_eq!(utxo.txid, txid);
        assert!(rpc
            .check_utxo_address_and_amount(&utxo, &address.script_pubkey(), amount)
            .await
            .unwrap());

        // In mempool.
        assert!(rpc.confirmation_blocks(&utxo.txid).await.is_err());
        assert!(rpc.get_blockhash_of_tx(&utxo.txid).await.is_err());
        assert!(!rpc.is_tx_on_chain(&txid).await.unwrap());
        assert!(rpc.is_utxo_spent(&utxo).await.is_err());

        rpc.mine_blocks(1).await.unwrap();
        let height = rpc.client.get_block_count().await.unwrap();
        let blockhash = rpc.client.get_block_hash(height).await.unwrap();

        // On chain.
        assert_eq!(rpc.confirmation_blocks(&utxo.txid).await.unwrap(), 1);
        assert_eq!(
            rpc.get_blockhash_of_tx(&utxo.txid).await.unwrap(),
            blockhash
        );
        assert_eq!(rpc.get_tx_of_txid(&txid).await.unwrap(), tx);
        assert!(rpc.is_tx_on_chain(&txid).await.unwrap());
        assert!(!rpc.is_utxo_spent(&utxo).await.unwrap());

        // Doesn't matter if in mempool or on chain.
        let txout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
        assert_eq!(txout.value, amount);
        assert_eq!(rpc.get_tx_of_txid(&txid).await.unwrap(), tx);
    }

    #[tokio::test]
    async fn bump_fee_with_fee_rate() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);

        let amount = amount::Amount::from_sat(10000);

        // Confirmed transaction cannot be fee bumped.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        rpc.mine_blocks(1).await.unwrap();
        assert!(rpc
            .bump_fee_with_fee_rate(utxo.txid, FeeRate::from_sat_per_vb(1).unwrap())
            .await
            .inspect_err(|e| {
                match e {
                    BitcoinRPCError::TransactionAlreadyInBlock(_) => {}
                    _ => panic!("Unexpected error: {:?}", e),
                }
            })
            .is_err());

        // TODO: Calculate this dynamically.
        let current_fee_rate = FeeRate::from_sat_per_vb_unchecked(1);

        // Trying to bump a transaction with a fee rate that is already enough
        // should return the original txid.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        let txid = rpc
            .bump_fee_with_fee_rate(utxo.txid, current_fee_rate)
            .await
            .unwrap();
        assert_eq!(txid, utxo.txid);

        // A bigger fee rate should return a different txid.
        let new_fee_rate = FeeRate::from_sat_per_vb_unchecked(10000);
        let txid = rpc
            .bump_fee_with_fee_rate(utxo.txid, new_fee_rate)
            .await
            .unwrap();
        assert_ne!(txid, utxo.txid);
    }
}
