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
use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use std::str::FromStr;
use std::sync::Arc;

use crate::builder::address::create_taproot_address;
use crate::builder::transaction::create_round_txhandlers;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::KickoffWinternitzKeys;
use crate::builder::transaction::TransactionType;
use crate::builder::transaction::TxHandler;
use crate::config::protocol::ProtocolParamset;
use crate::deposit::OperatorData;
use crate::errors::BridgeError;
use crate::operator::RoundIndex;
use secrecy::SecretBox;

type Result<T> = std::result::Result<T, BitcoinRPCError>;

/// Bitcoin RPC wrapper. Extended RPC provides useful wrapper functions for
/// common operations, as well as direct access to Bitcoin RPC. Bitcoin RPC can
/// be directly accessed via `client` member.
#[derive(Clone)]
pub struct ExtendedRpc {
    pub url: String,
    pub client: Arc<Client>,
}

impl std::fmt::Debug for ExtendedRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedRpc")
            .field("url", &self.url)
            .finish()
    }
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
    pub async fn connect(url: String, user: SecretString, password: SecretString) -> Result<Self> {
        let auth = Auth::UserPass(
            user.expose_secret().to_string(),
            password.expose_secret().to_string(),
        );

        let rpc = Client::new(&url, auth)
            .await
            .wrap_err("Failed to connect to Bitcoin RPC")?;

        Ok(Self {
            url,
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
    ///
    /// - [`u32`]: Current block height
    pub async fn get_current_chain_height(&self) -> Result<u32> {
        let height = self
            .client
            .get_block_count()
            .await
            .wrap_err("Failed to get block count")?;

        Ok(u32::try_from(height).wrap_err("Failed to convert block count to u32")?)
    }

    /// Checks if an operator's collateral is valid and available for use.
    ///
    /// This function validates the operator's collateral by:
    /// 1. Verifying the collateral UTXO exists and has the correct amount
    /// 2. Creating the round transaction chain to track current collateral position
    /// 3. Determining if the current collateral UTXO in the chain is spent in a non-protocol tx, signaling the exit of operator from the protocol
    ///
    /// # Parameters
    ///
    /// * `operator_data`: Data about the operator including collateral funding outpoint
    /// * `kickoff_wpks`: Kickoff Winternitz public keys for round transaction creation
    /// * `paramset`: Protocol parameters
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the collateral is still usable, thus operator is still in protocol, `false` if the collateral is spent, thus operator is not in protocol anymore
    ///
    /// # Errors
    ///
    /// - [`BridgeError`]: If there was an error retrieving transaction data, creating round transactions,
    ///   or checking UTXO status
    pub async fn collateral_check(
        &self,
        operator_data: &OperatorData,
        kickoff_wpks: &KickoffWinternitzKeys,
        paramset: &'static ProtocolParamset,
    ) -> std::result::Result<bool, BridgeError> {
        // first check if the collateral utxo is
        let tx = self
            .get_tx_of_txid(&operator_data.collateral_funding_outpoint.txid)
            .await
            .wrap_err(format!(
                "Failed to find collateral utxo in chain for outpoint {:?}",
                operator_data.collateral_funding_outpoint
            ))?;
        let collateral_outpoint = match tx
            .output
            .get(operator_data.collateral_funding_outpoint.vout as usize)
        {
            Some(output) => output,
            None => {
                tracing::warn!(
                    "No output at index {} for txid {} while checking for collateral existence",
                    operator_data.collateral_funding_outpoint.vout,
                    operator_data.collateral_funding_outpoint.txid
                );
                return Ok(false);
            }
        };

        if collateral_outpoint.value != paramset.collateral_funding_amount {
            tracing::error!(
                "Collateral amount for collateral {:?} is not correct: expected {}, got {}",
                operator_data.collateral_funding_outpoint,
                paramset.collateral_funding_amount,
                collateral_outpoint.value
            );
            return Ok(false);
        }

        let operator_tpr_address =
            create_taproot_address(&[], Some(operator_data.xonly_pk), paramset.network).0;

        if collateral_outpoint.script_pubkey != operator_tpr_address.script_pubkey() {
            tracing::error!(
                "Collateral script pubkey for collateral {:?} is not correct: expected {}, got {}",
                operator_data.collateral_funding_outpoint,
                operator_tpr_address.script_pubkey(),
                collateral_outpoint.script_pubkey
            );
            return Ok(false);
        }

        let mut current_collateral_outpoint: OutPoint = operator_data.collateral_funding_outpoint;
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        // iterate over all rounds
        for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
            // create round and ready to reimburse txs for the round
            let txhandlers = create_round_txhandlers(
                paramset,
                round_idx,
                operator_data,
                kickoff_wpks,
                prev_ready_to_reimburse.as_ref(),
            )?;

            let mut round_txhandler_opt = None;
            let mut ready_to_reimburse_txhandler_opt = None;
            for txhandler in &txhandlers {
                match txhandler.get_transaction_type() {
                    TransactionType::Round => round_txhandler_opt = Some(txhandler),
                    TransactionType::ReadyToReimburse => {
                        ready_to_reimburse_txhandler_opt = Some(txhandler)
                    }
                    _ => {}
                }
            }
            if round_txhandler_opt.is_none() || ready_to_reimburse_txhandler_opt.is_none() {
                return Err(eyre!(
                    "Failed to create round and ready to reimburse txs for round {:?} for operator {}",
                    round_idx,
                    operator_data.xonly_pk
                ).into());
            }

            let round_txid = round_txhandler_opt
                .expect("Round txhandler should exist, checked above")
                .get_cached_tx()
                .compute_txid();
            let is_round_tx_on_chain = self.is_tx_on_chain(&round_txid).await?;
            if !is_round_tx_on_chain {
                break;
            }
            let block_hash = self.get_blockhash_of_tx(&round_txid).await?;
            let block_height = self
                .client
                .get_block_info(&block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block info for block hash {}",
                    block_hash
                ))?
                .height;
            if block_height < paramset.start_height as usize {
                tracing::warn!(
                    "Collateral utxo of operator {:?} is spent in a block before paramset start height: {} < {}",
                    operator_data,
                    block_height,
                    paramset.start_height
                );
                return Ok(false);
            }
            current_collateral_outpoint = OutPoint {
                txid: round_txid,
                vout: UtxoVout::CollateralInRound.get_vout(),
            };
            if round_idx == RoundIndex::Round(paramset.num_round_txs - 1) {
                // for the last round, only check round tx, as if the operator sent the ready to reimburse tx of last round,
                // it cannot create more kickoffs anymore
                break;
            }
            let ready_to_reimburse_txhandler = ready_to_reimburse_txhandler_opt
                .expect("Ready to reimburse txhandler should exist");
            let ready_to_reimburse_txid =
                ready_to_reimburse_txhandler.get_cached_tx().compute_txid();
            let is_ready_to_reimburse_tx_on_chain =
                self.is_tx_on_chain(&ready_to_reimburse_txid).await?;
            if !is_ready_to_reimburse_tx_on_chain {
                break;
            }

            current_collateral_outpoint = OutPoint {
                txid: ready_to_reimburse_txid,
                vout: UtxoVout::CollateralInReadyToReimburse.get_vout(),
            };

            prev_ready_to_reimburse = Some(ready_to_reimburse_txhandler.clone());
        }

        // if the collateral utxo we found latest in the round tx chain is spent, operators collateral is spent from Clementine
        // bridge protocol, thus it is unusable and operator cannot fulfill withdrawals anymore
        // if not spent, it should exist in chain, which is checked below
        Ok(self
            .client
            .get_tx_out(
                &current_collateral_outpoint.txid,
                current_collateral_outpoint.vout,
                Some(true), // include mempool too
            )
            .await
            .wrap_err("Failed to get transaction output")?
            .is_some())
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

    /// Retrieves the block header and hash for a given block height.
    ///
    /// # Arguments
    ///
    /// * `height`: Target block height.
    ///
    /// # Returns
    ///
    /// - ([`bitcoin::BlockHash`], [`bitcoin::block::Header`]): A tuple
    ///   containing the block hash and header.
    pub async fn get_block_info_by_height(
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
    ///
    /// * `tx` - The transaction to get the previous transactions for
    ///
    /// # Returns
    ///
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

        let current_output = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(eyre!(
                "No output at index {} for txid {}",
                outpoint.vout,
                outpoint.txid
            ))?
            .to_owned();

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

    /// Gets the number of transactions in the mempool.
    ///
    /// # Returns
    ///
    /// - [`usize`]: The number of transactions in the mempool.
    pub async fn mempool_size(&self) -> Result<usize> {
        let mempool_info = self
            .client
            .get_mempool_info()
            .await
            .wrap_err("Failed to get mempool info")?;
        Ok(mempool_info.size)
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
        let vout = tx_result.details[0].vout;

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
        let txout = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(eyre!(
                "No output at index {} for txid {}",
                outpoint.vout,
                outpoint.txid
            ))?
            .to_owned();

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

                        return Err(eyre::eyre!("{:?}", rpc_error)
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
        Ok(Self {
            url: self.url.clone(),
            client: self.client.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::actor::Actor;
    use crate::config::protocol::{ProtocolParamset, REGTEST_PARAMSET};
    use crate::extended_rpc::ExtendedRpc;
    use crate::test::common::{citrea, create_test_config_with_thread_name};
    use crate::{
        bitvm_client::SECP, extended_rpc::BitcoinRPCError, test::common::create_regtest_rpc,
    };
    use bitcoin::Amount;
    use bitcoin::{amount, key::Keypair, Address, FeeRate, XOnlyPublicKey};
    use bitcoincore_rpc::RpcApi;
    use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
    use citrea_e2e::config::{BitcoinConfig, TestCaseDockerConfig};
    use citrea_e2e::test_case::TestCaseRunner;
    use citrea_e2e::Result;
    use citrea_e2e::{config::TestCaseConfig, framework::TestFramework, test_case::TestCase};
    use tonic::async_trait;

    #[tokio::test]
    async fn new_extended_rpc_with_clone() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        rpc.mine_blocks(101).await.unwrap();
        let height = rpc.client.get_block_count().await.unwrap();
        let hash = rpc.client.get_block_hash(height).await.unwrap();

        let cloned_rpc = rpc.clone_inner().await.unwrap();
        assert_eq!(cloned_rpc.url, rpc.url);
        assert_eq!(cloned_rpc.client.get_block_count().await.unwrap(), height);
        assert_eq!(
            cloned_rpc.client.get_block_hash(height).await.unwrap(),
            hash
        );
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
        assert_eq!(height as u32, rpc.get_current_chain_height().await.unwrap());
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

        let height = rpc.get_current_chain_height().await.unwrap();
        let (hash, header) = rpc.get_block_info_by_height(height.into()).await.unwrap();
        assert_eq!(blockhash, hash);
        assert_eq!(rpc.client.get_block_header(&hash).await.unwrap(), header);
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

    struct ReorgChecks;
    #[async_trait]
    impl TestCase for ReorgChecks {
        fn bitcoin_config() -> BitcoinConfig {
            BitcoinConfig {
                extra_args: vec![
                    "-txindex=1",
                    "-fallbackfee=0.000001",
                    "-rpcallowip=0.0.0.0/0",
                    "-dustrelayfee=0",
                ],
                ..Default::default()
            }
        }

        fn test_config() -> TestCaseConfig {
            TestCaseConfig {
                with_sequencer: true,
                with_batch_prover: false,
                n_nodes: 2,
                docker: TestCaseDockerConfig {
                    bitcoin: true,
                    citrea: true,
                },
                ..Default::default()
            }
        }

        async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
            let (da0, da1) = (
                f.bitcoin_nodes.get(0).unwrap(),
                f.bitcoin_nodes.get(1).unwrap(),
            );

            let mut config = create_test_config_with_thread_name().await;
            const PARAMSET: ProtocolParamset = ProtocolParamset {
                finality_depth: DEFAULT_FINALITY_DEPTH as u32,
                ..REGTEST_PARAMSET
            };
            config.protocol_paramset = &PARAMSET;
            citrea::update_config_with_citrea_e2e_values(
                &mut config,
                da0,
                f.sequencer.as_ref().expect("Sequencer is present"),
                None,
            );

            let rpc = ExtendedRpc::connect(
                config.bitcoin_rpc_url.clone(),
                config.bitcoin_rpc_user.clone(),
                config.bitcoin_rpc_password.clone(),
            )
            .await
            .unwrap();

            // Reorg starts here.
            f.bitcoin_nodes.disconnect_nodes().await?;

            let before_reorg_tip_height = rpc.client.get_block_count().await?;
            let before_reorg_tip_hash = rpc.client.get_block_hash(before_reorg_tip_height).await?;

            let address =
                Actor::new(config.secret_key, None, config.protocol_paramset.network).address;
            let tx = rpc
                .send_to_address(&address, Amount::from_sat(10000))
                .await?;

            assert!(!rpc.is_tx_on_chain(&tx.txid).await?);
            rpc.mine_blocks(1).await?;
            assert!(rpc.is_tx_on_chain(&tx.txid).await?);

            // Make the second branch longer and perform a reorg.
            let reorg_depth = 4;
            da1.generate(reorg_depth).await.unwrap();
            f.bitcoin_nodes.connect_nodes().await?;
            f.bitcoin_nodes.wait_for_sync(None).await?;

            // Check that reorg happened.
            let current_tip_height = rpc.client.get_block_count().await?;
            assert_eq!(
                before_reorg_tip_height + reorg_depth,
                current_tip_height,
                "Re-org did not occur"
            );
            let current_tip_hash = rpc.client.get_block_hash(current_tip_height).await?;
            assert_ne!(
                before_reorg_tip_hash, current_tip_hash,
                "Re-org did not occur"
            );

            assert!(!rpc.is_tx_on_chain(&tx.txid).await?);

            Ok(())
        }
    }

    #[tokio::test]
    async fn reorg_checks() -> Result<()> {
        TestCaseRunner::new(ReorgChecks).run().await
    }
}
