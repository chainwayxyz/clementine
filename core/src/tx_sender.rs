use bitcoin::XOnlyPublicKey;
use eyre::{eyre, OptionExt};
use std::{collections::BTreeMap, env, time::Duration};

use bitcoin::{
    transaction::Version, Address, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight,
};
use bitcoincore_rpc::PackageSubmissionResult;
use bitcoincore_rpc::{json::EstimateMode, PackageTransactionResult, RpcApi};
use eyre::Context;
use serde::{Deserialize, Serialize};
use tonic::async_trait;

use crate::errors::{ErrorExt, ResultExt};
use crate::extended_rpc::BitcoinRPCError;
use crate::task::{IgnoreError, WithDelay};
use crate::{
    actor::Actor,
    bitcoin_syncer::BitcoinSyncerEvent,
    builder::{
        self,
        script::SpendPath,
        transaction::{
            input::{get_watchtower_challenge_utxo_vout, SpendableTxIn},
            output::UnspentTxOut,
            TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE,
        },
    },
    config::BridgeConfig,
    constants::MIN_TAPROOT_AMOUNT,
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    rpc::clementine::NormalSignatureKind,
    task::{IntoTask, Task, TaskExt},
};

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(1)
};

#[derive(Clone, Debug)]
pub struct TxSender {
    pub signer: Actor,
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub network: bitcoin::Network,
    pub btc_syncer_consumer_id: String,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, sqlx::Type)]
#[sqlx(type_name = "fee_paying_type", rename_all = "lowercase")]
pub enum FeePayingType {
    CPFP,
    RBF,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ActivatedWithTxid {
    pub txid: Txid,
    pub relative_block_height: u32,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ActivatedWithOutpoint {
    pub outpoint: OutPoint,
    pub relative_block_height: u32,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxMetadata {
    pub deposit_outpoint: Option<OutPoint>,
    pub operator_xonly_pk: Option<XOnlyPublicKey>,
    pub round_idx: Option<u32>,
    pub kickoff_idx: Option<u32>,
    pub tx_type: TransactionType,
}

#[derive(Debug, thiserror::Error)]
pub enum SendTxError {
    #[error("Unconfirmed fee payer UTXOs left")]
    UnconfirmedFeePayerUTXOsLeft,
    #[error("Insufficient fee payer amount")]
    InsufficientFeePayerAmount,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

type Result<T> = std::result::Result<T, SendTxError>;

#[derive(Debug)]
pub struct TxSenderTask {
    db: Database,
    current_tip_height: u32,
    inner: TxSender,
}

#[async_trait]
impl Task for TxSenderTask {
    type Output = bool;

    async fn run_once(&mut self) -> std::result::Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await.map_to_eyre()?;

        let is_block_update = async {
            let event = self
                .db
                .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.inner.btc_syncer_consumer_id)
                .await?;
            if event.is_some() {
                tracing::info!("TXSENDER: Event: {:?}", event);
            }
            Ok::<bool, BridgeError>(match event {
                Some(event) => match event {
                    BitcoinSyncerEvent::NewBlock(block_id) => {
                        self.db.confirm_transactions(&mut dbtx, block_id).await?;
                        self.current_tip_height = self
                            .db
                            .get_block_info_from_id(Some(&mut dbtx), block_id)
                            .await?
                            .ok_or(BridgeError::Error(
                                "Block not found in TxSenderTask".to_string(),
                            ))?
                            .1;

                        tracing::info!("TXSENDER: Confirmed transactions for block {}", block_id);
                        dbtx.commit().await?;
                        true
                    }
                    BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                        tracing::info!(
                            "TXSENDER: Unconfirming transactions for block {}",
                            block_id
                        );
                        self.db.unconfirm_transactions(&mut dbtx, block_id).await?;
                        dbtx.commit().await?;
                        true
                    }
                },
                None => false,
            })
        }
        .await?;

        if is_block_update {
            // Don't wait in new events
            return Ok(true);
        }

        // tracing::info!("TXSENDER: Getting fee rate");
        // let fee_rate = self.inner.get_fee_rate().await;
        // tracing::info!("TXSENDER: Fee rate: {:?}", fee_rate);
        // let fee_rate = fee_rate.expect("Failed to get fee rate");
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
        // tracing::info!("TXSENDER: Trying to send unconfirmed txs");

        self.inner
            .try_to_send_unconfirmed_txs(fee_rate, self.current_tip_height)
            .await?;

        Ok(false)
    }
}

impl IntoTask for TxSender {
    type Task = WithDelay<IgnoreError<TxSenderTask>>;

    fn into_task(self) -> Self::Task {
        TxSenderTask {
            db: self.db.clone(),
            current_tip_height: 0,
            inner: self,
        }
        .ignore_error()
        .with_delay(POLL_DELAY)
    }
}

impl TxSender {
    pub fn new(
        signer: Actor,
        rpc: ExtendedRpc,
        db: Database,
        btc_syncer_consumer_id: String,
        network: bitcoin::Network,
    ) -> Self {
        Self {
            signer,
            rpc,
            db,
            btc_syncer_consumer_id,
            network,
        }
    }

    /// Creates a fee payer UTXO for a CPFP transaction.
    async fn create_fee_payer_utxo(
        &self,
        bumped_id: u32,
        tx: &Transaction,
        fee_rate: FeeRate,
        total_fee_payer_amount: Amount,
        fee_payer_utxos_len: usize,
    ) -> Result<()> {
        tracing::info!(
            "Creating fee payer UTXO for txid {} with bump id {}",
            &tx.compute_txid().to_string(),
            bumped_id
        );
        let required_fee = Self::calculate_required_fee(
            tx.weight(),
            fee_payer_utxos_len + 1,
            fee_rate,
            FeePayingType::CPFP,
        )?;

        let required_amount = (required_fee - total_fee_payer_amount)
            + required_fee
            + required_fee
            + required_fee
            + MIN_TAPROOT_AMOUNT;

        tracing::info!(
            "Creating fee payer UTXO with amount {} ({} sat/vb)",
            required_amount,
            fee_rate
        );

        let outpoint = self
            .rpc
            .send_to_address(&self.signer.address, required_amount)
            .await
            .map_to_eyre()?;

        self.db
            .save_fee_payer_tx(
                None,
                bumped_id,
                outpoint.txid,
                outpoint.vout,
                required_amount,
                None,
            )
            .await
            .map_to_eyre()?;

        Ok(())
    }

    /// Gets the current fee rate.
    ///
    /// If the fee rate is not estimable, it will return a fee rate of 1 sat/vb,
    /// **only for regtest**.
    ///
    /// TODO: Use more sophisticated fee estimation, like the one in mempool.space
    async fn _get_fee_rate(&self) -> Result<FeeRate> {
        tracing::info!("Getting fee rate");
        let fee_rate = self
            .rpc
            .client
            .estimate_smart_fee(1, Some(EstimateMode::Conservative))
            .await;

        match fee_rate {
            Ok(fee_rate) => match fee_rate.fee_rate {
                Some(fee_rate) => Ok(FeeRate::from_sat_per_kwu(fee_rate.to_sat())),
                None => {
                    if self.network == bitcoin::Network::Regtest {
                        tracing::debug!("Using fee rate of 1 sat/vb (Regtest mode)");
                        return Ok(FeeRate::from_sat_per_vb_unchecked(1));
                    }

                    tracing::error!("TXSENDER: Fee estimation error: {:?}", fee_rate.errors);
                    Ok(FeeRate::from_sat_per_vb_unchecked(1))
                }
            },
            Err(e) => {
                tracing::error!("TXSENDER: Error getting fee rate: {:?}", e);
                Ok(FeeRate::from_sat_per_vb_unchecked(1))
            }
        }
    }

    /// Calculates the required total fee of a CPFP child tx.
    fn calculate_required_fee(
        parent_tx_weight: Weight,
        num_fee_payer_utxos: usize,
        fee_rate: FeeRate,
        fee_paying_type: FeePayingType,
    ) -> Result<Amount> {
        tracing::info!(
            "Calculating required fee for {} fee payer utxos",
            num_fee_payer_utxos
        );
        // Each additional p2tr input adds 230 WU and each additional p2tr
        // output adds 172 WU to the transaction:
        // https://bitcoin.stackexchange.com/a/116959
        let child_tx_weight = match fee_paying_type {
            FeePayingType::CPFP => Weight::from_wu_usize(230 * num_fee_payer_utxos + 207 + 172),
            FeePayingType::RBF => Weight::from_wu_usize(230 * num_fee_payer_utxos + 172),
        };

        // When effective fee rate is calculated, it calculates vBytes of the tx not the total weight.
        let total_weight = match fee_paying_type {
            FeePayingType::CPFP => Weight::from_vb_unchecked(
                child_tx_weight.to_vbytes_ceil() + parent_tx_weight.to_vbytes_ceil(),
            ),
            FeePayingType::RBF => child_tx_weight + parent_tx_weight,
        };

        fee_rate
            .checked_mul_by_weight(total_weight)
            .ok_or_eyre("Fee calculation overflow")
            .map_err(Into::into)
    }

    /// Creates a child tx that spends the p2a anchor using the fee payer utxos.
    /// It assumes the parent tx pays 0 fees.
    /// It also assumes the fee payer utxos are signable by the self.signer.
    fn create_child_tx(
        &self,
        p2a_anchor: OutPoint,
        fee_payer_utxos: Vec<SpendableTxIn>,
        parent_tx_size: Weight,
        fee_rate: FeeRate,
        change_address: Address,
    ) -> Result<Transaction> {
        tracing::info!(
            "Creating child tx with {} fee payer utxos",
            fee_payer_utxos.len()
        );
        let required_fee = Self::calculate_required_fee(
            parent_tx_size,
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::CPFP,
        )
        .map_err(|e| eyre!(e))?;

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + builder::transaction::anchor_output().value; // We add the anchor output value to the total amount.

        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new_partial(p2a_anchor, builder::transaction::anchor_output()),
                SpendPath::Unknown,
                DEFAULT_SEQUENCE,
            );

        for fee_payer_utxo in fee_payer_utxos {
            builder = builder.add_input(
                NormalSignatureKind::OperatorSighashDefault,
                fee_payer_utxo,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            );
        }

        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: total_fee_payer_amount - required_fee,
            script_pubkey: change_address.script_pubkey(),
        }));

        let mut tx_handler = builder.finalize();

        for fee_payer_input in 1..tx_handler.get_cached_tx().input.len() {
            let sighash = tx_handler
                .calculate_pubkey_spend_sighash(fee_payer_input, bitcoin::TapSighashType::Default)
                .map_err(|e| eyre!(e))?;
            let signature = self
                .signer
                .sign_with_tweak_data(sighash, builder::sighash::TapTweakData::KeyPath(None), None)
                .map_err(|e| eyre!(e))?;
            tx_handler
                .set_p2tr_key_spend_witness(
                    &bitcoin::taproot::Signature {
                        signature,
                        sighash_type: bitcoin::TapSighashType::Default,
                    },
                    fee_payer_input,
                )
                .map_err(|e| eyre!(e))?;
        }
        let child_tx = tx_handler.get_cached_tx().clone();
        Ok(child_tx)
    }

    fn is_p2a_anchor(&self, output: &TxOut) -> bool {
        output.value == builder::transaction::anchor_output().value
            && output.script_pubkey == builder::transaction::anchor_output().script_pubkey
    }

    fn find_p2a_vout(&self, tx: &Transaction) -> Result<usize> {
        let p2a_anchor = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| self.is_p2a_anchor(output));
        if let Some((vout, _)) = p2a_anchor {
            Ok(vout)
        } else {
            Err(eyre::eyre!("P2A anchor output not found in transaction").into())
        }
    }

    /// Submit package returns the effective fee rate in btc/kvb.
    /// This function converts the btc/kvb to a fee rate in sat/vb.
    #[allow(dead_code)]
    fn btc_per_kvb_to_fee_rate(btc_per_kvb: f64) -> FeeRate {
        FeeRate::from_sat_per_vb_unchecked((btc_per_kvb * 100000.0) as u64)
    }

    /// Creates a package of txs that will be submitted to the network.
    /// The package will be a CPFP package
    fn create_package(
        &self,
        tx: Transaction,
        fee_rate: FeeRate,
        fee_payer_utxos: Vec<SpendableTxIn>,
    ) -> Result<Vec<Transaction>> {
        tracing::info!(
            "Creating package with {} fee payer utxos",
            fee_payer_utxos.len()
        );
        let txid = tx.compute_txid();

        let p2a_vout = self
            .find_p2a_vout(&tx)
            .wrap_err("Failed to find p2a vout")?;

        let child_tx = self
            .create_child_tx(
                OutPoint {
                    txid,
                    vout: p2a_vout as u32,
                },
                fee_payer_utxos,
                tx.weight(),
                fee_rate,
                self.signer.address.clone(),
            )
            .wrap_err("Failed to create child tx")?;

        Ok(vec![tx, child_tx])
    }

    /// Sends the tx with the given fee_rate.
    async fn send_tx(&self, id: u32, fee_rate: FeeRate) -> Result<()> {
        tracing::info!("Sending tx {} with fee rate {}", id, fee_rate);
        let unconfirmed_fee_payer_utxos = self
            .db
            .get_bumpable_fee_payer_txs(None, id)
            .await
            .map_to_eyre()?;
        if !unconfirmed_fee_payer_utxos.is_empty() {
            return Err(SendTxError::UnconfirmedFeePayerUTXOsLeft);
        }

        let fee_payer_utxos = self
            .db
            .get_confirmed_fee_payer_utxos(None, id)
            .await
            .wrap_err("Failed to get confirmed fee payer utxos")?;

        let fee_payer_utxos: Vec<SpendableTxIn> = fee_payer_utxos
            .iter()
            .map(|(txid, vout, amount)| {
                SpendableTxIn::new(
                    OutPoint {
                        txid: *txid,
                        vout: *vout,
                    },
                    TxOut {
                        value: *amount,
                        script_pubkey: self.signer.address.script_pubkey(),
                    },
                    vec![],
                    Some(
                        builder::address::create_taproot_address(
                            &[],
                            Some(self.signer.xonly_public_key),
                            self.network,
                        )
                        .1,
                    ),
                )
            })
            .collect();

        let (tx_metadata, tx, fee_paying_type, _) = self
            .db
            .get_tx(None, id)
            .await
            .wrap_err("Failed to get tx")?;

        if fee_paying_type == FeePayingType::RBF {
            tracing::info!(
                "Sending RBF tx, meta: {tx_metadata:?}, tx: {:?}",
                hex::encode(bitcoin::consensus::serialize(&tx))
            );

            let mut dbtx = self
                .db
                .begin_transaction()
                .await
                .wrap_err("Failed to begin database transaction")?;
            let last_rbf_txid = self
                .db
                .get_last_rbf_txid(Some(&mut dbtx), id)
                .await
                .wrap_err("Failed to get last RBF txid")?;
            if last_rbf_txid.is_none() {
                tracing::info!(
                    "Funding RBF tx, meta: {tx_metadata:?}, tx: {:?}",
                    hex::encode(bitcoin::consensus::serialize(&tx))
                );

                let funded_tx = self
                    .rpc
                    .client
                    .fund_raw_transaction(
                        &tx,
                        Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
                            add_inputs: Some(true),
                            change_address: None,
                            change_position: Some(1),
                            change_type: None,
                            include_watching: None,
                            lock_unspents: None,
                            fee_rate: Some(Amount::from_sat(5 * fee_rate.to_sat_per_kwu())),
                            subtract_fee_from_outputs: None,
                            replaceable: Some(true),
                            conf_target: None,
                            estimate_mode: None,
                        }),
                        None,
                    )
                    .await
                    .wrap_err("Failed to fund raw transaction")?
                    .hex;

                let signed_tx: Transaction = bitcoin::consensus::deserialize(
                    &self
                        .rpc
                        .client
                        .sign_raw_transaction_with_wallet(&funded_tx, None, None)
                        .await
                        .wrap_err("Failed to sign raw transaction")?
                        .hex,
                )
                .wrap_err("Failed to deserialize signed transaction")?;
                let txid = self
                    .rpc
                    .client
                    .send_raw_transaction(&signed_tx)
                    .await
                    .wrap_err("Failed to send raw transaction")?;
                self.db
                    .save_rbf_txid(Some(&mut dbtx), id, txid)
                    .await
                    .wrap_err("Failed to save RBF txid")?;
            } else {
                let bumped_txid = self
                    .rpc
                    .bump_fee_with_fee_rate(
                        last_rbf_txid.expect("Last RBF txid should be present"),
                        fee_rate,
                    )
                    .await
                    .wrap_err("Failed to bump fee with fee rate")?;
                if bumped_txid != last_rbf_txid.expect("Last RBF txid should be present") {
                    self.db
                        .save_rbf_txid(Some(&mut dbtx), id, bumped_txid)
                        .await
                        .wrap_err("Failed to save RBF txid")?;
                }
            }

            dbtx.commit()
                .await
                .wrap_err("Failed to commit database transaction")?;
            return Ok(());
        }

        let package = self
            .create_package(tx, fee_rate, fee_payer_utxos)
            .wrap_err("Failed to create package")?;
        let package_refs: Vec<&Transaction> = package.iter().collect();

        // If the tx is RBF, we should note the txid of the package.
        if fee_paying_type == FeePayingType::RBF {
            self.db
                .save_rbf_txid(None, id, package[0].compute_txid())
                .await
                .wrap_err("Failed to save RBF txid")?;
        }
        tracing::info!(
            "Submitting package: {}\n\n pkg tx hexs: {:?}",
            tx_metadata
                .map(|tx_metadata| format!("{tx_metadata:?}"))
                .unwrap_or("missing tx metadata".to_string()),
            if env::var("DBG_PACKAGE_HEX").is_ok() {
                package
                    .iter()
                    .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                    .collect::<Vec<_>>()
            } else {
                vec!["use DBG_PACKAGE_HEX=1 to print the package as hex".into()]
            }
        );

        let test_mempool_result = self
            .rpc
            .client
            .test_mempool_accept(&package_refs)
            .await
            .wrap_err("Failed to test mempool accept")?;

        tracing::info!("Test mempool result: {test_mempool_result:?}");

        let submit_package_result: PackageSubmissionResult = self
            .rpc
            .client
            .submit_package(&package_refs)
            .await
            .wrap_err("Failed to submit package")?;

        tracing::info!(
            self.btc_syncer_consumer_id,
            ?tx_metadata,
            "Submit package result: {submit_package_result:?}"
        );

        // If tx_results is empty, it means the txs were already accepted by the network.
        if submit_package_result.tx_results.is_empty() {
            return Ok(());
        }

        let mut early_exit = false;
        for (_txid, result) in submit_package_result.tx_results {
            if let PackageTransactionResult::Failure { error, .. } = result {
                tracing::error!("Error submitting package: {:?}", error);
                early_exit = true;
            }
        }
        if early_exit {
            return Ok(());
        }

        // // Get the effective fee rate from the first transaction result
        // let effective_fee_rate_btc_per_kvb = submit_package_result
        //     .tx_results
        //     .iter()
        //     .next()
        //     .and_then(|(_, result)| match result {
        //         PackageTransactionResult::Success { fees, .. } => Some(fees.effective_feerate),
        //         PackageTransactionResult::SuccessAlreadyInMempool { txid, .. } => {
        //             tracing::warn!(
        //                 "{}: transaction {txid} is already in mempool, skipping",
        //                 self.consumer_handle
        //             );
        //             None
        //         }
        //         PackageTransactionResult::Failure { txid, error } => {
        //             tracing::warn!(
        //                 "{}: failed to send the transaction {txid} with error {error}, skipping",
        //                 self.consumer_handle
        //             );
        //             None
        //         }
        //     })
        //     .expect("Effective fee rate should be present")
        //     .expect("Effective fee rate should be present");

        // let effective_fee_rate = Self::btc_per_kvb_to_fee_rate(effective_fee_rate_btc_per_kvb);
        // Save the effective fee rate to the db
        self.db
            .update_effective_fee_rate(None, id, fee_rate)
            .await
            .wrap_err("Failed to update effective fee rate")?;

        // Sanity check to make sure the fee rate is equal to the required fee rate
        // assert_eq!(
        //     effective_fee_rate, fee_rate,
        //     "Effective fee rate is not equal to the required fee rate: {:?} to {:?} != {:?}",
        //     effective_fee_rate_btc_per_kvb, effective_fee_rate, fee_rate
        // );

        Ok(())
    }

    /// Tries to bump fees of fee payer txs with the given fee_rate.
    async fn bump_fees_of_fee_payer_txs(&self, bumped_id: u32, fee_rate: FeeRate) -> Result<()> {
        let bumpable_fee_payer_txs = self
            .db
            .get_bumpable_fee_payer_txs(None, bumped_id)
            .await
            .map_to_eyre()?;

        for (id, fee_payer_txid, vout, amount) in bumpable_fee_payer_txs {
            tracing::info!(
                "Bumping fee for fee payer tx {} with bumped tx {} for fee rate {}",
                fee_payer_txid,
                bumped_id,
                fee_rate
            );
            let new_txi_result = self
                .rpc
                .bump_fee_with_fee_rate(fee_payer_txid, fee_rate)
                .await;

            match new_txi_result {
                Ok(new_txid) => {
                    if new_txid != fee_payer_txid {
                        self.db
                            .save_fee_payer_tx(None, bumped_id, new_txid, vout, amount, Some(id))
                            .await
                            .map_to_eyre()?;
                    }
                }
                Err(e) => {
                    let e = e.into_eyre();
                    match e.root_cause().downcast_ref::<BitcoinRPCError>() {
                        Some(BitcoinRPCError::TransactionAlreadyInBlock(block_hash)) => {
                            tracing::info!(
                                "{}: Fee payer tx {} is already in block {}, skipping",
                                self.btc_syncer_consumer_id,
                                fee_payer_txid,
                                block_hash
                            );
                            continue;
                        }
                        Some(BitcoinRPCError::BumpFeeUTXOSpent(outpoint)) => {
                            tracing::info!("{}: Fee payer UTXO for the bumped tx {} is already onchain, skipping : {:?}", self.btc_syncer_consumer_id, bumped_id, outpoint);
                            continue;
                        }
                        _ => {
                            tracing::warn!("{}: failed to bump fee the fee payer tx {} of bumped tx {} with error {e}, skipping", self.btc_syncer_consumer_id, fee_payer_txid, bumped_id);
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Tries to send unconfirmed txs that have a new effective fee rate.
    /// Tries to bump fees of fee payer UTXOs with RBF
    async fn try_to_send_unconfirmed_txs(
        &self,
        new_fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<()> {
        tracing::info!("Trying to send unconfirmed txs with new fee rate: {new_fee_rate:?}, current tip height: {current_tip_height:?}");
        let txs = self
            .db
            .get_sendable_txs(None, new_fee_rate, current_tip_height)
            .await
            .map_to_eyre()?;

        if !txs.is_empty() {
            tracing::info!(
                self.btc_syncer_consumer_id,
                "Trying to send unconfirmed txs with new fee rate: {new_fee_rate:?}, current tip height: {current_tip_height:?}, txs: {txs:?}"
            );
        }

        for id in txs {
            self.bump_fees_of_fee_payer_txs(id, new_fee_rate).await?;
            let send_tx_result = self.send_tx(id, new_fee_rate).await;
            match send_tx_result {
                Ok(_) => {}
                Err(e) => {
                    let e = e.into_eyre();
                    match e.root_cause().downcast_ref::<SendTxError>() {
                        Some(SendTxError::UnconfirmedFeePayerUTXOsLeft) => {
                            tracing::info!(
                                "{}: Bumping Tx {} : Unconfirmed fee payer UTXOs left, skipping",
                                self.btc_syncer_consumer_id,
                                id
                            );
                            continue;
                        }
                        Some(SendTxError::InsufficientFeePayerAmount) => {
                            tracing::info!("{}: Bumping Tx {} : Insufficient fee payer amount, creating new fee payer UTXO", self.btc_syncer_consumer_id, id);
                            let (_, tx, _, _) = self.db.get_tx(None, id).await.map_to_eyre()?;
                            let fee_payer_utxos = self
                                .db
                                .get_confirmed_fee_payer_utxos(None, id)
                                .await
                                .map_to_eyre()?;
                            let total_fee_payer_amount = fee_payer_utxos
                                .iter()
                                .map(|(_, _, amount)| *amount)
                                .sum::<Amount>();
                            let fee_payer_utxos_len = fee_payer_utxos.len();
                            self.create_fee_payer_utxo(
                                id,
                                &tx,
                                new_fee_rate,
                                total_fee_payer_amount,
                                fee_payer_utxos_len,
                            )
                            .await?;

                            continue;
                        }
                        _ => {
                            tracing::error!(
                                "{}: Bumping Tx {} : Failed to send tx with CPFP: {:?}",
                                self.btc_syncer_consumer_id,
                                id,
                                e
                            );
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn client(&self) -> TxSenderClient {
        TxSenderClient::new(self.db.clone(), self.btc_syncer_consumer_id.clone())
    }
}

#[derive(Debug, Clone)]
pub struct TxSenderClient {
    db: Database,
    tx_sender_consumer_id: String,
}

impl TxSenderClient {
    pub fn new(db: Database, tx_sender_consumer_id: String) -> Self {
        Self {
            db,
            tx_sender_consumer_id,
        }
    }

    /// Tries to send a tx. If all conditions are met, it will save the tx to the database.
    /// It will also save the cancelled outpoints, cancelled txids and activated prerequisite txs to the database.
    /// It will automatically save inputs as cancelled outpoints.
    /// It will automatically save inputs as activated outpoints.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE), skip(signed_tx))]
    pub async fn insert_try_to_send(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
    ) -> Result<u32> {
        tracing::info!(
            "{} added tx {:?} with tx_metadata: {:?}",
            self.tx_sender_consumer_id,
            tx_metadata
                .map(|data| data.tx_type)
                .unwrap_or(TransactionType::Dummy),
            tx_metadata
        );
        let txid = signed_tx.compute_txid();
        let try_to_send_id = self
            .db
            .save_tx(Some(dbtx), tx_metadata, signed_tx, fee_paying_type, txid)
            .await
            .map_to_eyre()?;

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, input_outpoint)
                .await
                .map_to_eyre()?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, *outpoint)
                .await
                .map_to_eyre()?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(Some(dbtx), try_to_send_id, *txid)
                .await
                .map_to_eyre()?;
        }

        let mut max_timelock_of_activated_txids = BTreeMap::new();

        for activated_txid in activate_txids {
            let timelock = max_timelock_of_activated_txids
                .entry(activated_txid.txid)
                .or_insert(activated_txid.relative_block_height);
            if *timelock < activated_txid.relative_block_height {
                *timelock = activated_txid.relative_block_height;
            }
        }

        for input in signed_tx.input.iter() {
            let relative_block_height = if input.sequence.is_relative_lock_time() {
                let relative_locktime = input
                    .sequence
                    .to_relative_lock_time()
                    .expect("Invalid relative locktime");
                match relative_locktime {
                    bitcoin::relative::LockTime::Blocks(height) => height.value() as u32,
                    _ => {
                        return Err(eyre::eyre!("Invalid relative locktime").into());
                    }
                }
            } else {
                0
            };
            let timelock = max_timelock_of_activated_txids
                .entry(input.previous_output.txid)
                .or_insert(relative_block_height);
            if *timelock < relative_block_height {
                *timelock = relative_block_height;
            }
        }

        for (txid, timelock) in max_timelock_of_activated_txids {
            self.db
                .save_activated_txid(
                    Some(dbtx),
                    try_to_send_id,
                    &ActivatedWithTxid {
                        txid,
                        relative_block_height: timelock,
                    },
                )
                .await
                .map_to_eyre()?;
        }

        for activated_outpoint in activate_outpoints {
            self.db
                .save_activated_outpoint(Some(dbtx), try_to_send_id, activated_outpoint)
                .await
                .map_to_eyre()?;
        }

        Ok(try_to_send_id)
    }

    pub async fn add_tx_to_queue<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_metadata: Option<TxMetadata>,
        config: &BridgeConfig,
    ) -> Result<u32> {
        let tx_metadata = tx_metadata.map(|mut data| {
            data.tx_type = tx_type;
            data
        });
        match tx_type {
            TransactionType::Kickoff
            | TransactionType::Dummy
            | TransactionType::ChallengeTimeout
            | TransactionType::DisproveTimeout
            | TransactionType::Reimburse
            | TransactionType::Round
            | TransactionType::OperatorChallengeNack(_)
            | TransactionType::UnspentKickoff(_)
            | TransactionType::Payout
            | TransactionType::MoveToVault
            | TransactionType::AssertTimeout(_)
            | TransactionType::Disprove
            | TransactionType::BurnUnusedKickoffConnectors
            | TransactionType::KickoffNotFinalized
            | TransactionType::MiniAssert(_)
            | TransactionType::WatchtowerChallenge(_) => {
                // no_dependency and cpfp
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::Challenge => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::RBF,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::WatchtowerChallengeTimeout(_watchtower_idx) => {
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(tx_type, tx)| {
                        if let TransactionType::Kickoff = tx_type {
                            Some(tx.compute_txid())
                        } else {
                            None
                        }
                    })
                    .ok_or(eyre::eyre!("Couldn't find kickoff tx in related_txs"))?;
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    &[OutPoint {
                        txid: kickoff_txid,
                        vout: 1, // TODO: Make this a function of smth
                    }],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::OperatorChallengeAck(watchtower_idx) => {
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(tx_type, tx)| {
                        if let TransactionType::Kickoff = tx_type {
                            Some(tx.compute_txid())
                        } else {
                            None
                        }
                    })
                    .ok_or(eyre::eyre!("Couldn't find kickoff tx in related_txs"))?;
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    &[],
                    &[],
                    &[],
                    &[ActivatedWithOutpoint {
                        outpoint: OutPoint {
                            txid: kickoff_txid,
                            vout: get_watchtower_challenge_utxo_vout(watchtower_idx) as u32,
                        },
                        relative_block_height: config.protocol_paramset().finality_depth,
                    }],
                )
                .await
            }
            TransactionType::AllNeededForDeposit | TransactionType::YieldKickoffTxid => {
                unreachable!()
            }
            TransactionType::ReadyToReimburse
            | TransactionType::BaseDeposit
            | TransactionType::ReplacementDeposit => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::TweakCache;
    use crate::bitcoin_syncer::BitcoinSyncer;
    use crate::bitvm_client::SECP;
    use crate::builder::script::{CheckSig, SpendableScript};
    use crate::builder::transaction::TransactionType;
    use crate::{database::Database, test::common::*};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use secp256k1::rand;
    use std::result::Result;
    use std::sync::Arc;

    impl TxSenderClient {
        pub async fn test_dbtx(
            &self,
        ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
            self.db.begin_transaction().await
        }
    }

    async fn create_test_tx_sender(
        rpc: ExtendedRpc,
    ) -> (TxSender, ExtendedRpc, Database, Actor, bitcoin::Network) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = bitcoin::Network::Regtest;
        let actor = Actor::new(sk, None, network);

        let config = create_test_config_with_thread_name().await;

        let db = Database::new(&config).await.unwrap();

        let tx_sender = TxSender::new(
            actor.clone(),
            rpc.clone(),
            db.clone(),
            "tx_sender".into(),
            network,
        );

        (tx_sender, rpc, db, actor, network)
    }

    async fn create_bumpable_tx(
        rpc: &ExtendedRpc,
        signer: &Actor,
        network: bitcoin::Network,
        fee_paying_type: FeePayingType,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

        let amount = Amount::from_sat(100000);
        let outpoint = rpc.send_to_address(&address, amount).await?;
        rpc.mine_blocks(1).await?;

        let version = match fee_paying_type {
            FeePayingType::CPFP => Version::non_standard(3),
            FeePayingType::RBF => Version::TWO,
        };

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(version)
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new(
                    outpoint,
                    TxOut {
                        value: amount,
                        script_pubkey: address.script_pubkey(),
                    },
                    vec![],
                    Some(spend_info),
                ),
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(TxOut {
                value: amount - builder::transaction::anchor_output().value,
                script_pubkey: address.script_pubkey(), // TODO: This should be the wallet address, not the signer address
            }))
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .finalize();

        let sighash_type = match fee_paying_type {
            FeePayingType::CPFP => bitcoin::TapSighashType::Default,
            FeePayingType::RBF => bitcoin::TapSighashType::AllPlusAnyoneCanPay,
        };

        let sighash = builder.calculate_pubkey_spend_sighash(0, sighash_type)?;
        let signature = signer.sign_with_tweak_data(
            sighash,
            builder::sighash::TapTweakData::KeyPath(None),
            None,
        )?;
        builder.set_p2tr_key_spend_witness(
            &bitcoin::taproot::Signature {
                signature,
                sighash_type,
            },
            0,
        )?;

        let tx = builder.get_cached_tx().clone();
        Ok(tx)
    }

    #[tokio::test]
    async fn test_try_to_send() -> Result<(), BridgeError> {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();

        let (tx_sender, rpc, db, signer, network) = create_test_tx_sender(rpc).await;

        let btc_syncer = BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset())
            .await
            .unwrap()
            .into_task()
            .cancelable_loop();
        btc_syncer.0.into_bg();

        let client = tx_sender.client();
        let tx_sender = tx_sender.into_task().cancelable_loop();
        tx_sender.0.into_bg();

        let tx = create_bumpable_tx(&rpc, &signer, network, FeePayingType::CPFP)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        let tx_id1 = client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::CPFP,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        let tx_id2 = client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::CPFP,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap(); // It is ok to call this twice
        dbtx.commit().await.unwrap();

        for _ in 0..30 {
            rpc.mine_blocks(1).await.unwrap();

            let tx_result = rpc
                .client
                .get_raw_transaction_info(&tx.compute_txid(), None)
                .await;

            if tx_result.is_ok() && tx_result.unwrap().confirmations.unwrap() > 0 {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        tokio::time::sleep(Duration::from_secs(10)).await;

        let (_, _, _, tx_id2_seen_block_id) = db.get_tx(None, tx_id2).await.unwrap();

        assert!(tx_id2_seen_block_id.is_some());

        let (_, _, _, tx_id1_seen_block_id) = db.get_tx(None, tx_id1).await.unwrap();

        assert!(tx_id1_seen_block_id.is_none());

        let tx2 = create_bumpable_tx(&rpc, &signer, network, FeePayingType::RBF)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx2,
                FeePayingType::RBF,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        dbtx.commit().await.unwrap();

        for _ in 0..30 {
            rpc.mine_blocks(1).await.unwrap();

            let tx_result = rpc
                .client
                .get_raw_transaction_info(&tx.compute_txid(), None)
                .await;

            if tx_result.is_ok() && tx_result.unwrap().confirmations.unwrap() > 0 {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("Tx was not confirmed in time");
    }

    #[tokio::test]
    async fn get_fee_rate() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc: ExtendedRpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let amount = Amount::from_sat(100_000);
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );
        let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

        let tx_sender = TxSender::new(
            signer.clone(),
            rpc.clone(),
            db,
            "tx_sender".into(),
            config.protocol_paramset().network,
        );

        let scripts: Vec<Arc<dyn SpendableScript>> =
            vec![Arc::new(CheckSig::new(xonly_pk)).clone()];
        let (taproot_address, taproot_spend_info) = builder::address::create_taproot_address(
            &scripts
                .iter()
                .map(|s| s.to_script_buf())
                .collect::<Vec<_>>(),
            None,
            config.protocol_paramset().network,
        );

        let input_utxo = rpc.send_to_address(&taproot_address, amount).await.unwrap();

        let builder = TxHandlerBuilder::new(TransactionType::Dummy).add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(
                input_utxo,
                TxOut {
                    value: amount,
                    script_pubkey: taproot_address.script_pubkey(),
                },
                scripts.clone(),
                Some(taproot_spend_info.clone()),
            ),
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        );

        let mut will_fail_handler = builder
            .clone()
            .add_output(UnspentTxOut::new(
                TxOut {
                    value: amount,
                    script_pubkey: taproot_address.script_pubkey(),
                },
                scripts.clone(),
                Some(taproot_spend_info.clone()),
            ))
            .finalize();

        let mut tweak_cache = TweakCache::default();
        signer
            .tx_sign_and_fill_sigs(&mut will_fail_handler, &[], Some(&mut tweak_cache))
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        let will_fail_tx = will_fail_handler.get_cached_tx();
        assert!(rpc.client.send_raw_transaction(will_fail_tx).await.is_err());

        // Calculate and send with fee.
        let fee_rate = tx_sender._get_fee_rate().await.unwrap();
        let fee = TxSender::calculate_required_fee(
            will_fail_tx.weight(),
            1,
            fee_rate,
            FeePayingType::CPFP,
        )
        .unwrap();
        println!("Fee rate: {:?}, fee: {}", fee_rate, fee);

        let mut will_successful_handler = builder
            .add_output(UnspentTxOut::new(
                TxOut {
                    value: amount - fee,
                    script_pubkey: taproot_address.script_pubkey(),
                },
                scripts,
                Some(taproot_spend_info),
            ))
            .finalize();
        signer
            .tx_sign_and_fill_sigs(&mut will_successful_handler, &[], Some(&mut tweak_cache))
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        rpc.client
            .send_raw_transaction(will_successful_handler.get_cached_tx())
            .await
            .unwrap();
    }
}
