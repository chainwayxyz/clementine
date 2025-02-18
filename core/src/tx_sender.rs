use std::time::Duration;

use bitcoin::{
    transaction::Version, Address, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight,
};
use bitcoincore_rpc::{json::EstimateMode, RpcApi};
use tokio::task::JoinHandle;

use crate::{
    actor::Actor,
    bitcoin_syncer::BitcoinSyncerEvent,
    builder::{
        self,
        script::SpendPath,
        transaction::{
            input::SpendableTxIn, output::UnspentTxOut, TransactionType, TxHandlerBuilder,
            DEFAULT_SEQUENCE,
        },
    },
    constants::MIN_TAPROOT_AMOUNT,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    rpc::clementine::NormalSignatureKind,
};

#[derive(Clone, Debug)]
pub struct TxSender {
    pub signer: Actor,
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub network: bitcoin::Network,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum FeePayingType {
    CPFP,
    RBF,
}

impl std::fmt::Display for FeePayingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::str::FromStr for FeePayingType {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CPFP" => Ok(FeePayingType::CPFP),
            "RBF" => Ok(FeePayingType::RBF),
            _ => Err(BridgeError::Error(format!(
                "Invalid fee paying type: {}",
                s
            ))),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct PrerequisiteTx {
    pub txid: Txid,
    pub timelock: bitcoin::Sequence,
}

impl TxSender {
    pub fn new(signer: Actor, rpc: ExtendedRpc, db: Database, network: bitcoin::Network) -> Self {
        Self {
            signer,
            rpc,
            db,
            network,
        }
    }

    /// Runs the tx sender.
    /// It will start a background task that will listen for new blocks and confirm transactions.
    /// It will also listen for reorged blocks and unconfirm transactions.
    /// It will also periodically bump fees of both the package and the fee payer txs.
    /// consumer_handle is the name of the consumer that will be used to listen for events, it should be unique for each tx sender.
    pub async fn run(
        &self,
        consumer_handle: &str,
        poll_delay: Duration,
    ) -> Result<JoinHandle<Result<(), BridgeError>>, BridgeError> {
        // Clone the required fields for the async task
        let db = self.db.clone();
        let consumer_handle = consumer_handle.to_string();
        let this = self.clone();

        tracing::info!(
            "TXSENDER: Starting tx sender with handle {}",
            consumer_handle
        );

        let handle = tokio::spawn(async move {
            let mut current_tip_height = 0;
            loop {
                let result: Result<(), BridgeError> = async {
                    let mut dbtx = db.begin_transaction().await?;

                    let is_reorg = async {
                        let event = db.get_event_and_update(&mut dbtx, &consumer_handle).await?;
                        Ok::<bool, BridgeError>(match event {
                            Some(event) => match event {
                                BitcoinSyncerEvent::NewBlock(block_id) => {
                                    db.confirm_transactions(&mut dbtx, block_id as i32).await?;
                                    current_tip_height = db
                                        .get_block_info_from_id(Some(&mut dbtx), block_id)
                                        .await?
                                        .ok_or(BridgeError::Error("Block not found".to_string()))?
                                        .1;

                                    tracing::info!(
                                        "TXSENDER: Confirmed transactions for block {}",
                                        block_id
                                    );
                                    dbtx.commit().await?;
                                    false
                                }
                                BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                                    tracing::info!(
                                        "TXSENDER: Unconfirming transactions for block {}",
                                        block_id
                                    );
                                    db.unconfirm_transactions(&mut dbtx, block_id as i32)
                                        .await?;
                                    dbtx.commit().await?;
                                    true
                                }
                            },
                            None => false,
                        })
                    }
                    .await?;

                    if is_reorg {
                        // Don't wait in reorg, simply get the next event, there has to be a new event.
                        return Ok(());
                    }

                    tracing::info!("TXSENDER: Getting fee rate");
                    let fee_rate = this.get_fee_rate().await?;
                    tracing::info!("TXSENDER: Trying to send unconfirmed txs");
                    this.try_to_send_unconfirmed_txs(fee_rate, current_tip_height as u64)
                        .await?;

                    Ok(())
                }
                .await;

                match result {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("TXSENDER: Error sending txs: {:?}", e);
                    }
                }

                tokio::time::sleep(poll_delay).await;
            }
        });

        Ok(handle)
    }

    /// Tries to send a tx. If all conditions are met, it will save the tx to the database.
    /// It will also save the cancelled outpoints, cancelled txids and activated prerequisite txs to the database.
    /// It will automatically saves inputs as cancelled outpoints.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn try_to_send(
        &self,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_prerequisite_txs: &[PrerequisiteTx],
    ) -> Result<(), BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;

        let try_to_send_id = self
            .db
            .save_tx(Some(&mut dbtx), signed_tx, fee_paying_type)
            .await?;

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(Some(&mut dbtx), try_to_send_id, input_outpoint)
                .await?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(Some(&mut dbtx), try_to_send_id, *outpoint)
                .await?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(Some(&mut dbtx), try_to_send_id, *txid)
                .await?;
        }

        for prerequisite_tx in activate_prerequisite_txs {
            self.db
                .save_activated_prerequisite_tx(Some(&mut dbtx), try_to_send_id, prerequisite_tx)
                .await?;
        }

        dbtx.commit().await?;

        Ok(())
    }

    /// Creates a fee payer UTXO for a parent transaction. This function should
    /// be called before the parent tx is sent to the network.
    ///
    /// This is to make sure the client has enough funds to bump fees. The fee
    /// payer UTXO is used to bump fees of the parent tx.
    ///
    /// The fee payer UTXO **must be confirmed** before the parent tx is sent to
    /// the network.
    ///
    /// # Returns
    ///
    /// - [`OutPoint`]: Outpoint of the fee payer UTXO.
    pub async fn create_fee_payer_utxo(
        &self,
        bumped_id: i32,
        tx_weight: Weight,
        _fee_paying_type: FeePayingType,
    ) -> Result<OutPoint, BridgeError> {
        let fee_rate = self.get_fee_rate().await?;
        let required_amount =
            Self::calculate_required_amount_for_fee_payer_utxo(tx_weight, fee_rate)?;
        tracing::info!(
            "Creating fee payer UTXO with amount {} ({} sat/vb)",
            required_amount,
            fee_rate
        );

        let outpoint = self
            .rpc
            .send_to_address(&self.signer.address, required_amount)
            .await?;

        self.db
            .save_fee_payer_tx(
                None,
                bumped_id,
                outpoint.txid,
                outpoint.vout,
                required_amount,
                None,
            )
            .await?;

        Ok(outpoint)
    }

    /// Gets the current fee rate.
    ///
    /// If the fee rate is not estimable, it will return a fee rate of 1 sat/vb,
    /// **only for regtest**.
    ///
    /// TODO: Use more sophisticated fee estimation, like the one in mempool.space
    async fn get_fee_rate(&self) -> Result<FeeRate, BridgeError> {
        let fee_rate = self
            .rpc
            .client
            .estimate_smart_fee(1, Some(EstimateMode::Conservative))
            .await?;

        match fee_rate.fee_rate {
            Some(fee_rate) => Ok(FeeRate::from_sat_per_kwu(fee_rate.to_sat())),
            None => {
                if self.network == bitcoin::Network::Regtest {
                    // TODO: Looks like this check never occurs.
                    tracing::debug!("Using fee rate of 1 sat/vb (Regtest mode)");
                    return Ok(FeeRate::from_sat_per_vb_unchecked(1));
                }

                Err(BridgeError::FeeEstimationError(
                    fee_rate
                        .errors
                        .expect("Fee estimation errors should be present"),
                ))
            }
        }
    }

    /// Calculates the required total fee of a CPFP child tx.
    fn calculate_required_fee(
        parent_tx_weight: Weight,
        num_fee_payer_utxos: usize,
        fee_rate: FeeRate,
    ) -> Result<Amount, BridgeError> {
        // Each additional p2tr input adds 230 WU and each additional p2tr
        // output adds 172 WU to the transaction:
        // https://bitcoin.stackexchange.com/a/116959
        let child_tx_weight = Weight::from_wu_usize(230 * num_fee_payer_utxos + 207 + 172);

        // When effective fee rate is calculated, it calculates vBytes of the tx not the total weight.
        let total_weight = Weight::from_vb_unchecked(
            child_tx_weight.to_vbytes_ceil() + parent_tx_weight.to_vbytes_ceil(),
        );

        fee_rate
            .checked_mul_by_weight(total_weight)
            .ok_or(BridgeError::Overflow)
    }

    /// We want to allocate more than the required amount to be able to bump fees.
    /// This assumes the child tx has 1 p2a anchor input, 1 fee payer utxo input and 1 change output.
    fn calculate_required_amount_for_fee_payer_utxo(
        parent_tx_size: Weight,
        fee_rate: FeeRate,
    ) -> Result<Amount, BridgeError> {
        let required_fee = Self::calculate_required_fee(parent_tx_size, 1, fee_rate)?;

        Ok(required_fee * 3 + MIN_TAPROOT_AMOUNT)
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
    ) -> Result<Transaction, BridgeError> {
        let required_fee =
            Self::calculate_required_fee(parent_tx_size, fee_payer_utxos.len(), fee_rate)?;

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + builder::transaction::anchor_output().value; // We add the anchor output value to the total amount.

        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(BridgeError::InsufficientFeePayerAmount);
        }

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::NotStored,
                SpendableTxIn::new_partial(p2a_anchor, builder::transaction::anchor_output()),
                SpendPath::Unknown,
                DEFAULT_SEQUENCE,
            );

        for fee_payer_utxo in fee_payer_utxos {
            builder = builder.add_input(
                NormalSignatureKind::NotStored,
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

        let sighash =
            tx_handler.calculate_pubkey_spend_sighash(1, bitcoin::TapSighashType::Default)?;
        let signature = self.signer.sign_with_tweak(sighash, None)?;
        tx_handler.set_p2tr_key_spend_witness(
            &bitcoin::taproot::Signature {
                signature,
                sighash_type: bitcoin::TapSighashType::Default,
            },
            1,
        )?;
        let child_tx = tx_handler.get_cached_tx().clone();
        Ok(child_tx)
    }

    fn is_p2a_anchor(&self, output: &TxOut) -> bool {
        output.value == builder::transaction::anchor_output().value
            && output.script_pubkey == builder::transaction::anchor_output().script_pubkey
    }

    fn find_p2a_vout(&self, tx: &Transaction) -> Result<usize, BridgeError> {
        let p2a_anchor = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| self.is_p2a_anchor(output));
        if let Some((vout, _)) = p2a_anchor {
            Ok(vout)
        } else {
            Err(BridgeError::P2AAnchorNotFound)
        }
    }

    /// Submit package returns the effective fee rate in btc/kvb.
    /// This function converts the btc/kvb to a fee rate in sat/vb.
    fn btc_per_kvb_to_fee_rate(btc_per_kvb: f64) -> FeeRate {
        FeeRate::from_sat_per_vb_unchecked((btc_per_kvb * 100000.0) as u64)
    }

    fn add_fee_payer_utxos_to_tx(
        &self,
        tx: Transaction,
        fee_payer_utxos: Vec<SpendableTxIn>,
        fee_rate: FeeRate,
    ) -> Result<Transaction, BridgeError> {
        // Each additional p2tr input adds 230 WU and each additional p2tr
        // output adds 172 WU to the transaction:
        let tx_size = tx.weight() + Weight::from_wu_usize(fee_payer_utxos.len() * 230 + 172);
        let required_fee = fee_rate
            .checked_mul_by_weight(tx_size)
            .ok_or(BridgeError::Overflow)?;

        let input_amount = Amount::from_sat(0); // TODO: Fix this
        let output_amount = tx.output.iter().map(|output| output.value).sum::<Amount>();

        if input_amount < output_amount + required_fee {
            return Err(BridgeError::InsufficientFeePayerAmount);
        }

        let change_amount = input_amount - output_amount - required_fee;

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy).with_version(tx.version);

        for input in tx.input {
            builder = builder.add_input_with_witness(
                SpendableTxIn::new_partial(input.previous_output, TxOut::NULL),
                input.sequence,
                input.witness,
            );
        }

        for fee_payer_utxo in fee_payer_utxos {
            builder = builder.add_input(
                NormalSignatureKind::NotStored,
                fee_payer_utxo,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            );
        }

        for output in tx.output {
            builder = builder.add_output(UnspentTxOut::from_partial(output));
        }

        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: change_amount,
            script_pubkey: self.signer.address.script_pubkey(),
        }));

        let mut tx_handler = builder.finalize();

        self.signer.tx_sign_and_fill_sigs(&mut tx_handler, &[])?;

        Ok(tx_handler.get_cached_tx().clone())
    }

    fn create_package(
        &self,
        tx: Transaction,
        fee_rate: FeeRate,
        fee_payer_utxos: Vec<SpendableTxIn>,
        fee_paying_type: FeePayingType,
    ) -> Result<Vec<Transaction>, BridgeError> {
        match fee_paying_type {
            FeePayingType::CPFP => {
                let p2a_vout = self.find_p2a_vout(&tx)?;
                let txid = tx.compute_txid();

                let child_tx = self.create_child_tx(
                    OutPoint {
                        txid,
                        vout: p2a_vout as u32,
                    },
                    fee_payer_utxos,
                    tx.weight(),
                    fee_rate,
                    self.signer.address.clone(),
                )?;

                Ok(vec![tx, child_tx])
            }
            FeePayingType::RBF => {
                let tx = self.add_fee_payer_utxos_to_tx(tx, fee_payer_utxos, fee_rate)?;

                Ok(vec![tx])
            }
        }
    }

    /// Sends a tx with CPFP.
    /// Returns the effective fee rate of the tx.
    /// If the effective fee rate is lower than the required fee rate, it will return an error.
    /// If the fee payer tx is not confirmed, it will return an error.
    async fn send_tx_with_cpfp(
        &self,
        id: i32,
        fee_paying_type: FeePayingType,
        fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let unconfirmed_fee_payer_utxos = self.db.get_unconfirmed_fee_payer_utxos(None, id).await?;
        if !unconfirmed_fee_payer_utxos.is_empty() {
            return Err(BridgeError::UnconfirmedFeePayerUTXOsLeft);
        }

        let fee_payer_utxos = self.db.get_confirmed_fee_payer_utxos(None, id).await?;

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

        let tx = self.db.get_tx(None, id).await?;

        let package = self.create_package(tx, fee_rate, fee_payer_utxos, fee_paying_type)?;
        let package_refs: Vec<&Transaction> = package.iter().collect();
        let submit_package_result = self.rpc.client.submit_package(&package_refs[..]).await?;

        tracing::debug!("Submit package result: {:?}", submit_package_result);

        // If tx_results is empty, it means the txs were already accepted by the network.
        if submit_package_result.tx_results.is_empty() {
            return Ok(());
        }
        // Get the effective fee rate from the first transaction result
        let effective_fee_rate_btc_per_kvb = submit_package_result
            .tx_results
            .iter()
            .next()
            .map(|(_, result)| result.fees.effective_feerate)
            .expect("Effective fee rate should be present")
            .expect("Effective fee rate should be present");

        let effective_fee_rate = Self::btc_per_kvb_to_fee_rate(effective_fee_rate_btc_per_kvb);
        // Save the effective fee rate to the db
        self.db
            .update_effective_fee_rate(None, id, effective_fee_rate)
            .await?;

        // Sanity check to make sure the fee rate is equal to the required fee rate
        // assert_eq!(
        //     effective_fee_rate, fee_rate,
        //     "Effective fee rate is not equal to the required fee rate: {:?} to {:?} != {:?}",
        //     effective_fee_rate_btc_per_kvb, effective_fee_rate, fee_rate
        // );

        Ok(())
    }

    async fn bump_fees_of_fee_payer_txs(
        &self,
        bumped_id: i32,
        fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let bumpable_fee_payer_txs = self.db.get_bumpable_fee_payer_txs(None, bumped_id).await?;

        for (id, fee_payer_txid, vout, amount) in bumpable_fee_payer_txs {
            let new_txid_result = self
                .rpc
                .bump_fee_with_fee_rate(fee_payer_txid, fee_rate)
                .await;

            match new_txid_result {
                Ok(_new_txid) => {
                    self.db
                        .save_fee_payer_tx(
                            None,
                            bumped_id,
                            new_txid_result.expect("New txid result is None"),
                            vout,
                            amount,
                            Some(id),
                        )
                        .await?;
                }
                Err(e) => match e {
                    BridgeError::BumpFeeUTXOSpent(outpoint) => {
                        tracing::error!("Fee payer UTXO is spent, skipping : {:?}", outpoint);
                        continue;
                    }
                    _ => return Err(e),
                },
            }
        }

        Ok(())
    }

    /// Tries to send unconfirmed txs that have a new effective fee rate.
    /// Tries to bump fees of fee payer UTXOs with RBF
    async fn try_to_send_unconfirmed_txs(
        &self,
        new_fee_rate: FeeRate,
        current_tip_height: u64,
    ) -> Result<(), BridgeError> {
        let txids = self
            .db
            .get_sendable_txs(None, new_fee_rate, current_tip_height)
            .await?;
        tracing::info!("TXSENDER: Found {} sendable txs", txids.len());
        tracing::info!("TXSENDER: Bumping fees of fee payer UTXOs");

        for (id, fee_paying_type) in txids {
            self.bump_fees_of_fee_payer_txs(id, new_fee_rate).await?;
            let send_tx_with_cpfp_result = self
                .send_tx_with_cpfp(id, fee_paying_type, new_fee_rate)
                .await;
            match send_tx_with_cpfp_result {
                Ok(_) => {}
                Err(e) => {
                    match e {
                        BridgeError::InsufficientFeePayerAmount => {
                            tracing::error!("TXSENDER: Insufficient fee payer amount, creating new fee payer UTXO");
                            let tx = self.db.get_tx(None, id).await?;
                            let _fee_payer_utxo = self
                                .create_fee_payer_utxo(id, tx.weight(), fee_paying_type)
                                .await?;
                            continue;
                        }
                        _ => {
                            tracing::error!("TXSENDER: Error sending tx with CPFP: {:?}", e);
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_syncer;
    use crate::builder::script::{CheckSig, SpendableScript};
    use crate::builder::transaction::TransactionType;
    use crate::config::BridgeConfig;
    use crate::utils::{initialize_logger, SECP};
    use crate::{
        create_regtest_rpc, create_test_config_with_thread_name, database::Database,
        initialize_database,
    };
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use secp256k1::rand;
    use std::sync::Arc;

    async fn create_test_tx_sender(
        rpc: ExtendedRpc,
    ) -> (TxSender, ExtendedRpc, Database, Actor, bitcoin::Network) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = bitcoin::Network::Regtest;
        let actor = Actor::new(sk, None, network);

        let config = create_test_config_with_thread_name!(None);

        let db = Database::new(&config).await.unwrap();

        let tx_sender = TxSender::new(actor.clone(), rpc.clone(), db.clone(), network);

        (tx_sender, rpc, db, actor, network)
    }

    async fn create_bumpable_tx(
        rpc: &ExtendedRpc,
        signer: Actor,
        network: bitcoin::Network,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

        let amount = Amount::from_sat(100000);
        let outpoint = rpc.send_to_address(&address, amount).await?;
        rpc.mine_blocks(1).await?;

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::NotStored,
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

        let sighash =
            builder.calculate_pubkey_spend_sighash(0, bitcoin::TapSighashType::Default)?;
        let signature = signer.sign_with_tweak(sighash, None)?;
        builder.set_p2tr_key_spend_witness(
            &bitcoin::taproot::Signature {
                signature,
                sighash_type: bitcoin::TapSighashType::Default,
            },
            0,
        )?;

        let tx = builder.get_cached_tx().clone();
        Ok(tx)
    }

    #[tokio::test]
    async fn test_create_fee_payer_tx() {
        let mut config = create_test_config_with_thread_name!(None);
        let regtest = create_regtest_rpc!(config);
        let rpc = regtest.rpc().clone();
        rpc.mine_blocks(1).await.unwrap();

        let (tx_sender, rpc, db, signer, network) = create_test_tx_sender(rpc).await;

        let _bitcoin_syncer_handle =
            bitcoin_syncer::start_bitcoin_syncer(db, rpc.clone(), Duration::from_secs(1))
                .await
                .unwrap();

        let _tx_sender_handle = tx_sender
            .run("tx_sender", Duration::from_secs(0))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;

        let tx = create_bumpable_tx(&rpc, signer, network).await.unwrap();

        let _outpoint = tx_sender
            .create_fee_payer_utxo(1, tx.weight(), FeePayingType::CPFP)
            .await
            .unwrap();
        tx_sender
            .try_to_send(&tx, FeePayingType::CPFP, &[], &[], &[])
            .await
            .unwrap();

        // Mine a block and wait for confirmation
        rpc.mine_blocks(1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;

        // get the tx from the rpc
        let get_raw_transaction_result = rpc
            .client
            .get_raw_transaction(&tx.compute_txid(), None)
            .await
            .unwrap();

        tracing::info!(
            "Get raw transaction result: {:?}",
            get_raw_transaction_result
        );
    }

    #[tokio::test]
    async fn get_fee_rate() {
        let mut config = create_test_config_with_thread_name!(None);
        let regtest = create_regtest_rpc!(config);
        let rpc: ExtendedRpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let amount = Amount::from_sat(100_000);
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );
        let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

        let tx_sender = TxSender::new(signer.clone(), rpc.clone(), db, config.network);

        let scripts: Vec<Arc<dyn SpendableScript>> =
            vec![Arc::new(CheckSig::new(xonly_pk)).clone()];
        let (taproot_address, taproot_spend_info) = builder::address::create_taproot_address(
            &scripts
                .iter()
                .map(|s| s.to_script_buf())
                .collect::<Vec<_>>(),
            None,
            config.network,
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
        signer
            .tx_sign_and_fill_sigs(&mut will_fail_handler, &[])
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        let will_fail_tx = will_fail_handler.get_cached_tx();
        assert!(rpc.client.send_raw_transaction(will_fail_tx).await.is_err());

        // Calculate and send with fee.
        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        let fee = TxSender::calculate_required_fee(will_fail_tx.weight(), 1, fee_rate).unwrap();
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
            .tx_sign_and_fill_sigs(&mut will_successful_handler, &[])
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        rpc.client
            .send_raw_transaction(will_successful_handler.get_cached_tx())
            .await
            .unwrap();
    }
}
