use std::{collections::BTreeMap, time::Duration};

use bitcoin::{
    transaction::Version, Address, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight,
};
use bitcoincore_rpc::{json::EstimateMode, PackageTransactionResult, RpcApi};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

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
};

#[derive(Clone, Debug)]
pub struct TxSender {
    pub signer: Actor,
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub network: bitcoin::Network,
    pub consumer_handle: String,
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
pub struct TxDataForLogging {
    pub deposit_outpoint: Option<OutPoint>,
    pub operator_idx: Option<u32>,
    pub verifier_idx: Option<u32>,
    pub round_idx: Option<u32>,
    pub kickoff_idx: Option<u32>,
    pub tx_type: TransactionType,
}

impl TxSender {
    pub fn new(
        signer: Actor,
        rpc: ExtendedRpc,
        db: Database,
        consumer_handle: &str,
        network: bitcoin::Network,
    ) -> Self {
        Self {
            signer,
            rpc,
            db,
            consumer_handle: consumer_handle.to_string(),
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
        poll_delay: Duration,
    ) -> Result<JoinHandle<Result<(), BridgeError>>, BridgeError> {
        // Clone the required fields for the async task
        let db = self.db.clone();
        let consumer_handle = self.consumer_handle.clone();
        let this = self.clone();

        tracing::trace!(
            "TXSENDER: Starting tx sender with handle {}",
            consumer_handle
        );

        let handle = tokio::spawn(async move {
            let mut current_tip_height = 0;
            loop {
                let result: Result<bool, BridgeError> = async {
                    let mut dbtx = db.begin_transaction().await?;

                    let is_block_update = async {
                        let event = db.get_event_and_update(&mut dbtx, &consumer_handle).await?;
                        Ok::<bool, BridgeError>(match event {
                            Some(event) => match event {
                                BitcoinSyncerEvent::NewBlock(block_id) => {
                                    db.confirm_transactions(&mut dbtx, block_id).await?;
                                    current_tip_height = db
                                        .get_block_info_from_id(Some(&mut dbtx), block_id)
                                        .await?
                                        .ok_or(BridgeError::Error("Block not found".to_string()))?
                                        .1;

                                    tracing::trace!(
                                        "TXSENDER: Confirmed transactions for block {}",
                                        block_id
                                    );
                                    dbtx.commit().await?;
                                    true
                                }
                                BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                                    tracing::trace!(
                                        "TXSENDER: Unconfirming transactions for block {}",
                                        block_id
                                    );
                                    db.unconfirm_transactions(&mut dbtx, block_id).await?;
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

                    tracing::trace!("TXSENDER: Getting fee rate");
                    let fee_rate = this.get_fee_rate().await?;
                    tracing::trace!("TXSENDER: Trying to send unconfirmed txs");
                    this.try_to_send_unconfirmed_txs(fee_rate, current_tip_height)
                        .await?;

                    Ok(false)
                }
                .await;

                match result {
                    Ok(true) => {}
                    Ok(false) => {
                        tokio::time::sleep(poll_delay).await;
                    }
                    Err(e) => {
                        tracing::error!("TXSENDER: Error sending txs: {:?}", e);
                        tokio::time::sleep(poll_delay).await;
                    }
                }
            }
        });

        Ok(handle)
    }

    pub async fn add_tx_to_queue<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_data_for_logging: Option<TxDataForLogging>,
        config: &BridgeConfig,
    ) -> Result<u32, BridgeError> {
        let tx_data_for_logging = tx_data_for_logging.map(|mut data| {
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
            | TransactionType::WatchtowerChallenge(_)
            | TransactionType::UnspentKickoff(_)
            | TransactionType::Challenge
            | TransactionType::Payout
            | TransactionType::MoveToVault
            | TransactionType::AssertTimeout(_)
            | TransactionType::Disprove
            | TransactionType::BurnUnusedKickoffConnectors
            | TransactionType::KickoffNotFinalized
            | TransactionType::MiniAssert(_) => {
                // no_dependency and cpfp
                self.try_to_send(
                    dbtx,
                    tx_data_for_logging,
                    signed_tx,
                    FeePayingType::CPFP,
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
                    .ok_or(BridgeError::Error(
                        "Couldn't find kickoff tx in related_txs".to_string(),
                    ))?;
                self.try_to_send(
                    dbtx,
                    tx_data_for_logging,
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
                    .ok_or(BridgeError::Error(
                        "Couldn't find kickoff tx in related_txs".to_string(),
                    ))?;
                self.try_to_send(
                    dbtx,
                    tx_data_for_logging,
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
                        relative_block_height: config.confirmation_threshold,
                    }],
                )
                .await
            }
            TransactionType::AllNeededForDeposit => unreachable!(),
            TransactionType::ReadyToReimburse => unimplemented!(),
        }
    }

    /// Tries to send a tx. If all conditions are met, it will save the tx to the database.
    /// It will also save the cancelled outpoints, cancelled txids and activated prerequisite txs to the database.
    /// It will automatically save inputs as cancelled outpoints.
    /// It will automatically save inputs as activated outpoints.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn try_to_send(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        tx_data_for_logging: Option<TxDataForLogging>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
    ) -> Result<u32, BridgeError> {
        tracing::info!(
            "{} added tx {:?} with tx_data_for_logging: {:?}",
            self.consumer_handle,
            tx_data_for_logging
                .map(|data| data.tx_type)
                .unwrap_or(TransactionType::Dummy),
            tx_data_for_logging
        );
        let txid = signed_tx.compute_txid();
        let try_to_send_id = self
            .db
            .save_tx(
                Some(dbtx),
                tx_data_for_logging,
                signed_tx,
                fee_paying_type,
                txid,
            )
            .await?;

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, input_outpoint)
                .await?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, *outpoint)
                .await?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(Some(dbtx), try_to_send_id, *txid)
                .await?;
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
                let relatetive_locktime = input
                    .sequence
                    .to_relative_lock_time()
                    .expect("Invalid relative locktime");
                match relatetive_locktime {
                    bitcoin::relative::LockTime::Blocks(height) => height.value() as u32,
                    _ => {
                        return Err(BridgeError::Error("Invalid relative locktime".to_string()));
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
                .await?;
        }

        for activated_outpoint in activate_outpoints {
            self.db
                .save_activated_outpoint(Some(dbtx), try_to_send_id, activated_outpoint)
                .await?;
        }

        Ok(try_to_send_id)
    }

    /// Creates a fee payer UTXO for a transaction.
    /// The fee paying type can be either CPFP or RBF.
    async fn create_fee_payer_utxo(
        &self,
        bumped_id: u32,
        tx: &Transaction,
        fee_rate: FeeRate,
        fee_paying_type: FeePayingType,
        total_fee_payer_amount: Amount,
        fee_payer_utxos_len: usize,
    ) -> Result<(), BridgeError> {
        let required_fee = Self::calculate_required_fee(
            tx.weight(),
            fee_payer_utxos_len + 1,
            fee_rate,
            fee_paying_type,
        )?;

        // calculate additional if the tx is bumpable by RBF
        // This will only be non-zero for the Challenge Tx
        let additional_amount = if fee_paying_type == FeePayingType::RBF {
            // We assume the input amount is always the minimum amount.
            tx.output.iter().map(|output| output.value).sum::<Amount>()
        } else {
            Amount::from_sat(0)
        };

        let required_amount = if additional_amount > total_fee_payer_amount {
            // This means we haven't added the additional amount for the Challenge Tx
            assert!(total_fee_payer_amount == Amount::from_sat(0));
            additional_amount + required_fee + required_fee + required_fee + MIN_TAPROOT_AMOUNT
        } else {
            (additional_amount + required_fee - total_fee_payer_amount)
                + required_fee
                + required_fee
                + required_fee
                + MIN_TAPROOT_AMOUNT
        };

        // let required_amount = Amount::from_sat(5000);

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

        Ok(())
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
        fee_paying_type: FeePayingType,
    ) -> Result<Amount, BridgeError> {
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
            .ok_or(BridgeError::Overflow)
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
        let required_fee = Self::calculate_required_fee(
            parent_tx_size,
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::CPFP,
        )?;

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
    #[allow(dead_code)]
    fn btc_per_kvb_to_fee_rate(btc_per_kvb: f64) -> FeeRate {
        FeeRate::from_sat_per_vb_unchecked((btc_per_kvb * 100000.0) as u64)
    }

    /// Adds fee payer utxos to a tx that is bumpable by RBF.
    fn add_fee_payer_utxos_to_tx(
        &self,
        tx: Transaction,
        fee_payer_utxos: Vec<SpendableTxIn>,
        fee_rate: FeeRate,
    ) -> Result<Transaction, BridgeError> {
        let required_fee = Self::calculate_required_fee(
            tx.weight(),
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::RBF,
        )?;

        let input_amount = MIN_TAPROOT_AMOUNT; // We assume the input amount is always the minimum amount.
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

        let mut tx_handler: builder::transaction::TxHandler = builder.finalize();

        self.signer.tx_sign_and_fill_sigs(&mut tx_handler, &[])?;

        Ok(tx_handler.get_cached_tx().clone())
    }

    /// Creates a package of txs that will be submitted to the network.
    /// The package will be a CPFP package if fee_paying_type is CPFP,
    /// otherwise it will be a single tx with fee payer utxos.
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

    /// Sends the tx with the given fee_rate.
    async fn send_tx(&self, id: u32, fee_rate: FeeRate) -> Result<(), BridgeError> {
        let unconfirmed_fee_payer_utxos = self.db.get_bumpable_fee_payer_txs(None, id).await?;
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

        let (tx_data_for_logging, tx, fee_paying_type, _) = self.db.get_tx(None, id).await?;

        let package = self.create_package(tx, fee_rate, fee_payer_utxos, fee_paying_type)?;
        let package_refs: Vec<&Transaction> = package.iter().collect();

        // If the tx is RBF, we should note the txid of the package.
        if fee_paying_type == FeePayingType::RBF {
            self.db
                .save_rbf_txid(None, id, package[0].compute_txid())
                .await?;
        }
        tracing::info!(
            "Submitting package for tx_type: {:?}, round_idx: {:?}, kickoff_idx: {:?}, operator_idx: {:?}, verifier_idx: {:?}, deposit_outpoint: {:?}, details: {:?} ",
            tx_data_for_logging.as_ref().map(|d| d.tx_type),
            tx_data_for_logging.as_ref().map(|d| d.round_idx),
            tx_data_for_logging.as_ref().map(|d| d.kickoff_idx),
            tx_data_for_logging.as_ref().map(|d| d.operator_idx),
            tx_data_for_logging.as_ref().map(|d| d.verifier_idx),
            tx_data_for_logging.as_ref().map(|d| d.deposit_outpoint),
            package
                .iter()
                .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                .collect::<Vec<_>>()
        );
        let submit_package_result = self
            .rpc
            .client
            .submit_package(&package_refs[..])
            .await
            .inspect_err(|e| {
                tracing::warn!(
                    "{}: failed to submit package with error {:?}",
                    self.consumer_handle,
                    e
                );
            })?;

        tracing::error!(
            self.consumer_handle,
            ?tx_data_for_logging,
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
                break;
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
            .await?;

        // Sanity check to make sure the fee rate is equal to the required fee rate
        // assert_eq!(
        //     effective_fee_rate, fee_rate,
        //     "Effective fee rate is not equal to the required fee rate: {:?} to {:?} != {:?}",
        //     effective_fee_rate_btc_per_kvb, effective_fee_rate, fee_rate
        // );

        Ok(())
    }

    /// Tries to bump fees of fee payer txs with the given fee_rate.
    async fn bump_fees_of_fee_payer_txs(
        &self,
        bumped_id: u32,
        fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let bumpable_fee_payer_txs = self.db.get_bumpable_fee_payer_txs(None, bumped_id).await?;

        for (id, fee_payer_txid, vout, amount) in bumpable_fee_payer_txs {
            let new_txi_result = self
                .rpc
                .bump_fee_with_fee_rate(fee_payer_txid, fee_rate)
                .await;

            match new_txi_result {
                Ok(new_txid) => {
                    self.db
                        .save_fee_payer_tx(None, bumped_id, new_txid, vout, amount, Some(id))
                        .await?;
                }
                Err(e) => match e {
                    BridgeError::BumpFeeUTXOSpent(outpoint) => {
                        tracing::error!("{}: Fee payer UTXO for the bumped tx {} is already onchain, skipping : {:?}", self.consumer_handle, bumped_id, outpoint);
                        continue;
                    }
                    e => {
                        tracing::error!("{}: failed to bump fee the fee payer tx {} of bumped tx {} with error {e}, skipping", self.consumer_handle, fee_payer_txid, bumped_id);
                        continue;
                    }
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
        current_tip_height: u32,
    ) -> Result<(), BridgeError> {
        let txs = self
            .db
            .get_sendable_txs(None, new_fee_rate, current_tip_height)
            .await?;

        if !txs.is_empty() {
            tracing::error!(
                self.consumer_handle,
                "Trying to send unconfirmed txs with new fee rate: {new_fee_rate:?}, current tip height: {current_tip_height:?}, txs: {txs:?}"
            );
        }

        for id in txs {
            self.bump_fees_of_fee_payer_txs(id, new_fee_rate).await?;
            let send_tx_result = self.send_tx(id, new_fee_rate).await;
            match send_tx_result {
                Ok(_) => {}
                Err(e) => match e {
                    BridgeError::UnconfirmedFeePayerUTXOsLeft => {
                        tracing::info!(
                            "{}: Bumping Tx {} : Unconfirmed fee payer UTXOs left, skipping",
                            self.consumer_handle,
                            id
                        );
                        continue;
                    }
                    BridgeError::InsufficientFeePayerAmount => {
                        tracing::info!("{}: Bumping Tx {} : Insufficient fee payer amount, creating new fee payer UTXO", self.consumer_handle, id);
                        let (_, tx, fee_paying_type, _) = self.db.get_tx(None, id).await?;
                        let fee_payer_utxos =
                            self.db.get_confirmed_fee_payer_utxos(None, id).await?;
                        let total_fee_payer_amount = fee_payer_utxos
                            .iter()
                            .map(|(_, _, amount)| *amount)
                            .sum::<Amount>();
                        let fee_payer_utxos_len = fee_payer_utxos.len();
                        self.create_fee_payer_utxo(
                            id,
                            &tx,
                            new_fee_rate,
                            fee_paying_type,
                            total_fee_payer_amount,
                            fee_payer_utxos_len,
                        )
                        .await?;

                        continue;
                    }
                    _ => {
                        tracing::error!(
                            "{}: Bumping Tx {} : Error sending tx with CPFP: {:?}",
                            self.consumer_handle,
                            id,
                            e
                        );
                        continue;
                    }
                },
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_syncer;
    use crate::bitvm_client::SECP;
    use crate::builder::script::{CheckSig, SpendableScript};
    use crate::builder::transaction::TransactionType;
    use crate::{database::Database, test::common::*};
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

        let config = create_test_config_with_thread_name(None).await;

        let db = Database::new(&config).await.unwrap();

        let tx_sender = TxSender::new(actor.clone(), rpc.clone(), db.clone(), "tx_sender", network);

        (tx_sender, rpc, db, actor, network)
    }

    async fn create_bumpable_tx(
        rpc: &ExtendedRpc,
        signer: Actor,
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
        let signature = signer.sign_with_tweak(sighash, None)?;
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
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();

        let (tx_sender, rpc, db, signer, network) = create_test_tx_sender(rpc).await;

        let _bitcoin_syncer_handle =
            bitcoin_syncer::start_bitcoin_syncer(db.clone(), rpc.clone(), Duration::from_secs(1))
                .await
                .unwrap();

        let _tx_sender_handle = tx_sender.run(Duration::from_secs(1)).await.unwrap();

        let tx = create_bumpable_tx(&rpc, signer.clone(), network, FeePayingType::CPFP)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        let tx_id1 = tx_sender
            .try_to_send(
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
        let tx_id2 = tx_sender
            .try_to_send(
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

        let tx2 = create_bumpable_tx(&rpc, signer.clone(), network, FeePayingType::RBF)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        tx_sender
            .try_to_send(
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
        let mut config = create_test_config_with_thread_name(None).await;
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
            "tx_sender",
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
        signer
            .tx_sign_and_fill_sigs(&mut will_fail_handler, &[])
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        let will_fail_tx = will_fail_handler.get_cached_tx();
        assert!(rpc.client.send_raw_transaction(will_fail_tx).await.is_err());

        // Calculate and send with fee.
        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
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
            .tx_sign_and_fill_sigs(&mut will_successful_handler, &[])
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        rpc.client
            .send_raw_transaction(will_successful_handler.get_cached_tx())
            .await
            .unwrap();
    }
}
