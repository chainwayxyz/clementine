//! # Child Pays For Parent (CPFP) Support For Transaction Sender
//!
//! This module implements the Child Pays For Parent (CPFP) strategy for sending
//! Bitcoin transactions with transaction sender.
//!
//! ## Child Transaction Details
//!
//! A child transaction is created to pay for the fees of a parent transaction.
//! They must be submitted together as a package for Bitcoin nodes to accept
//! them.
//!
//! ### Fee Payer Transactions/UTXOs
//!
//! Child transaction needs to spend an UTXO for the fees. But because of the
//! TRUC rules (https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki#specification),
//! a third transaction can't be put into the package. So, a so called "fee
//! payer" transaction must be send and confirmed before the CPFP package is
//! send.

use super::{Result, SendTxError, TxMetadata, TxSender};
use crate::constants::NON_STANDARD_V3;
use crate::errors::{ErrorExt, ResultExt};
use crate::extended_bitcoin_rpc::{rpc_error_code, BitcoinRPCError, RPC_INVALID_ADDRESS_OR_KEY};
use crate::utils::FeePayingType;
use crate::{
    builder::{
        self,
        script::SpendPath,
        transaction::{
            input::SpendableTxIn, output::UnspentTxOut, TransactionType, TxHandlerBuilder,
            DEFAULT_SEQUENCE,
        },
    },
    constants::MIN_TAPROOT_AMOUNT,
    rpc::clementine::NormalSignatureKind,
};
use bitcoin::{Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight};
use bitcoincore_rpc::PackageSubmissionResult;
use bitcoincore_rpc::{PackageTransactionResult, RpcApi};
use eyre::eyre;
use eyre::{Context, OptionExt};
use std::collections::HashSet;
use std::env;

/// BIP431 limit on the virtual size of a child of an unconfirmed TRUC transaction.
const TRUC_CHILD_MAX_VSIZE: u64 = 1_000;

/// The mempool transaction that spends a CPFP parent's P2A anchor.
struct CurrentCpfpChild {
    txid: Txid,
    modified_fee: Amount,
    vsize: u64,
}

impl TxSender {
    /// Creates and broadcasts a new "fee payer" UTXO to be used for CPFP
    /// transactions.
    ///
    /// This function is called when a CPFP attempt fails due to insufficient funds
    /// in the existing confirmed fee payer UTXOs associated with a transaction (`bumped_id`).
    /// It calculates the required fee based on the parent transaction (`tx`) and the current
    /// `fee_rate`, adding a buffer (2x required fee + dust limit) to handle potential fee spikes.
    /// It then funds a transaction to the `TxSender`'s own signer address with the
    /// node's wallet, saves the resulting UTXO information (`outpoint`, `amount`)
    /// to the database, linking it to the `bumped_id`, and broadcasts it.
    ///
    /// The UTXO is saved before the broadcast: a broadcast whose outcome is unknown
    /// stays tracked, and a saved tx that never reaches the mempool is marked evicted
    /// by [`Self::bump_fees_of_unconfirmed_fee_payer_txs`].
    ///
    /// # Arguments
    /// * `bumped_id` - The database ID of the parent transaction requiring the fee bump.
    /// * `tx` - The parent transaction itself.
    /// * `fee_rate` - The target fee rate for the CPFP package.
    /// * `total_fee_payer_amount` - The sum of amounts in currently available confirmed fee payer UTXOs.
    /// * `fee_payer_utxos_len` - The number of currently available confirmed fee payer UTXOs.
    /// * `minimum_child_fee` - Core's absolute fee floor, when replacing a mempool child.
    async fn create_fee_payer_utxo(
        &self,
        bumped_id: u32,
        tx: &Transaction,
        fee_rate: FeeRate,
        total_fee_payer_amount: Amount,
        fee_payer_utxos_len: usize,
        minimum_child_fee: Option<Amount>,
    ) -> Result<()> {
        tracing::debug!(
            "Creating fee payer UTXO for txid {} with bump id {}",
            &tx.compute_txid().to_string(),
            bumped_id
        );
        let parent_tx_fee = self.get_tx_fee(tx).await.map_err(|e| eyre!(e))?;
        let required_fee = std::cmp::max(
            Self::calculate_required_fee(
                tx.weight(),
                parent_tx_fee,
                fee_payer_utxos_len + 1,
                fee_rate,
                FeePayingType::CPFP,
            )?,
            minimum_child_fee.unwrap_or(Amount::ZERO),
        );

        // Aggressively add 2x required fee to the total amount to account for sudden spikes
        // We won't actually use 2x fees, but the fee payer utxo will hold that much amount so that while fee payer utxo gets mined
        // if fees increase the utxo should still be sufficient to fund the tx with high probability
        // leftover fees will get sent back to wallet with a change output in fn create_child_tx
        let new_total_fee_needed = required_fee
            .checked_mul(2)
            .and_then(|fee| fee.checked_add(MIN_TAPROOT_AMOUNT));
        if new_total_fee_needed.is_none() {
            return Err(eyre!("Total fee needed is too large, required fee: {}, total fee payer amount: {}, fee rate: {}", required_fee, total_fee_payer_amount, fee_rate).into());
        }
        let new_fee_payer_amount =
            new_total_fee_needed.and_then(|fee| fee.checked_sub(total_fee_payer_amount));

        let new_fee_payer_amount = match new_fee_payer_amount {
            Some(fee) => fee,
            // if underflow, no new fee payer utxo is needed, log it anyway in case its a bug
            None => {
                tracing::debug!("create_fee_payer_utxo was called but no new fee payer utxo is needed for tx: {:?}, required fee: {}, total fee payer amount: {}, current fee rate: {}", tx, required_fee, total_fee_payer_amount, fee_rate);
                return Ok(());
            }
        };

        tracing::debug!(
            "Creating fee payer UTXO with amount {} ({} sat/vb)",
            new_fee_payer_amount,
            fee_rate
        );

        let fee_payer_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: new_fee_payer_amount,
                script_pubkey: self.signer.address.script_pubkey(),
            }],
        };

        // Manually serialize in legacy format for 0-input transactions
        // Because fund_raw_transaction RPC gives deserialization error for 0-input transactions with segwit flag
        // but in the end fund_raw_transaction returns a segwit transaction after adding inputs
        let fee_payer_bytes = if fee_payer_tx.input.is_empty() {
            use bitcoin::consensus::Encodable;
            let mut buf = Vec::new();
            // Serialize version
            fee_payer_tx
                .version
                .consensus_encode(&mut buf)
                .expect("Failed to serialize version");
            fee_payer_tx
                .input
                .consensus_encode(&mut buf)
                .expect("Failed to serialize inputs");
            fee_payer_tx
                .output
                .consensus_encode(&mut buf)
                .expect("Failed to serialize outputs");
            // Serialize locktime
            fee_payer_tx
                .lock_time
                .consensus_encode(&mut buf)
                .expect("Failed to serialize locktime");

            buf
        } else {
            bitcoin::consensus::encode::serialize(&fee_payer_tx)
        };

        let funded_fee_payer_tx = self
            .rpc
            .fund_raw_transaction(
                &fee_payer_bytes,
                Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
                    add_inputs: Some(true),
                    include_unsafe: Some(false),
                    change_address: None,
                    change_position: None,
                    change_type: None,
                    include_watching: None,
                    lock_unspents: None,
                    fee_rate: Some(Amount::from_sat(fee_rate.to_sat_per_vb_ceil() * 1000)),
                    subtract_fee_from_outputs: None,
                    replaceable: Some(true),
                    conf_target: None,
                    estimate_mode: None,
                }),
                None,
            )
            .await
            .wrap_err("Failed to fund cpfp fee payer tx")?
            .hex;

        let signed_fee_payer_tx: Transaction = bitcoin::consensus::deserialize(
            &self
                .rpc
                .sign_raw_transaction_with_wallet(&funded_fee_payer_tx, None, None)
                .await
                .wrap_err("Failed to sign funded tx through bitcoin RPC")?
                .hex,
        )
        .wrap_err("Failed to deserialize signed tx")?;

        let outpoint_vout = signed_fee_payer_tx
            .output
            .iter()
            .position(|o| {
                o.value == new_fee_payer_amount
                    && o.script_pubkey == self.signer.address.script_pubkey()
            })
            .ok_or(eyre!("Failed to find outpoint vout"))?;

        self.db
            .save_fee_payer_tx(
                None,
                bumped_id,
                signed_fee_payer_tx.compute_txid(),
                outpoint_vout as u32,
                new_fee_payer_amount,
                None,
            )
            .await
            .map_to_eyre()?;

        self.rpc
            .send_raw_transaction(&signed_fee_payer_tx)
            .await
            .wrap_err("Failed to send signed fee payer tx")?;

        Ok(())
    }

    /// Creates a Child-Pays-For-Parent (CPFP) child transaction.
    ///
    /// This transaction spends:
    /// 1.  The designated "P2A anchor" output of the parent transaction (`p2a_anchor`).
    /// 2.  One or more confirmed "fee payer" UTXOs (`fee_payer_utxos`) controlled by the `signer`.
    ///
    /// It calculates the total fee required (`required_fee`) to make the combined parent + child
    /// package attractive to miners at the target `fee_rate`, and at least `minimum_child_fee`.
    /// The `required_fee` is paid entirely by this child transaction.
    ///
    /// The remaining value (total input value - `required_fee`) is sent to the CPFP change script.
    ///
    /// # Signing
    /// We sign the input spending the P2A anchor and all fee payer UTXOs.
    ///
    /// # Returns
    /// The constructed and partially signed child transaction.
    #[allow(clippy::too_many_arguments)]
    async fn create_child_tx(
        &self,
        p2a_anchor: OutPoint,
        anchor_sat: Amount,
        fee_payer_utxos: Vec<SpendableTxIn>,
        parent_tx_size: Weight,
        parent_tx_fee: Amount,
        fee_rate: FeeRate,
        minimum_child_fee: Option<Amount>,
    ) -> Result<Transaction> {
        tracing::debug!(
            "Creating child tx with {} fee payer utxos",
            fee_payer_utxos.len()
        );
        let required_fee = std::cmp::max(
            Self::calculate_required_fee(
                parent_tx_size,
                parent_tx_fee,
                fee_payer_utxos.len(),
                fee_rate,
                FeePayingType::CPFP,
            )
            .map_err(|e| eyre!(e))?,
            minimum_child_fee.unwrap_or(Amount::ZERO),
        );

        let change_script_pubkey = self
            .cpfp_change_script_pubkey
            .get_or_try_init(|| async {
                Ok::<_, SendTxError>(
                    self.rpc
                        .get_new_wallet_address()
                        .await
                        .wrap_err("Failed to get CPFP change address")?
                        .script_pubkey(),
                )
            })
            .await?
            .clone();

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + anchor_sat; // We add the anchor output value to the total amount.
        if change_script_pubkey.minimal_non_dust() + required_fee > total_fee_payer_amount {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(NON_STANDARD_V3)
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new_partial(
                    p2a_anchor,
                    builder::transaction::anchor_output(anchor_sat),
                ),
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
            script_pubkey: change_script_pubkey,
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

    /// Creates a transaction package for CPFP submission.
    ///
    /// Finds the P2A anchor output in the parent transaction (`tx`), then constructs
    /// the child transaction using `create_child_tx`.
    ///
    /// # Returns
    ///
    /// - [`Vec<Transaction>`]: Parent transaction followed by the child
    ///   transaction ready for submission via the `submitpackage` RPC.
    async fn create_package(
        &self,
        tx: Transaction,
        fee_rate: FeeRate,
        fee_payer_utxos: Vec<SpendableTxIn>,
        minimum_child_fee: Option<Amount>,
    ) -> Result<Vec<Transaction>> {
        tracing::debug!(
            "Creating package with {} fee payer utxos",
            fee_payer_utxos.len()
        );
        let txid = tx.compute_txid();

        let p2a_vout = self
            .find_p2a_vout(&tx)
            .wrap_err("Failed to find p2a vout")?;

        // get sat amount of anchor output in the tx
        let anchor_sat = tx.output[p2a_vout].value;
        let parent_tx_fee = self.get_tx_fee(&tx).await.map_err(|e| eyre!(e))?;

        let child_tx = self
            .create_child_tx(
                OutPoint {
                    txid,
                    vout: p2a_vout as u32,
                },
                anchor_sat,
                fee_payer_utxos,
                tx.weight(),
                parent_tx_fee,
                fee_rate,
                minimum_child_fee,
            )
            .await
            .wrap_err("Failed to create child tx")?;

        Ok(vec![tx, child_tx])
    }

    /// Retrieves confirmed fee payer UTXOs associated with a specific send attempt.
    ///
    /// Queries the database for UTXOs linked to `try_to_send_id` that are marked as confirmed.
    /// These UTXOs are controlled by the `TxSender`'s `signer` and are intended to be
    /// spent by a CPFP child transaction.
    ///
    /// # Returns
    ///
    /// - [`Vec<SpendableTxIn>`]: [`SpendableTxIn`]s of the confirmed fee payer
    ///   UTXOs that are ready to be included as inputs in the CPFP child tx.
    async fn get_confirmed_fee_payer_utxos(
        &self,
        try_to_send_id: u32,
    ) -> Result<Vec<SpendableTxIn>> {
        Ok(self
            .db
            .get_confirmed_fee_payer_utxos(None, try_to_send_id)
            .await
            .map_to_eyre()?
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
                    Some(self.cached_spendinfo.clone()),
                )
            })
            .collect())
    }

    /// Attempts to bump the fees of unconfirmed "fee payer" UTXOs using RBF.
    ///
    /// Fee payer UTXOs are created to fund CPFP child transactions. However, these
    /// fee payer creation transactions might themselves get stuck due to low fees.
    /// This function identifies such unconfirmed fee payer transactions and
    /// attempts to RBF them using the provided `fee_rate`.
    ///
    /// This ensures the fee payer UTXOs confirm quickly, making them available to be spent
    /// by the actual CPFP child transaction.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, fee_rate))]
    pub(crate) async fn bump_fees_of_unconfirmed_fee_payer_txs(
        &self,
        fee_rate: FeeRate,
    ) -> Result<()> {
        let bumpable_fee_payer_txs = self
            .db
            .get_all_unconfirmed_fee_payer_txs(None)
            .await
            .map_to_eyre()?;

        let mut not_evicted_ids = HashSet::new();
        let mut all_parent_ids = HashSet::new();

        for (id, try_to_send_id, fee_payer_txid, _vout, amount, replacement_of_id) in
            bumpable_fee_payer_txs
        {
            tracing::debug!(
                "Bumping fee for fee payer tx {} for try to send id {} for fee rate {}",
                fee_payer_txid,
                try_to_send_id,
                fee_rate
            );
            // parent id is the id of the first created tx for all replacements
            let parent_id = match replacement_of_id {
                Some(replacement_of_id) => replacement_of_id,
                None => id,
            };
            all_parent_ids.insert(parent_id);
            let mempool_info = self.rpc.get_mempool_entry(&fee_payer_txid).await;
            let mempool_info = match mempool_info {
                Ok(mempool_info) => {
                    not_evicted_ids.insert(parent_id);
                    mempool_info
                }
                Err(e) => {
                    // If not in mempool we should ignore
                    // give an error if the error is not "Transaction not in mempool"
                    if !e.to_string().contains("Transaction not in mempool") {
                        return Err(eyre::eyre!(
                            "Failed to get mempool entry for fee payer tx {}: {}",
                            fee_payer_txid,
                            e
                        )
                        .into());
                    }
                    // check here if the tx is already in block, if so do not mark it as evicted
                    let tx_info = self.rpc.get_transaction(&fee_payer_txid, None).await;
                    if let Ok(tx_info) = tx_info {
                        if tx_info.info.blockhash.is_some() && tx_info.info.confirmations > 0 {
                            not_evicted_ids.insert(parent_id);
                        }
                    }
                    continue;
                }
            };
            // only try to bump if tx has no descendants and some time has passed since tx was created
            if mempool_info.descendant_count > 1
                || std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .wrap_err("Failed to get unix timestamp")?
                    .as_secs()
                    .saturating_sub(mempool_info.time)
                    < self
                        .config
                        .tx_sender_limits
                        .cpfp_fee_payer_bump_wait_time_seconds
            {
                continue;
            }
            let bumped_tx = match self.rpc.create_fee_bump_tx(fee_payer_txid, fee_rate).await {
                Ok(Some(bumped_tx)) => bumped_tx,
                Ok(None) => {
                    tracing::trace!(
                        "Fee payer tx {} has enough fee, no need to bump",
                        fee_payer_txid
                    );
                    continue;
                }
                Err(e) => {
                    let e = e.into_eyre();
                    match e.root_cause().downcast_ref::<BitcoinRPCError>() {
                        Some(BitcoinRPCError::TransactionAlreadyInBlock(block_hash)) => {
                            tracing::debug!(
                                "Fee payer tx {} is already in block {}, skipping",
                                fee_payer_txid,
                                block_hash
                            );
                            continue;
                        }
                        Some(BitcoinRPCError::BumpFeeUTXOSpent(outpoint)) => {
                            tracing::debug!(
                                "Fee payer tx {} is already onchain, skipping: {:?}",
                                fee_payer_txid,
                                outpoint
                            );
                            continue;
                        }
                        _ => {
                            tracing::debug!(
                                "Failed to bump fee the fee payer tx {} with error {e}, skipping",
                                fee_payer_txid
                            );
                            continue;
                        }
                    }
                }
            };
            let new_txid = bumped_tx.compute_txid();
            let Some(new_vout) = bumped_tx.output.iter().position(|output| {
                output.value == amount
                    && output.script_pubkey == self.signer.address.script_pubkey()
            }) else {
                tracing::warn!(
                    "Bumped fee payer tx {new_txid} did not preserve the expected output of {amount} for try_to_send_id {try_to_send_id}, skipping"
                );
                continue;
            };
            let Ok(new_vout) = u32::try_from(new_vout) else {
                tracing::warn!("Fee payer vout {new_vout} does not fit in u32, skipping");
                continue;
            };

            // Saved before the broadcast, as in `create_fee_payer_utxo`. A saved
            // replacement that never reaches the mempool does no harm: the family
            // stays tracked through the replaced tx, and only confirmed rows are spent.
            self.db
                .save_fee_payer_tx(
                    None,
                    try_to_send_id,
                    new_txid,
                    new_vout,
                    amount,
                    Some(parent_id),
                )
                .await
                .map_to_eyre()?;

            if let Err(e) = self.rpc.send_raw_transaction(&bumped_tx).await {
                tracing::warn!(
                    "Failed to send bumped fee payer tx {new_txid} (replacement of {fee_payer_txid}): {e}"
                );
            }
        }

        // Mark families with no mempool/confirmed member as evicted. Accepted
        // rare false positive, recovered by creating a new fee-payer UTXO
        // (protocol tx delayed, not permanently blocked): mined then reorged
        // between mempool lookup and gettransaction.
        for parent_id in all_parent_ids {
            if !not_evicted_ids.contains(&parent_id) {
                self.db
                    .mark_fee_payer_utxo_as_evicted(None, parent_id)
                    .await
                    .map_to_eyre()?;
            }
        }

        Ok(())
    }

    /// Returns the mempool transaction that spends the parent's P2A anchor.
    async fn anchor_spender(&self, parent: &Transaction) -> Result<Option<Txid>> {
        let anchor = OutPoint {
            txid: parent.compute_txid(),
            vout: self.find_p2a_vout(parent)? as u32,
        };
        let spenders = self
            .rpc
            .get_tx_spending_prevout(&[anchor], None)
            .await
            .wrap_err("Failed to query the anchor spender of the CPFP parent")?;
        Ok(spenders
            .into_iter()
            .next()
            .ok_or_eyre("Missing CPFP anchor spender result")?
            .spending_txid)
    }

    /// Returns the parent's mempool child, whichever output it spends, with its fee.
    ///
    /// A TRUC parent normally has at most one unconfirmed child, so ours must replace it
    /// whichever output it spends. After a reorg, Core can leave the parent with several
    /// children and then evicts no sibling, so ours can only replace the child that spends
    /// the anchor. If none does, the first child is returned and Core rejects ours.
    async fn current_cpfp_child(&self, parent: &Transaction) -> Result<Option<CurrentCpfpChild>> {
        let parent_entry = match self.rpc.get_mempool_entry(&parent.compute_txid()).await {
            Ok(entry) => entry,
            Err(e) if rpc_error_code(&e) == Some(RPC_INVALID_ADDRESS_OR_KEY) => return Ok(None),
            Err(e) => {
                return Err(eyre!(e)
                    .wrap_err("Failed to query CPFP parent mempool entry")
                    .into())
            }
        };
        let child_txid = match parent_entry.spent_by.as_slice() {
            [] => return Ok(None),
            [child_txid] => *child_txid,
            [first_child, ..] => self.anchor_spender(parent).await?.unwrap_or(*first_child),
        };
        let entry = self
            .rpc
            .get_mempool_entry(&child_txid)
            .await
            .wrap_err_with(|| format!("Failed to query current CPFP child {child_txid}"))?;

        Ok(Some(CurrentCpfpChild {
            txid: child_txid,
            modified_fee: entry.fees.modified,
            vsize: entry.vsize,
        }))
    }

    /// Calculates Core's minimum fee for replacing a CPFP child: the old fee plus the
    /// incremental relay fee for the replacement's size, and a fee rate strictly above the
    /// old child's own fee rate.
    ///
    /// The fee-rate rule applies up to Core 30. Core 31+ compares package fee rates instead,
    /// so there the floor only overpays when the old child is smaller than ours.
    fn minimum_cpfp_replacement_fee(
        old_modified_fee: Amount,
        old_vsize: u64,
        replacement_weight: Weight,
        incremental_fee_rate: FeeRate,
    ) -> Result<Amount> {
        let replacement_vsize = replacement_weight.to_vbytes_ceil();
        let absolute_floor = incremental_fee_rate
            .fee_vb(replacement_vsize)
            .and_then(|incremental_fee| old_modified_fee.checked_add(incremental_fee));
        let fee_rate_floor = old_modified_fee
            .to_sat()
            .checked_mul(replacement_vsize)
            .and_then(|fee| fee.checked_div(old_vsize))
            .and_then(|fee| fee.checked_add(1))
            .map(Amount::from_sat);
        absolute_floor
            .zip(fee_rate_floor)
            .map(|(absolute_floor, fee_rate_floor)| absolute_floor.max(fee_rate_floor))
            .ok_or_eyre("CPFP replacement fee overflow")
            .map_err(Into::into)
    }

    /// Calculates the largest child fee allowed when replacing a CPFP child.
    ///
    /// Any child of the parent can be up to `TRUC_CHILD_MAX_VSIZE`. A third party that holds
    /// the signed parent can attach such a child with a package fee rate below ours but an
    /// absolute fee above what our smaller child pays at the hard cap. The budget lets us
    /// replace every full-size child whose package fee rate is below the hard cap.
    fn maximum_cpfp_replacement_fee(
        parent_tx_weight: Weight,
        parent_tx_fee: Amount,
        replacement_weight: Weight,
        hard_cap: FeeRate,
        incremental_fee_rate: FeeRate,
    ) -> Result<Amount> {
        let largest_child_fee = Self::calculate_cpfp_child_fee_for_vbytes(
            parent_tx_weight,
            parent_tx_fee,
            TRUC_CHILD_MAX_VSIZE,
            hard_cap,
        )?;
        Self::minimum_cpfp_replacement_fee(
            largest_child_fee,
            TRUC_CHILD_MAX_VSIZE,
            replacement_weight,
            incremental_fee_rate,
        )
    }

    /// Returns Core's incremental relay fee rate, which a replacement pays for its own size.
    async fn incremental_relay_fee_rate(&self) -> Result<FeeRate> {
        let sat_per_kvb = self
            .rpc
            .get_network_info()
            .await
            .wrap_err("Failed to query incremental relay fee")?
            .incremental_fee
            .to_sat();
        Ok(FeeRate::from_sat_per_kwu(sat_per_kvb.div_ceil(4)))
    }

    /// Submits a CPFP package. Returns false if Core keeps a child that is already in the
    /// mempool because ours is an insufficient-fee replacement.
    async fn submit_cpfp_package(
        &self,
        try_to_send_id: u32,
        package: &[&Transaction],
    ) -> Result<bool> {
        let submit_package_result: PackageSubmissionResult = self
            .rpc
            .submit_package(package, Some(Amount::from_sat(0)), None)
            .await
            .wrap_err("Failed to submit package")?;

        tracing::debug!(
            try_to_send_id,
            "Submit package result: {submit_package_result:?}"
        );

        if submit_package_result.tx_results.is_empty() {
            return Err(SendTxError::Other(eyre!(
                "submitpackage returned no transaction results"
            )));
        }

        let mut rejected_as_insufficient_replacement = false;
        for (_txid, result) in submit_package_result.tx_results {
            if let PackageTransactionResult::Failure { error, .. } = result {
                // CPFP packages are periodically resubmitted to counter replacement cycling.
                // An existing package can reject the resubmission as an insufficient-fee replacement.
                if super::is_rejecting_replacement_error(&error) {
                    tracing::debug!(
                        try_to_send_id,
                        "Package resubmission rejected because a replacement is already in the mempool: {error}"
                    );
                    rejected_as_insufficient_replacement = true;
                    continue;
                }

                tracing::error!(
                    try_to_send_id,
                    "Error submitting package: {:?}, package: {:?}",
                    error,
                    package
                        .iter()
                        .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                        .collect::<Vec<_>>()
                );

                return Err(SendTxError::Other(eyre!(
                    "submitpackage rejected a transaction: {error}"
                )));
            }
        }

        Ok(!rejected_as_insufficient_replacement)
    }

    /// Sends a transaction using the Child-Pays-For-Parent (CPFP) strategy.
    ///
    /// # Logic:
    /// 1.  **Check Unconfirmed Fee Payers:** Ensures no unconfirmed fee payer UTXOs exist
    ///     for this `try_to_send_id`. If they do, returns [`SendTxError::UnconfirmedFeePayerUTXOsLeft`]
    ///     as they need to confirm before being spendable by the child.
    /// 2.  **Get Confirmed Fee Payers:** Retrieves the available confirmed fee payer UTXOs.
    /// 3.  **Check Mempool Child:** If a mempool child of the parent already pays the target,
    ///     keeps it, and resubmits it with the parent if `rebroadcast` is true. Otherwise the
    ///     new child pays at least Core's absolute fee floor to replace it.
    /// 4.  **Create Package:** Calls `create_package` to build the `vec![parent_tx, child_tx]`.
    ///     The `child_tx` spends the parent's anchor output and the fee payer UTXOs, paying
    ///     a fee calculated for the whole package.
    /// 5.  **Test Mempool Accept (Debug step):** Uses `testmempoolaccept` RPC
    ///     to check if the package is likely to be accepted by the network before submitting.
    /// 6.  **Submit Package:** Uses the `submitpackage` RPC to atomically submit the parent
    ///     and child transactions. Bitcoin Core evaluates the fee rate of the package together.
    /// 7.  **Handle Results:** Returns an error for missing or failed `submitpackage` results.
    ///
    /// # Arguments
    /// * `try_to_send_id` - The database ID tracking this send attempt.
    /// * `tx` - The parent transaction requiring the fee bump.
    /// * `tx_metadata` - Optional metadata associated with the transaction.
    /// * `fee_rate` - The target fee rate for the CPFP package.
    /// * `rebroadcast` - If true, resubmit an already-sufficient package to trigger a Core re-relay.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, try_to_send_id, tx_meta=?tx_metadata))]
    pub(super) async fn send_cpfp_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRate,
        rebroadcast: bool,
    ) -> Result<()> {
        let unconfirmed_fee_payer_utxos = self
            .db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await
            .map_to_eyre()?;

        if !unconfirmed_fee_payer_utxos.is_empty() {
            // Log that we're waiting for unconfirmed UTXOs
            tracing::debug!(
                try_to_send_id,
                "Waiting for {} UTXOs to confirm",
                unconfirmed_fee_payer_utxos.len()
            );

            // Update the sending state
            let _ = self
                .db
                .update_tx_debug_sending_state(
                    try_to_send_id,
                    "waiting_for_utxo_confirmation",
                    true,
                )
                .await;

            return Ok(());
        }

        tracing::debug!(try_to_send_id, "Attempting to send CPFP tx");

        let confirmed_fee_payers = self.get_confirmed_fee_payer_utxos(try_to_send_id).await?;
        let confirmed_fee_payer_len = confirmed_fee_payers.len();

        // Core validates replacements using absolute integer fees, not only fee rates. A rebuilt
        // child at the same or a slightly higher target is rejected as a replacement, and
        // submitpackage then relays only the parent. Read the accepted child from Core: an
        // already-sufficient (possibly third-party) child is left alone, and only an insufficient
        // child needs Core's absolute replacement floor below.
        let minimum_child_fee = match self.current_cpfp_child(&tx).await? {
            Some(current_child) => {
                let parent_fee = self.get_tx_fee(&tx).await.map_err(|e| eyre!(e))?;
                let target_child_fee = Self::calculate_cpfp_child_fee_for_vbytes(
                    tx.weight(),
                    parent_fee,
                    current_child.vsize,
                    fee_rate,
                )?;
                if current_child.modified_fee >= target_child_fee {
                    if rebroadcast {
                        let child = self
                            .rpc
                            .get_tx_of_txid(&current_child.txid)
                            .await
                            .wrap_err("Failed to get current CPFP child")?;
                        self.submit_cpfp_package(try_to_send_id, &[&tx, &child])
                            .await?;
                    }
                    self.db
                        .update_effective_fee_rate(None, try_to_send_id, fee_rate)
                        .await
                        .wrap_err("Failed to update effective fee rate")?;
                    return Ok(());
                }

                let incremental_fee_rate = self.incremental_relay_fee_rate().await?;
                let child_weight = Self::estimate_cpfp_child_weight(confirmed_fee_payer_len);
                let minimum_child_fee = Self::minimum_cpfp_replacement_fee(
                    current_child.modified_fee,
                    current_child.vsize,
                    child_weight,
                    incremental_fee_rate,
                )?;
                let hard_cap =
                    FeeRate::from_sat_per_vb(self.config.tx_sender_limits.fee_rate_hard_cap)
                        .ok_or_eyre("CPFP fee rate hard cap overflow")?;
                let maximum_child_fee = Self::maximum_cpfp_replacement_fee(
                    tx.weight(),
                    parent_fee,
                    child_weight,
                    hard_cap,
                    incremental_fee_rate,
                )?;
                if minimum_child_fee > maximum_child_fee {
                    return Err(eyre!(
                        "CPFP replacement requires {minimum_child_fee}, exceeding the hard-cap budget {maximum_child_fee}"
                    )
                    .into());
                }
                Some(minimum_child_fee)
            }
            None => None,
        };

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "creating_package", true)
            .await;

        // to be used below
        let total_fee_payer_amount = confirmed_fee_payers
            .iter()
            .map(|txi| txi.get_prevout().value)
            .sum::<Amount>();

        let package = self
            .create_package(
                tx.clone(),
                fee_rate,
                confirmed_fee_payers,
                minimum_child_fee,
            )
            .await
            .wrap_err("Failed to create CPFP package");

        let package = match package {
            Ok(package) => package,
            Err(e) => match e.root_cause().downcast_ref::<SendTxError>() {
                Some(SendTxError::InsufficientFeePayerAmount) => {
                    tracing::debug!(
                        try_to_send_id,
                        "Insufficient fee payer amount, creating new fee payer utxo."
                    );

                    self.create_fee_payer_utxo(
                        try_to_send_id,
                        &tx,
                        fee_rate,
                        total_fee_payer_amount,
                        confirmed_fee_payer_len,
                        minimum_child_fee,
                    )
                    .await?;

                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "waiting_for_fee_payer_utxos",
                            true,
                        )
                        .await;

                    return Ok(());
                }
                _ => {
                    tracing::error!(try_to_send_id, "Failed to create CPFP package: {:?}", e);
                    return Err(e.into());
                }
            },
        };

        let package_refs: Vec<&Transaction> = package.iter().collect();

        tracing::debug!(
            try_to_send_id,
            "Submitting package\n Pkg tx hexs: {:?}",
            if env::var("DBG_PACKAGE_HEX").is_ok() {
                package
                    .iter()
                    .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                    .collect::<Vec<_>>()
            } else {
                vec!["use DBG_PACKAGE_HEX=1 to print the package as hex".into()]
            }
        );

        // Update sending state to submitting_package
        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "submitting_package", true)
            .await;

        tracing::debug!(try_to_send_id, "Submitting package, size {}", package.len());

        // let test_mempool_result = self
        //     .rpc
        //     .test_mempool_accept(&package_refs)
        //     .await
        //     .wrap_err("Failed to test mempool accept")?;

        if !self
            .submit_cpfp_package(try_to_send_id, &package_refs)
            .await?
        {
            return Ok(());
        }

        tracing::debug!("Package submitted successfully.");

        // Save the effective fee rate to the db
        self.db
            .update_effective_fee_rate(None, try_to_send_id, fee_rate)
            .await
            .wrap_err("Failed to update effective fee rate")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::Actor;
    use crate::database::Database;
    use crate::test::common::tx_utils::create_bumpable_tx;
    use crate::test::common::{create_regtest_rpc, create_test_config_with_thread_name};

    /// A replacement saved before a failed broadcast is either built and broadcast
    /// again with the same txid, or superseded. Either way no outpoint is saved twice.
    #[tokio::test]
    async fn fee_payer_bump_recovers_from_unsent_replacement() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        config
            .tx_sender_limits
            .cpfp_fee_payer_bump_wait_time_seconds = 0;
        let db = Database::new(&config).await.unwrap();
        let network = config.protocol_paramset().network;
        let signer = Actor::new(config.secret_key, network);
        let tx_sender = TxSender::new(
            signer.clone(),
            rpc.clone(),
            db.clone(),
            "tx_sender".into(),
            config.clone(),
        );

        let parent_tx = create_bumpable_tx(&rpc, &signer, network, FeePayingType::CPFP, false)
            .await
            .unwrap();
        let mut dbtx = db.begin_transaction().await.unwrap();
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(
                &mut dbtx,
                None,
                &parent_tx,
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        dbtx.commit().await.unwrap();

        let amount = Amount::from_sat(50_000);
        let fee_payer = rpc.send_to_address(&signer.address, amount).await.unwrap();
        db.save_fee_payer_tx(
            None,
            try_to_send_id,
            fee_payer.txid,
            fee_payer.vout,
            amount,
            None,
        )
        .await
        .unwrap();

        let (original_id, ..) = db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await
            .unwrap()[0];

        // A replacement that was saved but never broadcast, as after a crash.
        let fee_rate = FeeRate::from_sat_per_vb_u32(10);
        let unsent = rpc
            .create_fee_bump_tx(fee_payer.txid, fee_rate)
            .await
            .unwrap()
            .expect("A replacement is needed");
        let unsent_vout = unsent
            .output
            .iter()
            .position(|output| {
                output.value == amount && output.script_pubkey == signer.address.script_pubkey()
            })
            .unwrap() as u32;
        db.save_fee_payer_tx(
            None,
            try_to_send_id,
            unsent.compute_txid(),
            unsent_vout,
            amount,
            Some(original_id),
        )
        .await
        .unwrap();

        tx_sender
            .bump_fees_of_unconfirmed_fee_payer_txs(fee_rate)
            .await
            .unwrap();

        let fee_payers = db.get_all_unconfirmed_fee_payer_txs(None).await.unwrap();
        let outpoints: HashSet<_> = fee_payers
            .iter()
            .map(|(_, _, txid, vout, _, _)| (*txid, *vout))
            .collect();
        assert_eq!(outpoints.len(), fee_payers.len());
        assert!(rpc.get_mempool_entry(&fee_payer.txid).await.is_err());

        let mut broadcast_replacements = Vec::new();
        for (_, bumped_id, txid, vout, replacement_amount, replacement_of) in &fee_payers {
            if *txid == fee_payer.txid {
                continue;
            }
            assert_eq!(*bumped_id, try_to_send_id);
            assert_eq!(*replacement_amount, amount);
            assert_eq!(*replacement_of, Some(original_id));
            if rpc.get_mempool_entry(txid).await.is_ok() {
                broadcast_replacements.push((*txid, *vout));
            }
        }
        assert_eq!(broadcast_replacements.len(), 1);
        let (replacement_txid, replacement_vout) = broadcast_replacements[0];
        let replacement_tx = rpc.get_tx_of_txid(&replacement_txid).await.unwrap();
        assert_eq!(
            replacement_tx.output[replacement_vout as usize].script_pubkey,
            signer.address.script_pubkey()
        );
    }

    #[test]
    fn cpfp_replacement_uses_core_absolute_fee_requirement() {
        let child_vbytes = TxSender::estimate_cpfp_child_weight(1).to_vbytes_ceil();
        let old_fee = FeeRate::from_sat_per_kwu(625) // 2500 sat/kvB
            .fee_vb(child_vbytes)
            .unwrap();
        let target_fee = FeeRate::from_sat_per_kwu(650) // 2600 sat/kvB
            .fee_vb(child_vbytes)
            .unwrap();
        let minimum_replacement_fee = TxSender::minimum_cpfp_replacement_fee(
            old_fee,
            child_vbytes,
            TxSender::estimate_cpfp_child_weight(1),
            FeeRate::from_sat_per_kwu(25), // 100 sat/kvB
        )
        .unwrap();

        assert_eq!(old_fee, Amount::from_sat(383));
        assert_eq!(target_fee, Amount::from_sat(398));
        assert_eq!(minimum_replacement_fee, Amount::from_sat(399));
        assert!(target_fee < minimum_replacement_fee);
    }

    #[test]
    fn cpfp_replacement_outbids_fee_rate_of_smaller_child() {
        let child_weight = TxSender::estimate_cpfp_child_weight(1);
        let child_vbytes = child_weight.to_vbytes_ceil();
        // A 120 vB child at 20 sat/vB: its absolute fee plus incremental relay fee is
        // below 20 sat/vB for our 153 vB child.
        let old_fee = Amount::from_sat(2_400);
        let old_vsize = 120;
        let minimum_replacement_fee = TxSender::minimum_cpfp_replacement_fee(
            old_fee,
            old_vsize,
            child_weight,
            FeeRate::from_sat_per_kwu(25), // 100 sat/kvB
        )
        .unwrap();

        assert_eq!(child_vbytes, 153);
        assert_eq!(minimum_replacement_fee, Amount::from_sat(3_061));
        assert!(
            minimum_replacement_fee.to_sat() * old_vsize > old_fee.to_sat() * child_vbytes,
            "replacement fee rate must be strictly above the old child's",
        );
    }

    #[test]
    fn cpfp_replacement_budget_outbids_largest_truc_child_below_hard_cap() {
        let parent_weight = Weight::from_wu(500);
        let child_weight = TxSender::estimate_cpfp_child_weight(1);
        let incremental_fee_rate = FeeRate::from_sat_per_kwu(25);
        let pinning_child_fee = TxSender::calculate_cpfp_child_fee_for_vbytes(
            parent_weight,
            Amount::ZERO,
            TRUC_CHILD_MAX_VSIZE,
            FeeRate::from_sat_per_vb(99).unwrap(),
        )
        .unwrap();
        let minimum_replacement_fee = TxSender::minimum_cpfp_replacement_fee(
            pinning_child_fee,
            TRUC_CHILD_MAX_VSIZE,
            child_weight,
            incremental_fee_rate,
        )
        .unwrap();
        let maximum_replacement_fee = TxSender::maximum_cpfp_replacement_fee(
            parent_weight,
            Amount::ZERO,
            child_weight,
            FeeRate::from_sat_per_vb(100).unwrap(),
            incremental_fee_rate,
        )
        .unwrap();

        assert!(minimum_replacement_fee <= maximum_replacement_fee);
    }
}
