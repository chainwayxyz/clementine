use crate::builder;
use crate::builder::script::SpendPath;
use crate::builder::sighash::TapTweakData;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::TxHandlerBuilder;
use crate::database::Database;
use crate::rpc;
use crate::rpc::clementine::{NormalSignatureKind, TxDebugInfo};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, TxOut, Txid};
use clementine_errors::{BridgeError, ResultExt as _, RoundIndex, TransactionType};
use clementine_primitives::NON_STANDARD_V3;
use clementine_tx_sender::client::TxSenderClient;
use clementine_tx_sender::{TxSender, TxSenderSigner, TxSenderTxBuilder, DEFAULT_SEQUENCE};
use clementine_utils::FeePayingType;
use tonic::async_trait;

/// Core's implementation of TxSenderTxBuilder using SpendableTxIn and TxHandlerBuilder.
///
/// This struct provides static methods for building CPFP child transactions
/// using the core builder module's SpendableTxIn type and TxHandlerBuilder.
#[derive(Debug, Clone, Copy)]
pub struct CoreTxBuilder;

impl TxSenderTxBuilder for CoreTxBuilder {
    type SpendableInput = SpendableTxIn;

    fn build_child_tx<S: TxSenderSigner>(
        p2a_anchor: OutPoint,
        anchor_sat: Amount,
        fee_payer_utxos: Vec<Self::SpendableInput>,
        change_address: Address,
        required_fee: Amount,
        signer: &S,
    ) -> Result<bitcoin::Transaction, BridgeError> {
        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + anchor_sat;

        let change_amount = total_fee_payer_amount
            .checked_sub(required_fee)
            .ok_or_else(|| {
                BridgeError::Eyre(eyre::eyre!(
                    "Required fee {} exceeds total amount {}",
                    required_fee,
                    total_fee_payer_amount
                ))
            })?;

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
            value: change_amount,
            script_pubkey: change_address.script_pubkey(),
        }));

        let mut tx_handler = builder.finalize();

        for fee_payer_input in 1..tx_handler.get_cached_tx().input.len() {
            let sighash = tx_handler
                .calculate_pubkey_spend_sighash(fee_payer_input, bitcoin::TapSighashType::Default)
                .map_err(|e| BridgeError::Eyre(eyre::eyre!("{}", e)))?;
            let signature = signer
                .sign_with_tweak_data(sighash, TapTweakData::KeyPath(None))
                .map_err(|e| BridgeError::Eyre(eyre::eyre!("{}", e)))?;
            tx_handler
                .set_p2tr_key_spend_witness(
                    &bitcoin::taproot::Signature {
                        signature,
                        sighash_type: bitcoin::TapSighashType::Default,
                    },
                    fee_payer_input,
                )
                .map_err(|e| BridgeError::Eyre(eyre::eyre!("{}", e)))?;
        }

        let child_tx = tx_handler.get_cached_tx().clone();
        Ok(child_tx)
    }

    fn utxos_to_spendable_inputs(
        utxos: Vec<(Txid, u32, Amount)>,
        signer_address: &Address,
    ) -> Vec<Self::SpendableInput> {
        utxos
            .into_iter()
            .map(|(txid, vout, amount)| {
                SpendableTxIn::new_partial(
                    OutPoint { txid, vout },
                    TxOut {
                        value: amount,
                        script_pubkey: signer_address.script_pubkey(),
                    },
                )
            })
            .collect()
    }
}

#[async_trait]
pub trait TxSenderClientExt {
    /// Returns debugging information for a transaction
    ///
    /// This function gathers all debugging information about a transaction from the database,
    /// including its state history, fee payer UTXOs, submission errors, and current state.
    ///
    /// # Arguments
    /// * `id` - The ID of the transaction to debug
    ///
    /// # Returns
    /// A comprehensive debug info structure with all available information about the transaction
    async fn debug_tx(&self, id: u32) -> Result<TxDebugInfo, BridgeError>;
}

#[async_trait]
impl TxSenderClientExt for TxSenderClient<Database> {
    async fn debug_tx(&self, id: u32) -> Result<TxDebugInfo, BridgeError> {
        use crate::rpc::clementine::{TxDebugFeePayerUtxo, TxDebugInfo, TxDebugSubmissionError};

        let (tx_metadata, tx, fee_paying_type, seen_block_id, _) =
            self.db.get_try_to_send_tx(None, id).await.map_to_eyre()?;

        let submission_errors = self
            .db
            .get_tx_debug_submission_errors(None, id)
            .await
            .map_to_eyre()?;

        let submission_errors = submission_errors
            .into_iter()
            .map(|(error_message, timestamp)| TxDebugSubmissionError {
                error_message,
                timestamp,
            })
            .collect();

        let current_state = self.db.get_tx_debug_info(None, id).await.map_to_eyre()?;

        let fee_payer_utxos = self
            .db
            .get_tx_debug_fee_payer_utxos(None, id)
            .await
            .map_to_eyre()?;

        let fee_payer_utxos = fee_payer_utxos
            .into_iter()
            .map(|(txid, vout, amount, confirmed)| TxDebugFeePayerUtxo {
                txid: Some(txid.into()),
                vout,
                amount: amount.to_sat(),
                confirmed,
            })
            .collect::<Vec<_>>();

        let txid = match fee_paying_type {
            FeePayingType::CPFP | FeePayingType::NoFunding => tx.compute_txid(),
            FeePayingType::RBF => self
                .db
                .get_last_rbf_txid(None, id)
                .await
                .map_to_eyre()?
                .unwrap_or(bitcoin::Txid::all_zeros()),
        };
        let debug_info = TxDebugInfo {
            id,
            is_active: seen_block_id.is_none(),
            current_state: current_state.unwrap_or_else(|| "unknown".to_string()),
            submission_errors,
            created_at: "".to_string(),
            txid: Some(txid.into()),
            fee_paying_type: format!("{fee_paying_type:?}"),
            fee_payer_utxos_count: fee_payer_utxos.len() as u32,
            fee_payer_utxos_confirmed_count: fee_payer_utxos
                .iter()
                .filter(|utxo| utxo.confirmed)
                .count() as u32,
            fee_payer_utxos,
            raw_tx: bitcoin::consensus::serialize(&tx),
            metadata: tx_metadata.map(|metadata| rpc::clementine::TxMetadata {
                deposit_outpoint: metadata.deposit_outpoint.map(Into::into),
                operator_xonly_pk: metadata.operator_xonly_pk.map(Into::into),

                round_idx: metadata
                    .round_idx
                    .unwrap_or(RoundIndex::Round(0))
                    .to_index() as u32,
                kickoff_idx: metadata.kickoff_idx.unwrap_or(0),
                tx_type: Some(metadata.tx_type.into()),
            }),
        };

        Ok(debug_info)
    }
}

#[async_trait]
pub trait TxSenderExt {
    async fn debug_tx(&self, id: u32) -> Result<TxDebugInfo, BridgeError>;
}

#[async_trait]
impl<S> TxSenderExt for TxSender<S, Database, CoreTxBuilder>
where
    S: TxSenderSigner + 'static,
{
    async fn debug_tx(&self, id: u32) -> Result<TxDebugInfo, BridgeError> {
        let client = self.client();
        client.debug_tx(id).await
    }
}
