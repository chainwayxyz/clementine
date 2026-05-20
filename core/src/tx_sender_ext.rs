use crate::rpc;
use crate::rpc::clementine::TxDebugInfo;
use bitcoin::hashes::Hash;
use clementine_errors::{BridgeError, BridgeRound, ResultExt as _};
use clementine_tx_sender::client::TxSenderClient;
use clementine_tx_sender::TxSender;
use clementine_utils::FeePayingType;
use tonic::async_trait;

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
impl TxSenderClientExt for TxSenderClient {
    async fn debug_tx(&self, id: u32) -> Result<TxDebugInfo, BridgeError> {
        use crate::rpc::clementine::{TxDebugFeePayerUtxo, TxDebugInfo, TxDebugSubmissionError};

        let (tx_metadata, tx, fee_paying_type, seen_at_height, _) =
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
            FeePayingType::RBF | FeePayingType::RbfWtxidGrind => self
                .db
                .get_last_rbf_txid(None, id)
                .await
                .map_to_eyre()?
                .unwrap_or(bitcoin::Txid::all_zeros()),
        };
        let debug_info = TxDebugInfo {
            id,
            is_active: seen_at_height.is_none(),
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
                    .unwrap_or(BridgeRound::Round(0))
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
impl TxSenderExt for TxSender {
    async fn debug_tx(&self, id: u32) -> Result<TxDebugInfo, BridgeError> {
        let client = self.client();
        client.debug_tx(id).await
    }
}
