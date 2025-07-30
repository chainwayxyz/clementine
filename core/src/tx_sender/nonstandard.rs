//! TxSender for nonstandard transactions.
//!
//! This module contains the logic for sending nonstandard transactions for various bitcoin networks.
use bitcoin::consensus::serialize;
use bitcoin::Transaction;
use hex;
use std::collections::HashMap;

use super::{log_error_for_tx, SendTxError, TxSender};

impl TxSender {
    /// Checks if a bridge transaction is nonstandard. Keep in mind that these are not all cases where a transaction is nonstandard.
    /// We only check non-standard types that clementine generates by default in non-standard mode.
    /// Currently checks these cases:
    /// 1. The transaction contains 0 sat non-anchor (only checks our specific anchor address)
    ///    and non-op return output.
    /// 2. The transaction weight is bigger than 400k
    ///
    /// Arguments:
    /// * `tx` - The transaction to check.
    ///
    /// Returns:
    /// * `true` if the transaction is nonstandard, `false` otherwise.
    pub fn is_bridge_tx_nonstandard(&self, tx: &Transaction) -> bool {
        tx.output.iter().any(|output| {
            output.value.to_sat() == 0
                && !self.is_p2a_anchor(output)
                && !output.script_pubkey.is_op_return()
        }) || tx.weight().to_wu() > 400_000
    }

    /// Sends a nonstandard transaction to testnet4 using the mempool.space accelerator.
    ///
    /// Arguments:
    /// * `tx` - The transaction to send.
    ///
    /// Returns:
    /// * `Ok(())` if the transaction is sent successfully to the accelerator.
    /// * `Err(SendTxError)` if the transaction is not sent successfully to the accelerator.
    ///
    /// Note: Mempool.space accelerator doesn't accept transactions if:
    ///     - At least one of the transaction's inputs is signed with either the SIGHASH_NONE or SIGHASH_ANYONECANPAY flag, which may allow a third party to replace the transaction.
    ///     - The number of signature operations multiplied by 20 exceeds the transaction's weight.
    /// [Mempool Space API docs](https://mempool.space/docs/api/rest)
    /// [Mempool Space Accelerator FAQ](https://mempool.space/accelerator/faq)
    pub async fn send_testnet4_nonstandard_tx(
        &self,
        tx: &Transaction,
        try_to_send_id: u32,
    ) -> Result<(), SendTxError> {
        // Get API key from environment variable
        let api_key = std::env::var("MEMPOOL_SPACE_API_KEY").map_err(|_| {
            SendTxError::Other(eyre::eyre!(
                "MEMPOOL_SPACE_API_KEY environment variable not set, cannot send nonstandard transactions to testnet4"
            ))
        })?;

        // first check if the transaction is already submitted to the accelerator
        // TODO: is there a better api for this?? Because right now all previous transactions are returned from API
        let txid = tx.compute_txid();
        let response = self
            .http_client
            .get("https://mempool.space/api/v1/services/accelerator/testnet4/accelerations")
            .header("X-Mempool-Auth", api_key.clone())
            .send()
            .await
            .map_err(|e| {
                SendTxError::NetworkError(format!(
                    "Failed to get transaction history from mempool.space accelerator: {}",
                    e
                ))
            })?;
        if response.status().is_success() {
            // Try to parse the response, if for some reason response cant be parsed,
            // don't return errors, so we continue with sending the transaction to the accelerator.
            let text = response.text().await.unwrap_or_default();
            let previously_sent_txs: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!([]));

            // try to parse the response
            for tx in previously_sent_txs.as_array().unwrap_or(&vec![]) {
                let Some(response_txid) = tx.get("txid").and_then(|v| v.as_str()) else {
                    continue;
                };

                if response_txid == txid.to_string() && tx["status"] != "failed" {
                    tracing::debug!(
                        "Found {:?} with status {:?} in accelerator transaction history",
                        txid,
                        tx["status"]
                    );
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "nonstandard_testnet4_send_submitted",
                            false,
                        )
                        .await;
                    return Ok(()); // Already submitted
                }
            }
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(SendTxError::NetworkError(format!(
                "Accelerator returned HTTP {}: {}",
                status, error_text
            )));
        }

        // Serialize transaction to hex
        let tx_hex = hex::encode(serialize(tx));

        // Prepare form data
        let mut form_data = HashMap::new();
        form_data.insert("txInput", tx_hex);
        form_data.insert("label", format!("clementine-{}", tx.compute_txid()));

        // Make the API request
        let response = self
            .http_client
            .post("https://mempool.space/api/v1/services/accelerator/testnet4/accelerate/hex")
            .header("X-Mempool-Auth", api_key)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| {
                SendTxError::NetworkError(format!(
                    "Failed to submit transaction to mempool.space accelerator: {}",
                    e
                ))
            })?;

        // Check if the request was successful
        if response.status().is_success() {
            let response_text = response.text().await.map_err(|e| {
                SendTxError::NetworkError(format!("Failed to read response: {}", e))
            })?;

            tracing::info!(
                "Successfully submitted nonstandard transaction {:?} to mempool.space testnet4 accelerator: {}",
                txid,
                response_text
            );

            let _ = self
                .db
                .update_tx_debug_sending_state(
                    try_to_send_id,
                    "nonstandard_testnet4_send_success",
                    true,
                )
                .await;

            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            log_error_for_tx!(
                self.db,
                try_to_send_id,
                format!(
                    "Failed to submit transaction to mempool.space. Status: {}, Error: {}",
                    status, error_text
                )
            );
            let _ = self
                .db
                .update_tx_debug_sending_state(
                    try_to_send_id,
                    "nonstandard_testnet4_send_failed",
                    true,
                )
                .await;

            Err(SendTxError::NetworkError(format!(
                "Failed to submit transaction to mempool.space. Status: {}, Error: {}",
                status, error_text
            )))
        }
    }
}
