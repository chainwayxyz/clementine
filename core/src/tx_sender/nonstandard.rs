//! TxSender for nonstandard transactions.
//!
//! This module contains the logic for sending nonstandard transactions for various bitcoin networks.
use alloy::transports::http::reqwest;
use bitcoin::consensus::serialize;
use bitcoin::Transaction;
use hex;
use std::collections::HashMap;

use super::{SendTxError, TxSender};

impl TxSender {
    /// Checks if a bridge transaction is nonstandard.
    /// Currently there are 2 cases where a bridge transaction is nonstandard:
    /// 1. The transaction contains 0 sat non-anchor outputs.
    /// 2. The transaction weight is bigger than 400k
    ///
    /// Arguments:
    /// * `tx` - The transaction to check.
    ///
    /// Returns:
    /// * `true` if the transaction is nonstandard, `false` otherwise.
    pub fn is_bridge_tx_nonstandard(&self, tx: &Transaction) -> bool {
        // 1. The transaction contains 0 sat non-anchor outputs.
        tx.output
					.iter()
					.any(|output| output.value.to_sat() == 0 && !self.is_p2a_anchor(output))
					|| // 2. The transaction weight is bigger than 400k
					tx.weight().to_wu() > 400_000
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
    /// Note: Mempool.space accelerator doesnt accept transactions if:
    ///     - At least one of the transaction's inputs is signed with either the SIGHASH_NONE or SIGHASH_ANYONECANPAY flag, which may allow a third party to replace the transaction.
    ///     - The number of signature operations multiplied by 20 exceeds the transaction's weight.
    pub async fn send_testnet4_nonstandard_tx(&self, tx: &Transaction) -> Result<(), SendTxError> {
        // Get API key from environment variable
        let api_key = std::env::var("MEMPOOL_SPACE_API_KEY").map_err(|_| {
            SendTxError::NetworkError(
                "MEMPOOL_SPACE_API_KEY environment variable not set, cannot send nonstandard transactions to testnet4".to_string(),
            )
        })?;

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
                txid = %tx.txid(),
                "Successfully submitted nonstandard transaction to mempool.space testnet4 accelerator: {}",
                response_text
            );

            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            Err(SendTxError::NetworkError(format!(
                "Failed to submit transaction to mempool.space. Status: {}, Error: {}",
                status, error_text
            )))
        }
    }
}
