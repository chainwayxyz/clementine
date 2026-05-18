//! Core-specific txsender queue helpers.
//!
//! `clementine-tx-sender` intentionally exposes only a low-level, transactional
//! `insert_try_to_send` API. The mapping from transaction ids to tx-sender fee
//! strategies ([`FeePayingType`]) is Clementine-core specific and lives here.

use crate::protocol::ids::TransactionType;
use crate::tx_sender::{TxSenderClient, TxSenderTransaction};
use bitcoin::Transaction;
use clementine_errors::BridgeError;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};

#[tonic::async_trait]
pub trait TxSenderClientQueueExt {
    /// Adds a transaction to the txsender sending queue with the core fee strategy.
    async fn add_tx_to_queue(
        &self,
        dbtx: &mut TxSenderTransaction,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        tx_metadata: Option<TxMetadata>,
        rbf_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError>;
}

#[tonic::async_trait]
impl TxSenderClientQueueExt for TxSenderClient {
    async fn add_tx_to_queue(
        &self,
        dbtx: &mut TxSenderTransaction,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        tx_metadata: Option<TxMetadata>,
        rbf_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError> {
        let tx_metadata = tx_metadata.map(|mut data| {
            data.tx_type = tx_type.clone();
            data
        });

        let fee_paying_type = match tx_type {
            TransactionType::Challenge(_, _) | TransactionType::Payout => FeePayingType::RBF,
            TransactionType::Disprove(_, _) => FeePayingType::NoFunding,
            _ => FeePayingType::CPFP,
        };

        self.insert_try_to_send(
            dbtx,
            tx_metadata,
            signed_tx,
            fee_paying_type,
            rbf_info,
            &[],
            &[],
            &[],
            &[],
        )
        .await
    }
}
