//! Core-specific txsender queue helpers.
//!
//! `clementine-tx-sender` intentionally exposes only a low-level, transactional
//! `insert_try_to_send` API. The mapping from transaction ids
//! to tx-sender fee strategies ([`FeePayingType`]) is Clementine-core specific
//! and lives here.

use crate::protocol::ids::TransactionType;
use bitcoin::Transaction;
use clementine_errors::BridgeError;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};

use crate::tx_sender::{TxSenderClient, TxSenderTransaction};

#[tonic::async_trait]
pub trait TxSenderClientQueueExt {
    /// Adds a transaction to the txsender sending queue based on core transaction semantics.
    ///
    /// This function is a core-level wrapper around [`TxSenderClient::insert_try_to_send`].
    /// It determines the appropriate [`FeePayingType`] for the given
    /// transaction id.
    ///
    /// IMPORTANT: `insert_try_to_send` is transactional. This helper requires an active
    /// DB transaction and will not partially insert state.
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

        match tx_type {
            TransactionType::Challenge(_, _) | TransactionType::Payout => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::RBF,
                    rbf_info,
                    &[],
                )
                .await
            }
            TransactionType::Disprove(_, _) => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::NoFunding,
                    rbf_info,
                    &[],
                )
                .await
            }
            _ => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[],
                )
                .await
            }
        }
    }
}
