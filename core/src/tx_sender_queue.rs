//! Core-specific txsender queue helpers.
//!
//! `clementine-tx-sender` intentionally exposes only a low-level, transactional
//! `insert_try_to_send` API. The higher-level mapping from `TransactionType`
//! to cancellation/activation semantics is Clementine-core specific and lives here.

use bitcoin::{OutPoint, Transaction};
use clementine_config::protocol::ProtocolParamset;
use clementine_errors::BridgeError;
use clementine_primitives::{TransactionType, UtxoVout};
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::eyre;

use crate::tx_sender::{ActivatedWithOutpoint, TxSenderClient, TxSenderTransaction};

#[tonic::async_trait]
pub trait TxSenderClientQueueExt {
    /// Adds a transaction to the txsender sending queue based on core transaction semantics.
    ///
    /// This function is a core-level wrapper around [`TxSenderClient::insert_try_to_send`].
    /// It determines the appropriate [`FeePayingType`] and any cancellation/activation
    /// dependencies based on the [`TransactionType`].
    ///
    /// IMPORTANT: `insert_try_to_send` is transactional. This helper requires an active
    /// DB transaction and will not partially insert state.
    #[allow(clippy::too_many_arguments)]
    async fn add_tx_to_queue(
        &self,
        dbtx: &mut TxSenderTransaction,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_metadata: Option<TxMetadata>,
        protocol_paramset: &ProtocolParamset,
        rbf_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError>;
}

#[tonic::async_trait]
impl TxSenderClientQueueExt for TxSenderClient {
    #[allow(clippy::too_many_arguments)]
    async fn add_tx_to_queue(
        &self,
        dbtx: &mut TxSenderTransaction,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_metadata: Option<TxMetadata>,
        protocol_paramset: &ProtocolParamset,
        rbf_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError> {
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
            | TransactionType::MoveToVault
            | TransactionType::BurnUnusedKickoffConnectors
            | TransactionType::KickoffNotFinalized
            | TransactionType::MiniAssert(_)
            | TransactionType::LatestBlockhashTimeout
            | TransactionType::LatestBlockhash
            | TransactionType::EmergencyStop
            | TransactionType::OptimisticPayout
            | TransactionType::ReadyToReimburse
            | TransactionType::ReplacementDeposit
            | TransactionType::AssertTimeout(_)
            | TransactionType::WatchtowerChallenge(_) => {
                // no_dependency and cpfp
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::Challenge | TransactionType::Payout => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::RBF,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::WatchtowerChallengeTimeout(_) => {
                // Do not send watchtower timeout if kickoff is already finalized
                // which is done by adding kickoff finalizer utxo to cancel_outpoints
                // this is not needed for any timeouts that spend the kickoff finalizer utxo like AssertTimeout.
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(t, tx)| {
                        (matches!(t, TransactionType::Kickoff)).then(|| tx.compute_txid())
                    })
                    .ok_or(BridgeError::Eyre(eyre!(
                        "Couldn't find kickoff tx in related_txs"
                    )))?;

                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[OutPoint {
                        txid: kickoff_txid,
                        vout: UtxoVout::KickoffFinalizer.get_vout(),
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
                    .find_map(|(t, tx)| {
                        (matches!(t, TransactionType::Kickoff)).then(|| tx.compute_txid())
                    })
                    .ok_or(BridgeError::Eyre(eyre!(
                        "Couldn't find kickoff tx in related_txs"
                    )))?;

                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[ActivatedWithOutpoint {
                        // only send OperatorChallengeAck if corresponding watchtower challenge is sent
                        outpoint: OutPoint {
                            txid: kickoff_txid,
                            vout: UtxoVout::WatchtowerChallenge(watchtower_idx).get_vout(),
                        },
                        relative_block_height: protocol_paramset.finality_depth - 1,
                    }],
                )
                .await
            }
            TransactionType::Disprove => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::NoFunding,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::AllNeededForDeposit | TransactionType::YieldKickoffTxid => {
                unreachable!(
                    "Higher level transaction types should not be added to the txsender queue"
                );
            }
        }
    }
}
