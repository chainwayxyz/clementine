use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::transaction::creator::ReimburseDbCache;
use crate::builder::transaction::{DepositData, TransactionType};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::operator::Operator;
use crate::rpc::clementine::{KickoffId, RawSignedTx, RawSignedTxs};
use crate::utils::ClementineBitVMPublicKeys;
use crate::watchtower::Watchtower;
use crate::{builder, utils};
use bitcoin::{Transaction, XOnlyPublicKey};

#[derive(Debug, Clone)]
pub struct TransactionRequestData {
    pub deposit_data: DepositData,
    pub transaction_type: TransactionType,
    pub kickoff_id: KickoffId,
}

#[derive(Debug, Clone)]
pub struct AssertRequestData {
    pub deposit_data: DepositData,
    pub kickoff_id: KickoffId,
}

/// Signs all txes that are created and possible to be signed for the entity and returns them.
/// Tx's that are not possible to be signed: MiniAsserts, WatchtowerChallenge, Disprove, do not use
/// this for them
pub async fn create_and_sign_txs(
    db: Database,
    signer: &Actor,
    config: BridgeConfig,
    nofn_xonly_pk: XOnlyPublicKey,
    transaction_data: TransactionRequestData,
    block_hash: Option<[u8; 20]>, //to sign kickoff
) -> Result<Vec<(TransactionType, Transaction)>, BridgeError> {
    // get operator data
    let operator_data = db
        .get_operator(None, transaction_data.kickoff_id.operator_idx as i32)
        .await?
        .ok_or(BridgeError::OperatorNotFound(
            transaction_data.kickoff_id.operator_idx,
        ))?;

    let start_time = std::time::Instant::now();
    let txhandlers = builder::transaction::create_txhandlers(
        nofn_xonly_pk,
        transaction_data.transaction_type,
        transaction_data.kickoff_id,
        operator_data,
        None,
        &mut ReimburseDbCache::new(
            db.clone(),
            transaction_data.kickoff_id.operator_idx,
            transaction_data.deposit_data.clone(),
            &config,
        ),
    )
    .await?;
    tracing::trace!(
        "create_txhandlers for {:?} finished in {:?}",
        transaction_data.transaction_type,
        start_time.elapsed()
    );

    // signatures saved during deposit
    let deposit_sigs_query = db
        .get_deposit_signatures(
            None,
            transaction_data.deposit_data.deposit_outpoint,
            transaction_data.kickoff_id.operator_idx as usize,
            transaction_data.kickoff_id.round_idx as usize,
            transaction_data.kickoff_id.kickoff_idx as usize,
        )
        .await?;
    let mut signatures = deposit_sigs_query.unwrap_or_default();

    // signatures saved during setup
    let setup_sigs_query = db
        .get_unspent_kickoff_sigs(
            None,
            transaction_data.kickoff_id.operator_idx as usize,
            transaction_data.kickoff_id.round_idx as usize,
        )
        .await?;

    signatures.extend(setup_sigs_query.unwrap_or_default());

    let mut signed_txs = Vec::with_capacity(txhandlers.len());

    for (tx_type, mut txhandler) in txhandlers.into_iter() {
        let _ = signer.tx_sign_and_fill_sigs(&mut txhandler, &signatures);

        if let TransactionType::OperatorChallengeAck(watchtower_idx) = tx_type {
            let path = WinternitzDerivationPath::ChallengeAckHash(
                watchtower_idx as u32,
                transaction_data.deposit_data.deposit_outpoint.txid,
                config.protocol_paramset(),
            );
            let preimage = signer.generate_preimage_from_path(path)?;
            let _ = signer.tx_sign_preimage(&mut txhandler, preimage);
        }

        if let TransactionType::Kickoff = tx_type {
            if let Some(block_hash) = block_hash {
                // need to commit blockhash to start kickoff
                let path = WinternitzDerivationPath::Kickoff(
                    transaction_data.kickoff_id.round_idx,
                    transaction_data.kickoff_id.kickoff_idx,
                    config.protocol_paramset(),
                );
                signer.tx_sign_winternitz(&mut txhandler, &[(block_hash.to_vec(), path)])?;
            }
            // do not give err if blockhash was not given
        }

        let checked_txhandler = txhandler.promote();

        match checked_txhandler {
            Ok(checked_txhandler) => {
                signed_txs.push((tx_type, checked_txhandler.get_cached_tx().clone()));
            }
            Err(e) => {
                tracing::trace!(
                    "Couldn't sign transaction {:?} in create_and_sign_all_txs: {:?}",
                    tx_type,
                    e
                );
            }
        }
    }

    Ok(signed_txs)
}

impl Watchtower {
    /// Creates and signs the watchtower challenge
    pub async fn create_and_sign_watchtower_challenge(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        transaction_data: TransactionRequestData,
        commit_data: &[u8],
    ) -> Result<RawSignedTx, BridgeError> {
        if commit_data.len()
            != self
                .config
                .protocol_paramset()
                .watchtower_challenge_message_length
                / 2
        {
            return Err(BridgeError::InvalidWatchtowerChallengeData);
        }
        // get operator data
        let operator_data = self
            .db
            .get_operator(None, transaction_data.kickoff_id.operator_idx as i32)
            .await?
            .ok_or(BridgeError::OperatorNotFound(
                transaction_data.kickoff_id.operator_idx,
            ))?;

        let start_time = std::time::Instant::now();
        let mut txhandlers = builder::transaction::create_txhandlers(
            nofn_xonly_pk,
            TransactionType::WatchtowerChallenge(self.config.index as usize),
            transaction_data.kickoff_id,
            operator_data,
            None,
            &mut ReimburseDbCache::new(
                self.db.clone(),
                transaction_data.kickoff_id.operator_idx,
                transaction_data.deposit_data.clone(),
                &self.config,
            ),
        )
        .await?;
        tracing::trace!(
            "create_txhandlers for {:?} finished in {:?}",
            TransactionType::WatchtowerChallenge(self.config.index as usize),
            start_time.elapsed()
        );

        let mut requested_txhandler = txhandlers
            .remove(&transaction_data.transaction_type)
            .ok_or(BridgeError::TxHandlerNotFound(
                transaction_data.transaction_type,
            ))?;

        let path = WinternitzDerivationPath::WatchtowerChallenge(
            transaction_data.kickoff_id.operator_idx,
            transaction_data.deposit_data.deposit_outpoint.txid,
            self.config.protocol_paramset(),
        );
        self.signer
            .tx_sign_winternitz(&mut requested_txhandler, &[(commit_data.to_vec(), path)])?;

        let checked_txhandler = requested_txhandler.promote()?;

        Ok(checked_txhandler.encode_tx())
    }
}

impl Operator {
    pub async fn create_assert_commitment_txs(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        assert_data: AssertRequestData,
    ) -> Result<RawSignedTxs, BridgeError> {
        // get operator data
        let operator_data = self
            .db
            .get_operator(None, assert_data.kickoff_id.operator_idx as i32)
            .await?
            .ok_or(BridgeError::OperatorNotFound(
                assert_data.kickoff_id.operator_idx,
            ))?;

        let mut txhandlers = builder::transaction::create_txhandlers(
            nofn_xonly_pk,
            TransactionType::MiniAssert(0),
            assert_data.kickoff_id,
            operator_data,
            None,
            &mut ReimburseDbCache::new(
                self.db.clone(),
                assert_data.kickoff_id.operator_idx,
                assert_data.deposit_data.clone(),
                &self.config,
            ),
        )
        .await?;

        let mut signed_txhandlers = Vec::new();

        for idx in 0..ClementineBitVMPublicKeys::number_of_assert_txs() {
            let mut mini_assert_txhandler =
                txhandlers.remove(&TransactionType::MiniAssert(idx)).ok_or(
                    BridgeError::TxHandlerNotFound(TransactionType::MiniAssert(idx)),
                )?;
            let dummy_data = vec![];
            self.signer
                .tx_sign_winternitz(&mut mini_assert_txhandler, &dummy_data)?;
            signed_txhandlers.push(mini_assert_txhandler.promote()?);
        }

        Ok(RawSignedTxs {
            raw_txs: signed_txhandlers
                .into_iter()
                .map(|txhandler| txhandler.encode_tx())
                .collect(),
        })
    }
}
