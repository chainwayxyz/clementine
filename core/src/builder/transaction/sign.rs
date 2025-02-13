use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::transaction::{DepositId, TransactionType};
use crate::config::BridgeConfig;
use crate::constants::{WATCHTOWER_CHALLENGE_MESSAGE_LENGTH, WINTERNITZ_LOG_D};
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::{KickoffId, RawSignedTx, RawSignedTxs};
use crate::{builder, utils};
use bitcoin::XOnlyPublicKey;
use tonic::Status;
pub struct TransactionRequestData {
    pub deposit_id: DepositId,
    pub transaction_type: TransactionType,
    pub kickoff_id: KickoffId,
    pub commit_data: Vec<u8>,
}

pub struct AssertRequestData {
    pub deposit_id: DepositId,
    pub kickoff_id: KickoffId,
    pub commit_data: Vec<Vec<u8>>,
}

/// Creates a transaction type for a kickoff Id, signs it and returns the raw signed transaction
pub async fn create_and_sign_tx(
    db: Database,
    signer: &Actor,
    config: BridgeConfig,
    nofn_xonly_pk: XOnlyPublicKey,
    transaction_data: TransactionRequestData,
) -> Result<RawSignedTx, BridgeError> {
    // Get all the watchtower challenge addresses for this operator. We have all of them here (for all the kickoff_utxos).
    // Optimize: Make this only return for a specific kickoff, but its only 40mb (33bytes * 60000 (kickoff per op?) * 20 (watchtower count)
    let watchtower_all_challenge_addresses = (0..config.num_watchtowers)
        .map(|i| {
            db.get_watchtower_challenge_addresses(
                None,
                i as u32,
                transaction_data.kickoff_id.operator_idx,
            )
        })
        .collect::<Vec<_>>();
    let watchtower_all_challenge_addresses =
        futures::future::try_join_all(watchtower_all_challenge_addresses).await?;

    // Collect the challenge Winternitz pubkeys for this specific kickoff_utxo.
    let watchtower_challenge_addresses = (0..config.num_watchtowers)
        .map(|i| {
            watchtower_all_challenge_addresses[i][transaction_data
                .kickoff_id
                .sequential_collateral_idx
                as usize
                * config.num_kickoffs_per_sequential_collateral_tx
                + transaction_data.kickoff_id.kickoff_idx as usize]
                .clone()
        })
        .collect::<Vec<_>>();

    // get operator data
    let operator_data = db
        .get_operator(None, transaction_data.kickoff_id.operator_idx as i32)
        .await?;

    let mut txhandlers = builder::transaction::create_txhandlers(
        db.clone(),
        config.clone(),
        transaction_data.deposit_id.clone(),
        nofn_xonly_pk,
        transaction_data.transaction_type,
        transaction_data.kickoff_id,
        operator_data,
        Some(&watchtower_challenge_addresses),
        None,
    )
    .await?;

    let sig_query = db
        .get_deposit_signatures(
            None,
            transaction_data.deposit_id.deposit_outpoint,
            transaction_data.kickoff_id.operator_idx as usize,
            transaction_data.kickoff_id.sequential_collateral_idx as usize,
            transaction_data.kickoff_id.kickoff_idx as usize,
        )
        .await?;
    let signatures = sig_query.unwrap_or_default();

    let mut requested_txhandler = txhandlers
        .remove(&transaction_data.transaction_type)
        .ok_or(BridgeError::TxHandlerNotFound(
            transaction_data.transaction_type,
        ))?;

    signer.tx_sign_and_fill_sigs(&mut requested_txhandler, &signatures)?;

    if let TransactionType::OperatorChallengeAck(watchtower_idx) = transaction_data.transaction_type
    {
        let path = WinternitzDerivationPath {
            message_length: 1,
            log_d: 1,
            tx_type: crate::actor::TxType::OperatorChallengeACK,
            operator_idx: Some(transaction_data.kickoff_id.operator_idx),
            watchtower_idx: Some(watchtower_idx as u32),
            sequential_collateral_tx_idx: None,
            kickoff_idx: None,
            intermediate_step_name: None,
            deposit_txid: Some(transaction_data.deposit_id.deposit_outpoint.txid),
        };
        let preimage = signer.generate_preimage_from_path(path)?;
        signer.tx_sign_preimage(&mut requested_txhandler, preimage)?;
    }
    if let TransactionType::MiniAssert(assert_idx) = transaction_data.transaction_type {
        let path = WinternitzDerivationPath {
            message_length: *utils::BITVM_CACHE
                .intermediate_variables
                .iter()
                .nth(assert_idx)
                .ok_or_else(|| Status::invalid_argument("Mini Assert Index is too big"))?
                .1 as u32
                * 2,
            log_d: WINTERNITZ_LOG_D,
            tx_type: crate::actor::TxType::BitVM,
            operator_idx: Some(transaction_data.kickoff_id.operator_idx),
            watchtower_idx: None,
            sequential_collateral_tx_idx: None,
            kickoff_idx: None,
            intermediate_step_name: Some(
                utils::BITVM_CACHE
                    .intermediate_variables
                    .iter()
                    .nth(assert_idx)
                    .ok_or_else(|| Status::invalid_argument("Mini Assert Index is too big"))?
                    .0,
            ),
            deposit_txid: Some(transaction_data.deposit_id.deposit_outpoint.txid),
        };
        signer.tx_sign_winternitz(
            &mut requested_txhandler,
            &transaction_data.commit_data,
            path,
        )?;
    }
    if let TransactionType::WatchtowerChallenge(_) = transaction_data.transaction_type {
        // same path as get_watchtower_winternitz_public_keys()
        let path = WinternitzDerivationPath {
            message_length: WATCHTOWER_CHALLENGE_MESSAGE_LENGTH,
            log_d: WINTERNITZ_LOG_D,
            tx_type: crate::actor::TxType::WatchtowerChallenge,
            operator_idx: Some(transaction_data.kickoff_id.operator_idx),
            watchtower_idx: None,
            sequential_collateral_tx_idx: Some(
                transaction_data.kickoff_id.sequential_collateral_idx,
            ),
            kickoff_idx: Some(transaction_data.kickoff_id.kickoff_idx),
            intermediate_step_name: None,
            deposit_txid: None,
        };
        signer.tx_sign_winternitz(
            &mut requested_txhandler,
            &transaction_data.commit_data,
            path,
        )?;
    }

    let checked_txhandler = requested_txhandler.promote()?;

    Ok(checked_txhandler.encode_tx())
}

pub async fn create_assert_commitment_txs(
    db: Database,
    signer: &Actor,
    config: BridgeConfig,
    nofn_xonly_pk: XOnlyPublicKey,
    assert_data: AssertRequestData,
) -> Result<RawSignedTxs, BridgeError> {
    // get operator data
    let operator_data = db
        .get_operator(None, assert_data.kickoff_id.operator_idx as i32)
        .await?;

    if assert_data.commit_data.len() != utils::BITVM_CACHE.intermediate_variables.len() {
        return Err(BridgeError::InvalidCommitData);
    }

    let mut txhandlers = builder::transaction::create_txhandlers(
        db.clone(),
        config.clone(),
        assert_data.deposit_id.clone(),
        nofn_xonly_pk,
        TransactionType::AssertEnd,
        assert_data.kickoff_id,
        operator_data,
        None,
        None,
    )
    .await?;

    let mut signed_txhandlers = Vec::new();

    let sig_query = db
        .get_deposit_signatures(
            None,
            assert_data.deposit_id.deposit_outpoint,
            assert_data.kickoff_id.operator_idx as usize,
            assert_data.kickoff_id.sequential_collateral_idx as usize,
            assert_data.kickoff_id.kickoff_idx as usize,
        )
        .await?;
    let signatures = sig_query.unwrap_or_default();

    let mut assert_begin_txhandler = txhandlers
        .remove(&TransactionType::AssertBegin)
        .ok_or(BridgeError::TxHandlerNotFound(TransactionType::AssertBegin))?;
    signer.tx_sign_and_fill_sigs(&mut assert_begin_txhandler, &signatures)?;
    signed_txhandlers.push(assert_begin_txhandler.promote()?);

    for (idx, (step_name, &step_size)) in
        utils::BITVM_CACHE.intermediate_variables.iter().enumerate()
    {
        if step_size != assert_data.commit_data[idx].len() {
            return Err(BridgeError::InvalidStepCommitData(
                idx,
                step_size,
                assert_data.commit_data[idx].len(),
            ));
        }

        let path = WinternitzDerivationPath {
            message_length: step_size as u32 * 2,
            log_d: WINTERNITZ_LOG_D,
            tx_type: crate::actor::TxType::BitVM,
            operator_idx: Some(assert_data.kickoff_id.operator_idx),
            watchtower_idx: None,
            sequential_collateral_tx_idx: None,
            kickoff_idx: None,
            intermediate_step_name: Some(step_name),
            deposit_txid: Some(assert_data.deposit_id.deposit_outpoint.txid),
        };
        let mut mini_assert_txhandler =
            txhandlers.remove(&TransactionType::MiniAssert(idx)).ok_or(
                BridgeError::TxHandlerNotFound(TransactionType::MiniAssert(idx)),
            )?;
        signer.tx_sign_winternitz(
            &mut mini_assert_txhandler,
            &assert_data.commit_data[idx],
            path,
        )?;
        signed_txhandlers.push(mini_assert_txhandler.promote()?);
    }

    let mut assert_end_txhandler = txhandlers
        .remove(&TransactionType::AssertEnd)
        .ok_or(BridgeError::TxHandlerNotFound(TransactionType::AssertEnd))?;
    signer.tx_sign_and_fill_sigs(&mut assert_end_txhandler, &signatures)?;
    signed_txhandlers.push(assert_end_txhandler.promote()?);

    Ok(RawSignedTxs {
        raw_txs: signed_txhandlers
            .into_iter()
            .map(|txhandler| txhandler.encode_tx())
            .collect(),
    })
}
