use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::transaction::creator::TxHandlerDbData;
use crate::builder::transaction::{DepositData, TransactionType};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::{KickoffId, RawSignedTx, RawSignedTxs};
use crate::{builder, utils};
use bitcoin::XOnlyPublicKey;
use tonic::Status;

pub struct TransactionRequestData {
    pub deposit_data: DepositData,
    pub transaction_type: TransactionType,
    pub kickoff_id: KickoffId,
    pub commit_data: Vec<u8>,
}

pub struct AssertRequestData {
    pub deposit_data: DepositData,
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
    // get operator data
    let operator_data = db
        .get_operator(None, transaction_data.kickoff_id.operator_idx as i32)
        .await?
        .ok_or(BridgeError::OperatorNotFound(
            transaction_data.kickoff_id.operator_idx,
        ))?;

    let mut txhandlers = builder::transaction::create_txhandlers(
        config.clone(),
        transaction_data.deposit_data.clone(),
        nofn_xonly_pk,
        transaction_data.transaction_type,
        transaction_data.kickoff_id,
        operator_data,
        None,
        &mut TxHandlerDbData::new(
            db.clone(),
            transaction_data.kickoff_id.operator_idx,
            transaction_data.deposit_data.clone(),
            config.clone(),
        ),
    )
    .await?;

    let sig_query = db
        .get_deposit_signatures(
            None,
            transaction_data.deposit_data.deposit_outpoint,
            transaction_data.kickoff_id.operator_idx as usize,
            transaction_data.kickoff_id.round_idx as usize,
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
        let path = WinternitzDerivationPath::ChallengeAckHash(
            watchtower_idx as u32,
            transaction_data.deposit_data.deposit_outpoint.txid,
        );
        let preimage = signer.generate_preimage_from_path(path)?;
        signer.tx_sign_preimage(&mut requested_txhandler, preimage)?;
    }
    if let TransactionType::MiniAssert(assert_idx) = transaction_data.transaction_type {
        let (step_name, step_size) = utils::BITVM_CACHE
            .intermediate_variables
            .iter()
            .nth(assert_idx)
            .ok_or_else(|| Status::invalid_argument("Mini Assert Index is too big"))?;
        let path = WinternitzDerivationPath::BitvmAssert(
            *step_size as u32,
            step_name.to_owned(),
            transaction_data.deposit_data.deposit_outpoint.txid,
        );
        signer.tx_sign_winternitz(
            &mut requested_txhandler,
            &transaction_data.commit_data,
            path,
        )?;
    }
    if let TransactionType::WatchtowerChallenge(_) = transaction_data.transaction_type {
        let path = WinternitzDerivationPath::WatchtowerChallenge(
            transaction_data.kickoff_id.operator_idx,
            transaction_data.deposit_data.deposit_outpoint.txid,
        );
        signer.tx_sign_winternitz(
            &mut requested_txhandler,
            &transaction_data.commit_data,
            path,
        )?;
    }
    if let TransactionType::Kickoff = transaction_data.transaction_type {
        // need to commit blockhash to start kickoff
        let path = WinternitzDerivationPath::Kickoff(
            transaction_data.kickoff_id.round_idx,
            transaction_data.kickoff_id.kickoff_idx,
        );
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
        .await?
        .ok_or(BridgeError::OperatorNotFound(
            assert_data.kickoff_id.operator_idx,
        ))?;

    if assert_data.commit_data.len() != utils::BITVM_CACHE.intermediate_variables.len() {
        return Err(BridgeError::InvalidCommitData);
    }

    let mut txhandlers = builder::transaction::create_txhandlers(
        config.clone(),
        assert_data.deposit_data.clone(),
        nofn_xonly_pk,
        TransactionType::MiniAssert(0),
        assert_data.kickoff_id,
        operator_data,
        None,
        &mut TxHandlerDbData::new(
            db.clone(),
            assert_data.kickoff_id.operator_idx,
            assert_data.deposit_data.clone(),
            config.clone(),
        ),
    )
    .await?;

    let mut signed_txhandlers = Vec::new();

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

        let path = WinternitzDerivationPath::BitvmAssert(
            step_size as u32 * 2,
            step_name.to_owned(),
            assert_data.deposit_data.deposit_outpoint.txid,
        );
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

    Ok(RawSignedTxs {
        raw_txs: signed_txhandlers
            .into_iter()
            .map(|txhandler| txhandler.encode_tx())
            .collect(),
    })
}
