//! # Clementine related functions to do common operations

use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::citrea::CitreaClient;
use crate::database::Database;
use crate::deposit::KickoffData;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::{OptimisticWithdrawParams, TransactionRequest, WithdrawParams};
use crate::test::common::citrea::CitreaE2EData;
use crate::test::common::mine_once_after_in_mempool;
use crate::test::common::tx_utils::get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync;
use crate::test::sign::sign_optimistic_payout_verification_signature;
use crate::utils::FeePayingType;
use bitcoin::{OutPoint, Transaction, TxOut, Txid, XOnlyPublicKey};
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;

use super::test_actors::TestActors;
use super::tx_utils::{
    ensure_outpoint_spent_while_waiting_for_state_mngr_sync,
    mine_once_after_outpoint_spent_in_mempool,
};

/// Sends a payout tx with given operator for the given withdrawal, starts a kickoff then returns
/// the reimburse connector of the kickoff.
/// operator_xonly_pk and operator_db should match the operator client ClementineOperatorClient
#[allow(clippy::too_many_arguments)]
pub async fn payout_and_start_kickoff(
    mut operator: ClementineOperatorClient<tonic::transport::Channel>,
    operator_xonly_pk: XOnlyPublicKey,
    operator_db: &Database,
    withdrawal_id: u32,
    withdrawal_utxo: &OutPoint,
    payout_txout: &TxOut,
    sig: &bitcoin::secp256k1::schnorr::Signature,
    e2e: &CitreaE2EData<'_>,
    actors: &TestActors<CitreaClient>,
) -> OutPoint {
    loop {
        let withdrawal_response = operator
            .withdraw(WithdrawParams {
                withdrawal_id,
                input_signature: sig.serialize().to_vec(),
                input_outpoint: Some((*withdrawal_utxo).into()),
                output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                output_amount: payout_txout.value.to_sat(),
            })
            .await;

        tracing::info!("Withdrawal response: {:?}", withdrawal_response);

        match withdrawal_response {
            Ok(_) => break,
            Err(e) => tracing::info!("Withdrawal error: {:?}", e),
        };
        e2e.rpc.mine_blocks_while_synced(1, actors).await.unwrap();
    }

    let payout_txid = get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync(
        e2e.rpc,
        *withdrawal_utxo,
        actors,
    )
    .await
    .unwrap();

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors)
        .await
        .unwrap();

    tracing::info!(
        "Waiting until getting first unhandled payout for operator {:?}",
        operator_xonly_pk
    );

    // wait until payout is handled
    tracing::info!("Waiting until payout is handled");
    while operator_db
        .get_handled_payout_kickoff_txid(None, payout_txid)
        .await
        .unwrap()
        .is_none()
    {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let kickoff_txid = operator_db
        .get_handled_payout_kickoff_txid(None, payout_txid)
        .await
        .unwrap()
        .expect("Payout must be handled");

    let reimburse_connector = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::ReimburseInKickoff.get_vout(),
    };

    let kickoff_block_height =
        mine_once_after_in_mempool(e2e.rpc, kickoff_txid, Some("Kickoff tx"), Some(300))
            .await
            .unwrap();

    tracing::info!(
        "Kickoff height: {:?}, txid: {:?} operator: {:?}",
        kickoff_block_height,
        kickoff_txid,
        operator_xonly_pk
    );

    reimburse_connector
}

/// Reimburse a withdrawal with an optimistic payout
/// First it sends an optimistic payout tx request to aggregator, then it ensures the btc in vault is spent.
#[allow(clippy::too_many_arguments)]
pub async fn reimburse_with_optimistic_payout(
    actors: &TestActors<CitreaClient>,
    withdrawal_id: u32,
    withdrawal_utxo: &OutPoint,
    payout_txout: &TxOut,
    sig: &bitcoin::secp256k1::schnorr::Signature,
    e2e: &CitreaE2EData<'_>,
    move_txid: Txid,
) -> eyre::Result<()> {
    let mut aggregator = actors.get_aggregator();

    let withdrawal_params = WithdrawParams {
        withdrawal_id,
        input_signature: sig.serialize().to_vec(),
        input_outpoint: Some(withdrawal_utxo.to_owned().into()),
        output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
        output_amount: payout_txout.value.to_sat(),
    };

    let verification_signature =
        sign_optimistic_payout_verification_signature(&e2e.config, withdrawal_params.clone());

    let verification_signature_str = verification_signature.to_string();

    aggregator
        .optimistic_payout(OptimisticWithdrawParams {
            withdrawal: Some(withdrawal_params),
            verification_signature: Some(verification_signature_str),
        })
        .await?;

    // ensure the btc in vault is spent
    ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
        e2e.rpc,
        OutPoint {
            txid: move_txid,
            vout: (UtxoVout::DepositInMove).get_vout(),
        },
        actors,
    )
    .await?;

    Ok(())
}

/// Helper fn for common setup for disprove tests
/// Does a single deposit, registers a withdrawal, starts a kickoff from operator 0 and then challenges the kickoff
/// Afterwards it waits until all asserts are sent by operator.
/// Returns the actors, the kickoff txid and the kickoff tx
#[cfg(feature = "automation")]
pub async fn disprove_tests_common_setup(
    e2e: &CitreaE2EData<'_>,
) -> (TestActors<CitreaClient>, Txid, Transaction) {
    use crate::test::common::citrea::get_new_withdrawal_utxo_and_register_to_citrea;

    use super::run_single_deposit;
    use super::tx_utils::create_tx_sender;
    let mut config = e2e.config.clone();
    let (actors, deposit_info, move_txid, _deposit_blockhash, _) =
        run_single_deposit::<CitreaClient>(&mut config, e2e.rpc.clone(), None, None, None)
            .await
            .unwrap();

    // generate a withdrawal
    let (withdrawal_utxo, payout_txout, sig) =
        get_new_withdrawal_utxo_and_register_to_citrea(move_txid, e2e, &actors).await;

    // withdraw one with a kickoff with operator 0
    let (op0_db, op0_xonly_pk) = actors.get_operator_db_and_xonly_pk_by_index(0).await;
    let mut operator0 = actors.get_operator_client_by_index(0);

    let reimburse_connector = payout_and_start_kickoff(
        operator0.clone(),
        op0_xonly_pk,
        &op0_db,
        0,
        &withdrawal_utxo,
        &payout_txout,
        &sig,
        e2e,
        &actors,
    )
    .await;

    let kickoff_txid = reimburse_connector.txid;

    // send a challenge
    let kickoff_tx = e2e.rpc.get_tx_of_txid(&kickoff_txid).await.unwrap();

    // get kickoff utxo index
    let kickoff_idx = kickoff_tx.input[0].previous_output.vout - 1;
    let base_tx_req = TransactionRequest {
        kickoff_id: Some(
            KickoffData {
                operator_xonly_pk: op0_xonly_pk,
                round_idx: crate::operator::RoundIndex::Round(0),
                kickoff_idx: kickoff_idx as u32,
            }
            .into(),
        ),
        deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
    };

    let all_txs = operator0
        .internal_create_signed_txs(base_tx_req.clone())
        .await
        .unwrap()
        .into_inner();

    let challenge_tx = bitcoin::consensus::deserialize(
        &all_txs
            .signed_txs
            .iter()
            .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
            .unwrap()
            .raw_tx,
    )
    .unwrap();

    let (tx_sender, tx_sender_db) = create_tx_sender(&config, 0).await.unwrap();
    let mut db_commit = tx_sender_db.begin_transaction().await.unwrap();
    tx_sender
        .insert_try_to_send(
            &mut db_commit,
            None,
            &challenge_tx,
            FeePayingType::RBF,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
    db_commit.commit().await.unwrap();

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, &actors)
        .await
        .unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::Challenge.get_vout(),
    };
    // wait until challenge tx is in mempool and mine
    mine_once_after_outpoint_spent_in_mempool(e2e.rpc, challenge_outpoint)
        .await
        .unwrap();

    // wait until all asserts are mined
    for i in 0..ClementineBitVMPublicKeys::number_of_assert_txs() {
        ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
            e2e.rpc,
            OutPoint {
                txid: kickoff_txid,
                vout: UtxoVout::Assert(i).get_vout(),
            },
            &actors,
        )
        .await
        .unwrap();
    }

    (actors, kickoff_txid, kickoff_tx)
}
