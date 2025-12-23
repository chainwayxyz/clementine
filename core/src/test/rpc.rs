use bitcoin::{secp256k1::SecretKey, Amount};
use bitcoin::{Address, OutPoint, Transaction};
use bitcoincore_rpc::json::ScanTxOutRequest;
use bitcoincore_rpc::RpcApi;

use crate::actor::Actor;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::operator::RoundIndex;
use crate::rpc::clementine::{KickoffId, Outpoints, TransactionRequest};
use crate::test::common::citrea::MockCitreaClient;
use crate::test::common::tx_utils::get_tx_from_signed_txs_with_type;
use crate::test::common::{
    create_regtest_rpc, create_test_config_with_thread_name, run_single_deposit,
    test_actors::TestActors,
};

#[tokio::test]
#[cfg(feature = "automation")]
async fn operator_transfer_to_btc_wallet() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc();

    // do not start unnecessary verifiers and operators with TestActors
    config.test_params.all_operators_secret_keys = vec![];
    config.test_params.all_verifiers_secret_keys = vec![SecretKey::new(&mut rand::thread_rng())];
    let mut test_actors = TestActors::<MockCitreaClient>::new(&config).await.unwrap();

    // create new config for the operator
    let operator_secret_key = SecretKey::new(&mut rand::thread_rng());
    let signer = Actor::new(operator_secret_key, config.protocol_paramset().network);
    let operator_address = signer.address.clone();

    // set the operator reimbursement address to the signer address, otherwise the rpc will return an error.
    let operator_reimbursement_address = Some(operator_address.as_unchecked().clone());

    // create collateral funding outpoint
    let collateral_outpoint = rpc
        .send_to_address(
            &signer.address,
            config.protocol_paramset().collateral_funding_amount,
        )
        .await
        .unwrap();
    rpc.mine_blocks(1).await.unwrap();

    test_actors
        .add_operator(
            operator_secret_key,
            0,
            operator_reimbursement_address,
            Some(collateral_outpoint),
        )
        .await
        .unwrap();

    let mut operator_client =
        test_actors.get_operator_client_by_index(test_actors.num_total_operators - 1);

    // send some funds to the operator's address
    let utxo = rpc
        .send_to_address(&signer.address, Amount::from_sat(1000))
        .await
        .unwrap();
    let utxo2 = rpc
        .send_to_address(&signer.address, Amount::from_sat(2000))
        .await
        .unwrap();
    let utxo3 = rpc
        .send_to_address(&signer.address, Amount::from_sat(3000))
        .await
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();
    let operator_descriptor = format!("addr({operator_address})");
    let scan_request = ScanTxOutRequest::Single(operator_descriptor);

    let check_if_outpoints_are_in_address = async |outpoints: &[OutPoint]| -> bool {
        let operator_outpoints = rpc
            .scan_tx_out_set_blocking(&[scan_request.clone()])
            .await
            .unwrap();
        let operator_outpoints = operator_outpoints
            .unspents
            .into_iter()
            .map(|utxo| OutPoint::new(utxo.txid, utxo.vout))
            .collect::<Vec<_>>();
        for outpoint in outpoints {
            if !operator_outpoints.contains(outpoint) {
                return false;
            }
        }
        true
    };
    assert!(check_if_outpoints_are_in_address(&[utxo, utxo2, utxo3]).await);
    assert!(!check_if_outpoints_are_in_address(&[OutPoint::null()]).await);

    let raw_signed_tx = operator_client
        .transfer_to_btc_wallet(Outpoints {
            outpoints: vec![utxo.into(), utxo2.into()],
        })
        .await
        .unwrap()
        .into_inner()
        .raw_tx;

    let signed_tx: Transaction = bitcoin::consensus::deserialize(&raw_signed_tx).unwrap();

    let output_scriptpubkey = &signed_tx.output[0].script_pubkey;
    let output_address =
        Address::from_script(output_scriptpubkey, config.protocol_paramset().network).unwrap();

    // check if output address belongs to btc wallet
    let is_own_address = rpc
        .get_address_info(&output_address)
        .await
        .unwrap()
        .is_mine
        .unwrap_or(false);
    assert!(is_own_address);

    rpc.mine_blocks(1).await.unwrap();
    assert!(!check_if_outpoints_are_in_address(&[utxo, utxo2, utxo3]).await);
    assert!(check_if_outpoints_are_in_address(&[utxo3]).await);

    // include non operator utxo and check if it fails
    let random_utxo = rpc
        .send_to_address(
            &rpc.get_new_address(None, None)
                .await
                .unwrap()
                .assume_checked(),
            Amount::from_sat(1000),
        )
        .await
        .unwrap();
    assert!(operator_client
        .transfer_to_btc_wallet(Outpoints {
            outpoints: vec![random_utxo.into(), utxo3.into()],
        })
        .await
        .is_err());
    assert!(check_if_outpoints_are_in_address(&[utxo3]).await);

    // check that operator's collateral cannot be sent
    let collateral_error = operator_client
        .transfer_to_btc_wallet(Outpoints {
            outpoints: vec![collateral_outpoint.into()],
        })
        .await
        .unwrap_err();
    assert!(collateral_error
        .message()
        .contains("Cannot transfer collateral outpoint"));

    // create deposit and check collateral for all rounds and ready to reimburse txs
    let (deposit_info, ..) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, &test_actors, None)
            .await
            .unwrap();
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    let mut first_round_sent = false;
    let num_rounds = config.protocol_paramset().num_round_txs;
    for round in RoundIndex::iter_rounds(num_rounds) {
        use tonic::Request;

        use crate::test::common::{
            mine_once_after_in_mempool, tx_utils::get_txid_where_utxo_is_spent,
        };

        rpc.mine_blocks(config.protocol_paramset().operator_reimburse_timelock as u64 + 2)
            .await
            .unwrap();

        let round_txs = operator_client
            .internal_create_signed_txs(TransactionRequest {
                deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
                kickoff_id: Some(KickoffId {
                    round_idx: round.to_index() as u32,
                    operator_xonly_pk: signer.xonly_public_key.serialize().to_vec(),
                    kickoff_idx: 0,
                }),
            })
            .await
            .unwrap()
            .into_inner();

        let round_tx =
            get_tx_from_signed_txs_with_type(&round_txs, TransactionType::Round).unwrap();
        let round_txid = round_tx.compute_txid();

        // we need to send the first round from collateral first
        if !first_round_sent {
            operator_client
                .internal_end_round(Request::new(crate::rpc::clementine::Empty {}))
                .await
                .unwrap();
            first_round_sent = true;
        }

        mine_once_after_in_mempool(
            rpc,
            round_txid,
            Some(format!("{round:?} tx").as_str()),
            None,
        )
        .await
        .unwrap();

        // check that collateral in round tx cannot be sent
        let round_collateral_outpoint =
            OutPoint::new(round_txid, UtxoVout::CollateralInRound.get_vout());
        let round_collateral_error = operator_client
            .transfer_to_btc_wallet(Outpoints {
                outpoints: vec![round_collateral_outpoint.into()],
            })
            .await
            .unwrap_err();
        assert!(round_collateral_error
            .message()
            .contains("Cannot transfer collateral outpoint"));

        // start the next round
        operator_client
            .internal_end_round(Request::new(crate::rpc::clementine::Empty {}))
            .await
            .unwrap();

        // Get ready to reimburse tx from round_txs
        let ready_to_reimburse_tx =
            get_tx_from_signed_txs_with_type(&round_txs, TransactionType::ReadyToReimburse)
                .unwrap();

        // check that collateral in ready to reimburse tx cannot be sent
        let ready_to_reimburse_txid = ready_to_reimburse_tx.compute_txid();
        // wait until burnunusedkickoffconnectors tx is on chain
        get_txid_where_utxo_is_spent(rpc, OutPoint::new(round_txid, 1))
            .await
            .unwrap();
        // kickoffs need to be finalized before ready to reimburse tx can be sent
        rpc.mine_blocks(config.protocol_paramset().finality_depth as u64)
            .await
            .unwrap();
        mine_once_after_in_mempool(
            rpc,
            ready_to_reimburse_txid,
            Some(format!("{round:?} ready to reimburse tx").as_str()),
            None,
        )
        .await
        .unwrap();
        let ready_to_reimburse_collateral_outpoint = OutPoint::new(
            ready_to_reimburse_txid,
            UtxoVout::CollateralInReadyToReimburse.get_vout(),
        );
        let ready_to_reimburse_collateral_error = operator_client
            .transfer_to_btc_wallet(Outpoints {
                outpoints: vec![ready_to_reimburse_collateral_outpoint.into()],
            })
            .await;
        assert!(ready_to_reimburse_collateral_error
            .expect_err(
                format!("Should fail to transfer ReadyToReimburse collateral belonging to {round:?} to wallet").as_str(),
            )
            .message()
            .contains("Cannot transfer collateral outpoint"));
    }
}
