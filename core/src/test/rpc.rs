use bitcoin::{secp256k1::SecretKey, Amount};
use bitcoin::{Address, OutPoint, Transaction};
use bitcoincore_rpc::json::ScanTxOutRequest;
use bitcoincore_rpc::RpcApi;

use crate::actor::Actor;
use crate::rpc::clementine::Outpoints;
use crate::test::common::citrea::MockCitreaClient;
use crate::test::common::{
    create_regtest_rpc, create_test_config_with_thread_name, test_actors::TestActors,
};

#[tokio::test]
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

    test_actors
        .add_operator(operator_secret_key, 0, operator_reimbursement_address, None)
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
}
