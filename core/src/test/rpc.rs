//! # RPC Tests
//!
//! This tests checks if typical RPC flows works or not.

use super::common::run_single_deposit;
use crate::bitvm_client::SECP;
use crate::rpc::clementine::WithdrawParams;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use tonic::Request;

use crate::test::common::*;

#[ignore = "Design changes in progress"]
#[tokio::test]
async fn honest_operator_takes_refund() {
    let mut config = create_test_config_with_thread_name(None).await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    let (_verifiers, mut operators, _aggregator, _watchtowers, _deposit_outpoint) =
        run_single_deposit(config.clone()).await.unwrap();

    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();

    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.protocol_paramset().network,
    );

    // We are giving enough sats to the user so that the operator can pay the
    // withdrawal and profit.
    let withdrawal_amount = Amount::from_sat(
        config.protocol_paramset().bridge_amount.to_sat()
            - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
    );

    let (empty_utxo, _withdrawal_tx_out, user_sig) = generate_withdrawal_transaction_and_signature(
        &config,
        &rpc,
        &withdrawal_address,
        withdrawal_amount,
    )
    .await;

    let request = Request::new(WithdrawParams {
        withdrawal_id: 0,
        input_signature: user_sig.serialize().to_vec(),
        input_outpoint: Some(empty_utxo.outpoint.into()),
        output_script_pubkey: _withdrawal_tx_out.txout().script_pubkey.clone().into(),
        output_amount: withdrawal_amount.to_sat(),
    });
    let _withdrawal_provide_txid = operators[1].withdraw(request).await.unwrap().into_inner();

    // let request = Request::new(WithdrawalFinalizedParams {
    //     withdrawal_id: 0,
    //     deposit_outpoint: Some(deposit_outpoint.into()),
    // });
    // operators[1].withdrawal_finalized(request).await.unwrap();

    // for tx in txs_to_be_sent.iter().take(txs_to_be_sent.len() - 1) {
    //     rpc.client.send_raw_transaction(tx.clone()).await.unwrap();
    //     rpc.mine_blocks(1).await.unwrap();
    // }
    // rpc.mine_blocks(1 + config.operator_takes_after as u64)
    //     .await
    //     .unwrap();

    // Send last transaction.
    // let operator_take_txid = rpc
    //     .client
    //     .send_raw_transaction(txs_to_be_sent.last().unwrap().clone())
    //     .await
    //     .unwrap();
    // let operator_take_tx = rpc
    //     .client
    //     .get_raw_transaction(&operator_take_txid, None)
    //     .await
    //     .unwrap();

    // assert!(operator_take_tx.output[0].value > withdrawal_amount);

    // assert_eq!(
    //     operator_take_tx.output[0].script_pubkey,
    //     config.operator_wallet_addresses[1]
    //         .clone()
    //         .assume_checked()
    //         .script_pubkey()
    // );
}

// #[ignore = "We are switching to gRPC"]
// #[tokio::test]
// async fn withdrawal_fee_too_low() {
//     let (_verifiers, operators, config, _) = run_single_deposit("test_config.toml").await.unwrap();
//     let rpc = ExtendedRpc::connect(
//         config.bitcoin_rpc_url.clone(),
//         config.bitcoin_rpc_user.clone(),
//         config.bitcoin_rpc_password.clone(),
//     )
//     .await;

//     let user_sk = SecretKey::from_slice(&[12u8; 32]).unwrap();
//     let withdrawal_address = Address::p2tr(
//         &SECP,
//         user_sk.x_only_public_key(&SECP).0,
//         None,
//         config.protocol_paramset().network,
//     );

//     let user = User::new(rpc.clone_inner().await.unwrap(), user_sk, config.clone());

//     // We are giving too much sats to the user so that operator won't pay it.
//     let (empty_utxo, withdrawal_tx_out, user_sig) = user
//         .generate_withdrawal_transaction_and_signature(
//             withdrawal_address,
//             Amount::from_sat(config.protocol_paramset().bridge_amount.to_sat()),
//         )
//         .await
//         .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature

//     // Operator will reject because it its not profitable.
//     assert!(operators[0]
//         .0
//         .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
//         .await
//         .is_err_and(|err| {
//             if let jsonrpsee::core::client::Error::Call(err) = err {
//                 err.message() == BridgeError::NotEnoughFeeForOperator.to_string()
//             } else {
//                 false
//             }
//         }));
// }
