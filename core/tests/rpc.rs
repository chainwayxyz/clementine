//! # RPC Tests
//!
//! This tests checks if typical RPC flows works or not.

mod common;

// #[ignore = "We are switching to gRPC"]
// #[tokio::test]
// #[serial_test::serial]
// async fn honest_operator_takes_refund() {
//     let (_verifiers, operators, config, deposit_outpoint) =
//         run_single_deposit("test_config.toml").await.unwrap();
//     let rpc = ExtendedRpc::new(
//         config.bitcoin_rpc_url.clone(),
//         config.bitcoin_rpc_user.clone(),
//         config.bitcoin_rpc_password.clone(),
//     )
//     .await;

//     let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
//     let user = User::new(rpc.clone(), user_sk, config.clone());

//     let withdrawal_address = Address::p2tr(
//         &SECP,
//         user_sk.x_only_public_key(&SECP).0,
//         None,
//         config.network,
//     );

//     // We are giving enough sats to the user so that the operator can pay the
//     // withdrawal and profit.
//     let withdrawal_amount = Amount::from_sat(
//         config.bridge_amount_sats.to_sat()
//             - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
//     );

//     let (empty_utxo, withdrawal_tx_out, user_sig) = user
//         .generate_withdrawal_transaction_and_signature(withdrawal_address, withdrawal_amount) This line needs to be converted into generate_withdrawal_transaction_and_signature!
//         .await
//         .unwrap();

//     let _withdrawal_provide_txid = operators[1]
//         .0
//         .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
//         .await
//         .unwrap();

//     let txs_to_be_sent = operators[1]
//         .0
//         .withdrawal_proved_on_citrea_rpc(0, deposit_outpoint)
//         .await
//         .unwrap();

//     for tx in txs_to_be_sent.iter().take(txs_to_be_sent.len() - 1) {
//         rpc.client.send_raw_transaction(tx.clone()).await.unwrap();
//         rpc.mine_blocks(1).await.unwrap();
//     }
//     rpc.mine_blocks(1 + config.operator_takes_after as u64)
//         .await
//         .unwrap();

//     // Send last transaction.
//     let operator_take_txid = rpc
//         .client
//         .send_raw_transaction(txs_to_be_sent.last().unwrap().clone())
//         .await
//         .unwrap();
//     let operator_take_tx = rpc
//         .client
//         .get_raw_transaction(&operator_take_txid, None)
//         .await
//         .unwrap();

//     assert!(operator_take_tx.output[0].value > withdrawal_amount);

//     assert_eq!(
//         operator_take_tx.output[0].script_pubkey,
//         config.operator_wallet_addresses[1]
//             .clone()
//             .assume_checked()
//             .script_pubkey()
//     );
// }

// #[ignore = "We are switching to gRPC"]
// #[tokio::test]
// async fn withdrawal_fee_too_low() {
//     let (_verifiers, operators, config, _) = run_single_deposit("test_config.toml").await.unwrap();
//     let rpc = ExtendedRpc::new(
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
//         config.network,
//     );

//     let user = User::new(rpc.clone(), user_sk, config.clone());

//     // We are giving too much sats to the user so that operator won't pay it.
//     let (empty_utxo, withdrawal_tx_out, user_sig) = user
//         .generate_withdrawal_transaction_and_signature(
//             withdrawal_address,
//             Amount::from_sat(config.bridge_amount_sats.to_sat()),
//         )
//         .await
//         .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature!

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
