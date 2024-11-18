//! # Flow Tests
//!
//! This tests checks if typical flows works or not.

use std::str::FromStr;

use bitcoin::{Address, Amount, Txid};
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use clementine_core::rpc::clementine::{self, DepositParams};
use clementine_core::servers::create_verifiers_and_operators_grpc;
use clementine_core::utils::{initialize_logger, SECP};
use clementine_core::{create_extended_rpc, traits::rpc::OperatorRpcClient, user::User};
use common::run_single_deposit;
use secp256k1::SecretKey;
use tonic::transport::Uri;

mod common;

#[ignore = "We are switching to gRPC"]
#[tokio::test]
async fn honest_operator_takes_refund() {
    let (_verifiers, operators, mut config, deposit_outpoint) =
        run_single_deposit("test_config.toml").await.unwrap();
    let rpc = create_extended_rpc!(config);

    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let user = User::new(rpc.clone(), user_sk, config.clone());

    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.network,
    );

    // We are giving enough sats to the user so that the operator can pay the
    // withdrawal and profit.
    let withdrawal_amount = Amount::from_sat(
        config.bridge_amount_sats.to_sat()
            - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
    );

    let (empty_utxo, withdrawal_tx_out, user_sig) = user
        .generate_withdrawal_transaction_and_signature(withdrawal_address, withdrawal_amount)
        .unwrap();

    let _withdrawal_provide_txid = operators[1]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await
        .unwrap();

    let txs_to_be_sent = operators[1]
        .0
        .withdrawal_proved_on_citrea_rpc(0, deposit_outpoint)
        .await
        .unwrap();

    for tx in txs_to_be_sent.iter().take(txs_to_be_sent.len() - 1) {
        rpc.send_raw_transaction(tx.clone()).unwrap();
        rpc.mine_blocks(1).unwrap();
    }
    rpc.mine_blocks(1 + config.operator_takes_after as u64)
        .unwrap();

    // Send last transaction.
    let operator_take_txid = rpc
        .send_raw_transaction(txs_to_be_sent.last().unwrap().clone())
        .unwrap();
    let operator_take_tx = rpc.get_raw_transaction(&operator_take_txid, None).unwrap();

    assert!(operator_take_tx.output[0].value > withdrawal_amount);

    assert_eq!(
        operator_take_tx.output[0].script_pubkey,
        config.operator_wallet_addresses[1]
            .clone()
            .assume_checked()
            .script_pubkey()
    );
}

#[ignore = "We are switching to gRPC"]
#[tokio::test]
async fn withdrawal_fee_too_low() {
    let (_verifiers, operators, mut config, _) =
        run_single_deposit("test_config.toml").await.unwrap();
    let rpc = create_extended_rpc!(config);

    let user_sk = SecretKey::from_slice(&[12u8; 32]).unwrap();
    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.network,
    );

    let user = User::new(rpc.clone(), user_sk, config.clone());

    // We are giving too much sats to the user so that operator won't pay it.
    let (empty_utxo, withdrawal_tx_out, user_sig) = user
        .generate_withdrawal_transaction_and_signature(
            withdrawal_address,
            Amount::from_sat(config.bridge_amount_sats.to_sat()),
        )
        .unwrap();

    // Operator will reject because it its not profitable.
    assert!(operators[0]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await
        .is_err_and(|err| {
            if let jsonrpsee::core::client::Error::Call(err) = err {
                err.message() == BridgeError::NotEnoughFeeForOperator.to_string()
            } else {
                false
            }
        }));
}

#[tokio::test]
#[should_panic]
async fn double_calling_setip() {
    initialize_logger(5).unwrap();
    let (_verifiers, _operators, aggregator) =
        create_verifiers_and_operators_grpc("test_config.toml").await;

    let x: Uri = format!("http://{}", aggregator.0).parse().unwrap();

    println!("x: {:?}", x);

    let mut aggregator_client = ClementineAggregatorClient::connect(x).await.unwrap();

    aggregator_client
        .setup(tonic::Request::new(clementine::Empty {}))
        .await
        .unwrap();

    aggregator_client
        .setup(tonic::Request::new(clementine::Empty {}))
        .await
        .unwrap();
}

#[tokio::test]
async fn grpc_flow() {
    initialize_logger(5).unwrap();
    let (_verifiers, _operators, aggregator) =
        create_verifiers_and_operators_grpc("test_config.toml").await;

    let x: Uri = format!("http://{}", aggregator.0).parse().unwrap();

    println!("x: {:?}", x);

    let mut aggregator_client = ClementineAggregatorClient::connect(x).await.unwrap();

    aggregator_client
        .setup(tonic::Request::new(clementine::Empty {}))
        .await
        .unwrap();

    aggregator_client
        .new_deposit(DepositParams {
            deposit_outpoint: Some(
                bitcoin::OutPoint {
                    txid: Txid::from_str(
                        "17e3fc7aae1035e77a91e96d1ba27f91a40a912cf669b367eb32c13a8f82bb02",
                    )
                    .unwrap(),
                    vout: 0,
                }
                .into(),
            ),
            evm_address: [1u8; 20].to_vec(),
            recovery_taproot_address:
                "tb1pk8vus63mx5zwlmmmglq554kwu0zm9uhswqskxg99k66h8m3arguqfrvywa".to_string(),
            user_takes_after: 5,
        })
        .await
        .unwrap();

    // let mut verifier_client = ClementineVerifierClient::connect(x)
    //     .await
    //     .unwrap();

    // let x= verifier_client.nonce_gen(Empty {}).await.unwrap();
    // println!("x: {:?}", x);
}
