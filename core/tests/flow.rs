//! # Flow Tests
//!
//! This tests checks if typical flows works or not.

use bitcoin::Address;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::utils::SECP;
use clementine_core::{create_extended_rpc, traits::rpc::OperatorRpcClient, user::User};
use common::run_single_deposit;
use secp256k1::SecretKey;

mod common;

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
    let withdrawal_amount =
        config.bridge_amount_sats - 2 * config.operator_withdrawal_fee_sats.unwrap();

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

    assert!(operator_take_tx.output[0].value > bitcoin::Amount::from_sat(withdrawal_amount));

    assert_eq!(
        operator_take_tx.output[0].script_pubkey,
        config.operator_wallet_addresses[1]
            .clone()
            .assume_checked()
            .script_pubkey()
    );
}

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
            config.bridge_amount_sats,
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
