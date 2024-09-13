// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::Address;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::{
    create_extended_rpc, errors::BridgeError, traits::rpc::OperatorRpcClient, user::User,
};
use common::{run_multiple_deposits, run_single_deposit};
use secp256k1::SecretKey;

mod common;

#[tokio::test]
async fn test_deposit() -> Result<(), BridgeError> {
    match run_single_deposit("test_config.toml").await {
        Ok((_, _, _, deposit_outpoint)) => {
            // tracing::debug!("Verifiers: {:#?}", verifiers);
            // tracing::debug!("Operators: {:#?}", operators);
            tracing::debug!("Deposit outpoint: {:#?}", deposit_outpoint);
            Ok(())
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            Err(e)
        }
    }
}

#[tokio::test]
async fn test_honest_operator_takes_refund() {
    // let mut config = create_test_config_with_thread_name!("test_config_flow.toml");
    let (_verifiers, operators, mut config, deposit_outpoint) =
        run_single_deposit("test_config.toml").await.unwrap();
    let rpc = create_extended_rpc!(config);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let user = User::new(rpc.clone(), user_sk, config.clone());
    let withdrawal_address = Address::p2tr(
        &secp,
        user_sk.x_only_public_key(&secp).0,
        None,
        config.bitcoin.network,
    );
    // We are giving 99_800_000 sats to the user so that the operator can pay the withdrawal and profit.
    let (empty_utxo, withdrawal_tx_out, user_sig) = user
        .generate_withdrawal_sig(
            withdrawal_address,
            config.bridge_amount_sats - 2 * config.operator_withdrawal_fee_sats.unwrap(),
        )
        .unwrap();
    let withdrawal_provide_txid = operators[1]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await
        .unwrap();
    println!("Withdrawal provide: {:?}", withdrawal_provide_txid);
    let txs_to_be_sent = operators[1]
        .0
        .withdrawal_proved_on_citrea_rpc(0, deposit_outpoint)
        .await
        .unwrap();
    tracing::debug!("txs_to_be_sent: {:#?}", txs_to_be_sent);

    for tx in txs_to_be_sent.iter().take(txs_to_be_sent.len() - 1) {
        let outpoint = rpc.send_raw_transaction(tx.clone()).unwrap();
        rpc.mine_blocks(1).unwrap();
        tracing::debug!("outpoint: {:#?}", outpoint);
    }
    rpc.mine_blocks(1 + config.operator.takes_after as u64)
        .unwrap();
    // send the last tx
    let operator_take_txid = rpc
        .send_raw_transaction(txs_to_be_sent.last().unwrap().clone())
        .unwrap();
    let operator_take_tx = rpc.get_raw_transaction(&operator_take_txid, None).unwrap();

    assert!(
        operator_take_tx.output[0].value
            > bitcoin::Amount::from_sat(
                config.bridge_amount_sats - 2 * config.operator_withdrawal_fee_sats.unwrap()
            ),
        "Expected value to be greater than 99,800,000 satoshis, but it was not."
    );
    assert_eq!(
        operator_take_tx.output[0].script_pubkey,
        config.operator_wallet_addresses[1]
            .clone()
            .assume_checked()
            .script_pubkey()
    );
}

#[tokio::test]
async fn test_withdrawal_fee_too_low() {
    let (_verifiers, operators, mut config, _) =
        run_single_deposit("test_config.toml").await.unwrap();
    let rpc = create_extended_rpc!(config);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_sk = SecretKey::from_slice(&[12u8; 32]).unwrap();
    let user = User::new(rpc.clone(), user_sk, config.clone());
    let withdrawal_address = Address::p2tr(
        &secp,
        user_sk.x_only_public_key(&secp).0,
        None,
        config.bitcoin.network,
    );
    // We are giving 100_000_000 sats to the user so that the operator cannot pay it because it is not profitable.
    let (empty_utxo, withdrawal_tx_out, user_sig) = user
        .generate_withdrawal_sig(withdrawal_address, config.bridge_amount_sats)
        .unwrap();
    let withdrawal_provide_txid = operators[0]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await;
    assert!(withdrawal_provide_txid.is_err());
}

#[tokio::test]
async fn multiple_deposits_for_operator() {
    run_multiple_deposits("test_config.toml").await;
}
