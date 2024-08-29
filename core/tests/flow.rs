// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::Address;
use clementine_circuits::constants::OPERATOR_TAKES_AFTER;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::{
    create_extended_rpc, errors::BridgeError, traits::rpc::OperatorRpcClient, user::User,
};
use common::run_single_deposit;
use secp256k1::SecretKey;

mod common;

#[tokio::test]
async fn test_deposit() -> Result<(), BridgeError> {
    match run_single_deposit("test_config_flow.toml").await {
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
        run_single_deposit("test_config_flow.toml").await.unwrap();
    let rpc = create_extended_rpc!(config);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_sk = SecretKey::from_slice(&[12u8; 32]).unwrap();
    let user = User::new(rpc.clone(), user_sk, config.clone());
    let withdrawal_address = Address::p2tr(
        &secp,
        user_sk.x_only_public_key(&secp).0,
        None,
        config.network,
    );
    let (empty_utxo, withdrawal_tx_out, user_sig) =
        user.generate_withdrawal_sig(withdrawal_address).unwrap();
    let withdrawal_provide_txid = operators[0]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await
        .unwrap();
    println!("Withdrawal provide: {:?}", withdrawal_provide_txid);
    let txs_to_be_sent = operators[0]
        .0
        .withdrawal_proved_on_citrea_rpc(0, deposit_outpoint)
        .await
        .unwrap();
    tracing::debug!("txs_to_be_sent: {:#?}", txs_to_be_sent);

    for tx in txs_to_be_sent.iter().take(txs_to_be_sent.len() - 1) {
        let outpoint = rpc.send_raw_transaction(tx.clone()).unwrap();
        tracing::debug!("outpoint: {:#?}", outpoint);
    }
    rpc.mine_blocks(OPERATOR_TAKES_AFTER as u64).unwrap();
    // send the last tx
    rpc.send_raw_transaction(txs_to_be_sent.last().unwrap().clone())
        .unwrap();
}
