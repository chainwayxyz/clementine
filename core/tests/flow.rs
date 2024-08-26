//! # Deposit and Withdraw Flow Test
//!
//! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::XOnlyPublicKey;
use bitcoin::{Address, Amount};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::database::common::Database;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::script_builder;
use clementine_core::servers::*;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::transaction_builder::{TransactionBuilder, TxHandler};
use clementine_core::user::User;
use clementine_core::utils;
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::utils::SECP;
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use crypto_bigint::rand_core::OsRng;
use secp256k1::rand::Rng;
use secp256k1::SecretKey;
use std::thread;

#[tokio::test]
async fn test_withdrawal_request() {
    let mut config = create_test_config_with_thread_name!("test_config_flow.toml");
    let rpc = create_extended_rpc!(config);

    let (operator_client, _operator_handler, _operator_addr) =
        create_operator_server(config.clone(), rpc.clone())
            .await
            .unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_sk = SecretKey::from_slice(&OsRng.gen::<[u8; 32]>()).unwrap();
    let user = User::new(rpc, user_sk, config.clone());
    let withdrawal_address = Address::p2tr(
        &secp,
        user_sk.x_only_public_key(&secp).0,
        None,
        config.network,
    );
    let (empty_utxo, withdrawal_tx_out, user_sig) =
        user.generate_withdrawal_sig(withdrawal_address).unwrap();
    let withdrawal_provide_txid = operator_client
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await
        .unwrap();
    println!("{:?}", withdrawal_provide_txid);
}

#[tokio::test]
async fn test_honest_operator_takes_refund() {
    let mut config = create_test_config_with_thread_name!("test_config_flow.toml");
    let rpc = create_extended_rpc!(config);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_sk = SecretKey::from_slice(&OsRng.gen::<[u8; 32]>()).unwrap();
    let user = User::new(rpc, user_sk, config.clone());
    let withdrawal_address = Address::p2tr(
        &secp,
        user_sk.x_only_public_key(&secp).0,
        None,
        config.network,
    );
    let (empty_utxo, withdrawal_tx_out, user_sig) =
        user.generate_withdrawal_sig(withdrawal_address).unwrap();
    // let withdrawal_provide_txid = operator_client
    //     .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
    //     .await
    //     .unwrap();
    // println!("{:?}", withdrawal_provide_txid);
}

#[tokio::test]
async fn test_malicious_operator_gets_slashed() {}
