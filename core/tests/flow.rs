//! # Deposit and Withdraw Flow Test
//!
//! This test checks if basic deposit and withdraw operations are OK or not.

mod common;

use bitcoin::Address;
use bitcoincore_rpc::Auth;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{start_operator_and_verifiers, EVMAddress};
use common::get_test_config;

#[tokio::test]
async fn deposit_and_withdraw_flow() {
    let config = BridgeConfig::try_parse_file(
        get_test_config("test_config_deposit_and_withdraw.toml").into(),
    )
    .unwrap();

    let (operator_client, _operator_handler, _results) =
        start_operator_and_verifiers(config.clone()).await;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.clone());

    let evm_addresses = vec![
        EVMAddress([1u8; 20]),
        EVMAddress([2u8; 20]),
        EVMAddress([3u8; 20]),
        EVMAddress([4u8; 20]),
    ];

    let deposit_addresses = evm_addresses
        .iter()
        .map(|evm_address| {
            tx_builder
                .generate_deposit_address(&xonly_pk, evm_address, BRIDGE_AMOUNT_SATS)
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );

    for (idx, deposit_address) in deposit_addresses.iter().enumerate() {
        let deposit_utxo = rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)
            .unwrap();
        tracing::debug!("Deposit UTXO: {:?}", deposit_utxo);

        rpc.mine_blocks(18).unwrap();

        let output = operator_client
            .new_deposit_rpc(deposit_utxo, xonly_pk, evm_addresses[idx])
            .await
            .unwrap();
        tracing::debug!("Output: {:?}", output);
    }

    let withdrawal_address = Address::p2tr(&secp, xonly_pk, None, config.network);

    let withdraw_txid = operator_client
        .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
        .await
        .unwrap();
    tracing::debug!("Withdrawal TXID: {:?}", withdraw_txid);

    // get the tx details from rpc with txid
    // check wheter it has an output with the withdrawal address
}
