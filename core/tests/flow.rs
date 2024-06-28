//! # Deposit and Withdraw Flow Test
//!
//! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::{Address, Amount};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::create_test_database;
use clementine_core::database::common::Database;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::script_builder::ScriptBuilder;
use clementine_core::servers::*;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::transaction_builder::{CreateTxOutputs, TransactionBuilder};
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::EVMAddress;
use std::thread;

#[tokio::test]
async fn test_flow_1() {
    // Create a temporary database for testing.
    let handle = thread::current()
        .name()
        .unwrap()
        .split(':')
        .last()
        .unwrap()
        .to_owned();
    let config = create_test_database!(handle, "test_config_flow_1.toml");
    for i in 0..4 {
        create_test_database!(
            handle.clone() + i.to_string().as_str(),
            "test_config_flow_1.toml"
        );
    }

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    let (operator_client, _operator_handler, _results) =
        create_operator_and_verifiers(config.clone()).await;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let taproot_address = Address::p2tr(&secp, xonly_pk, None, config.network);
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.network);

    let evm_addresses = [
        EVMAddress([1u8; 20]),
        EVMAddress([2u8; 20]),
        EVMAddress([3u8; 20]),
        EVMAddress([4u8; 20]),
    ];

    let deposit_addresses = evm_addresses
        .iter()
        .map(|evm_address| {
            tx_builder
                .generate_deposit_address(
                    taproot_address.as_unchecked(),
                    evm_address,
                    BRIDGE_AMOUNT_SATS,
                    config.user_takes_after,
                )
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();
    tracing::debug!("Deposit addresses: {:#?}", deposit_addresses);

    for (idx, deposit_address) in deposit_addresses.iter().enumerate() {
        let deposit_utxo = rpc
            .send_to_address(deposit_address, BRIDGE_AMOUNT_SATS)
            .unwrap();
        tracing::debug!("Deposit UTXO #{}: {:#?}", idx, deposit_utxo);

        rpc.mine_blocks(18).unwrap();

        let output = operator_client
            .new_deposit_rpc(
                deposit_utxo,
                taproot_address.as_unchecked().clone(),
                evm_addresses[idx],
            )
            .await
            .unwrap();
        tracing::debug!("Output #{}: {:#?}", idx, output);
    }

    let withdrawal_address = Address::p2tr(&secp, xonly_pk, None, config.network);

    // This index is 3 since when testing the unit tests complete first and the index=1,2 is not sane
    let withdraw_txid = operator_client
        .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
        .await
        .unwrap();
    tracing::debug!("Withdrawal sent to address: {:?}", withdrawal_address);
    tracing::debug!("Withdrawal TXID: {:#?}", withdraw_txid);

    // get the tx details from rpc with txid
    let tx = rpc.get_raw_transaction(&withdraw_txid, None).unwrap();
    // tracing::debug!("Withdraw TXID raw transaction: {:#?}", tx);

    // check whether it has an output with the withdrawal address
    let rpc_withdraw_script = tx.output[0].script_pubkey.clone();
    let rpc_withdraw_amount = tx.output[0].value;
    let expected_withdraw_script = withdrawal_address.script_pubkey();
    assert_eq!(rpc_withdraw_script, expected_withdraw_script);
    let anyone_can_spend_amount = ScriptBuilder::anyone_can_spend_txout().value;

    // check if the amounts match
    let expected_withdraw_amount = Amount::from_sat(BRIDGE_AMOUNT_SATS - 2 * config.min_relay_fee)
        - anyone_can_spend_amount * 2;
    assert_eq!(expected_withdraw_amount, rpc_withdraw_amount);
}

#[tokio::test]
async fn test_flow_2() {
    // Create a temporary database for testing.
    let handle = thread::current()
        .name()
        .unwrap()
        .split(':')
        .last()
        .unwrap()
        .to_owned();
    let config = create_test_database!(handle, "test_config_flow_2.toml");
    for i in 0..4 {
        create_test_database!(
            handle.clone() + i.to_string().as_str(),
            "test_config_flow_2.toml"
        );
    }

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    let (_operator_client, _operator_handler, _results) =
        create_operator_and_verifiers(config.clone()).await;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let taproot_address = Address::p2tr(&secp, xonly_pk, None, config.network);
    tracing::debug!(
        "Taproot address script pubkey: {:#?}",
        taproot_address.script_pubkey()
    );
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.network);

    let evm_address = EVMAddress([1u8; 20]);

    let deposit_address_info = tx_builder
        .generate_deposit_address(
            taproot_address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
            config.user_takes_after,
        )
        .unwrap();

    tracing::debug!(
        "Deposit address taproot spend info: {:#?}",
        deposit_address_info.1
    );
    tracing::debug!("Deposit address: {:#?}", deposit_address_info.0);

    let deposit_utxo = rpc
        .send_to_address(&deposit_address_info.0, BRIDGE_AMOUNT_SATS)
        .unwrap();
    tracing::debug!("Deposit UTXO: {:#?}", deposit_utxo);
    rpc.mine_blocks(config.user_takes_after as u64 + 2).unwrap();
    let signer = Actor::new(config.secret_key, config.network);
    let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();
    let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(
        vec![deposit_utxo],
        config.user_takes_after as u16 + 1,
    );
    let tx_outs = TransactionBuilder::create_tx_outs(vec![
        (
            Amount::from_sat(BRIDGE_AMOUNT_SATS - 2 * config.min_relay_fee)
                - anyone_can_spend_txout.value * 2,
            taproot_address.script_pubkey(),
        ),
        (
            anyone_can_spend_txout.value,
            anyone_can_spend_txout.script_pubkey,
        ),
    ]);
    let takes_after_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
    let deposit_tx = rpc.get_raw_transaction(&deposit_utxo.txid, None).unwrap();
    let prevouts = vec![deposit_tx.output[deposit_utxo.vout as usize].clone()];

    let takes_after_script = ScriptBuilder::generate_timelock_script(
        taproot_address.as_unchecked(),
        config.user_takes_after,
    );
    let bridge_script = tx_builder.script_builder.generate_script_n_of_n();

    let mut takes_after_tx_details = CreateTxOutputs {
        tx: takes_after_tx.clone(),
        prevouts,
        scripts: vec![vec![bridge_script, takes_after_script]],
        taproot_spend_infos: vec![deposit_address_info.1],
    };

    let sig = signer
        .sign_taproot_script_spend_tx_new_tweaked(&mut takes_after_tx_details, 0, 1)
        .unwrap();

    handle_taproot_witness_new(&mut takes_after_tx_details, &vec![sig.as_ref()], 0, 1).unwrap();
    tracing::debug!(
        "now sending takes_after_tx: {:#?}",
        takes_after_tx_details.tx
    );
    let user_takes_back_txid = rpc
        .send_raw_transaction(&takes_after_tx_details.tx)
        .unwrap();
    tracing::debug!("User takes back txid: {:?}", user_takes_back_txid);
    let user_takes_back_tx = rpc
        .get_raw_transaction(&user_takes_back_txid, None)
        .unwrap();
    tracing::debug!("User takes back tx: {:#?}", user_takes_back_tx);
}
