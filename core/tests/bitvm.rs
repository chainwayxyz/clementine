//! # Deposit and Withdraw Flow Test
//!
//! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, OutPoint, Transaction, TxOut};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::database::common::Database;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::servers::*;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::transaction_builder::{CreateTxOutputs, TransactionBuilder};
use clementine_core::utils::{handle_taproot_pubkey_spend_witness, handle_taproot_witness_new};
use clementine_core::utils::SECP;
use clementine_core::EVMAddress;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use clementine_core::{script_builder, utils};
use secp256k1::schnorr::Signature;
use std::{thread, vec};

#[tokio::test]
async fn test_bitvm() {
    let mut config = create_test_config_with_thread_name!("test_config_bitvm.toml");
    let rpc = create_extended_rpc!(config);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (operator_xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let taproot_address = Address::p2tr(&secp, operator_xonly_pk, None, config.network);
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.network);

    // Create operator and verifier (challenger) entities
    let verifier = Actor::new(config.all_secret_keys.clone().unwrap()[0], config.network.clone());
    let operator = Actor::new(config.secret_key.clone(), config.network.clone());

    // Calculate the verifier_address
    let verifier_taproot_address =
        Address::p2tr(&secp, config.verifiers_public_keys[0], None, config.network);

    // Calculate the dummy_commit_address and dummy_commit_tree_info
    let dummy_commit_script = script_builder::generate_dummy_commit_script();
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);
    let dummy_commit_taproot = TaprootBuilder::new()
        .add_leaf(1, dummy_commit_script.clone())
        .unwrap()
        .add_leaf(1, musig_script.clone())
        .unwrap();
    let dummy_commit_tree_info = dummy_commit_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let dummy_commit_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        dummy_commit_tree_info.merkle_root(),
        config.network,
    );

    // Calculate the challenger_takes_after_address and challenger_takes_after_tree_info
    let challenger_takes_after_script = script_builder::generate_challenger_takes_after_script(
        &config.verifiers_public_keys[0],
        1008,
    );
    let challenger_takes_after_taproot = TaprootBuilder::new()
        .add_leaf(0, challenger_takes_after_script.clone())
        .unwrap();
    let challenger_takes_after_tree_info = challenger_takes_after_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let challenger_takes_after_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        challenger_takes_after_tree_info.merkle_root(),
        config.network.clone(),
    );

    let verifier_source_utxo = rpc
        .send_to_address(&verifier_taproot_address, 20_000)
        .unwrap();
    let verifier_source_utxo_as_prevout = TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: verifier_taproot_address.script_pubkey(),
    };

    let mut bitvm_setup = create_bitvm_sequence(
        1,
        verifier_source_utxo,
        &operator,
        &verifier,
        &config,
    );
    println!("{:?}", bitvm_setup);
    let verifier_sig = verifier.sign_taproot_pubkey_spend_tx(&mut bitvm_setup.0, &vec![verifier_source_utxo_as_prevout], 0).unwrap();
    handle_taproot_pubkey_spend_witness(&mut bitvm_setup.0, verifier_sig, 0).unwrap();
    let start_challenge_txid = rpc.send_raw_transaction(&bitvm_setup.0).unwrap();
    println!("Start Challenge TXID: {:?}", start_challenge_txid);

    // let operator_commits

    // for (idx, deposit_address) in deposit_addresses.iter().enumerate() {
    //     let deposit_utxo = rpc
    //         .send_to_address(deposit_address, BRIDGE_AMOUNT_SATS)
    //         .unwrap();
    //     tracing::debug!("Deposit UTXO #{}: {:#?}", idx, deposit_utxo);

    //     rpc.mine_blocks(18).unwrap();

    //     let output = operator_client
    //         .new_deposit_rpc(
    //             deposit_utxo,
    //             taproot_address.as_unchecked().clone(),
    //             evm_addresses[idx],
    //         )
    //         .await
    //         .unwrap();
    //     tracing::debug!("Output #{}: {:#?}", idx, output);
    // }

    // let withdrawal_address = Address::p2tr(&secp, xonly_pk, None, config.network);

    // // This index is 3 since when testing the unit tests complete first and the index=1,2 is not sane
    // let withdraw_txid = operator_client
    //     .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
    //     .await
    //     .unwrap();
    // tracing::debug!("Withdrawal sent to address: {:?}", withdrawal_address);
    // tracing::debug!("Withdrawal TXID: {:#?}", withdraw_txid);

    // // get the tx details from rpc with txid
    // let tx = rpc.get_raw_transaction(&withdraw_txid, None).unwrap();
    // // tracing::debug!("Withdraw TXID raw transaction: {:#?}", tx);

    // // check whether it has an output with the withdrawal address
    // let rpc_withdraw_script = tx.output[0].script_pubkey.clone();
    // let rpc_withdraw_amount = tx.output[0].value;
    // let expected_withdraw_script = withdrawal_address.script_pubkey();
    // assert_eq!(rpc_withdraw_script, expected_withdraw_script);
    // let anyone_can_spend_amount = script_builder::anyone_can_spend_txout().value;

    // // check if the amounts match
    // let expected_withdraw_amount = Amount::from_sat(BRIDGE_AMOUNT_SATS - 2 * config.min_relay_fee)
    //     - anyone_can_spend_amount * 2;
    // assert_eq!(expected_withdraw_amount, rpc_withdraw_amount);
}

fn create_bitvm_sequence(
    num_tx: usize,
    source_utxo: OutPoint,
    operator: &Actor,
    verifier: &Actor,
    config: &BridgeConfig,
) -> (Transaction, Vec<(CreateTxOutputs, CreateTxOutputs)>, Vec<(Signature, Signature)>) {
    let mut tx_vec: Vec<(CreateTxOutputs, CreateTxOutputs)> = Vec::new();
    let mut sig_tuple_vec: Vec<(Signature, Signature)> = Vec::new();

    let verifier_starts_tx = create_verifier_starts_tx(source_utxo, config);
    let start_utxo = OutPoint {
        txid: verifier_starts_tx.compute_txid(),
        vout: 0,
    };
    let verifier_takes_after_utxo = OutPoint {
        txid: verifier_starts_tx.compute_txid(),
        vout: 1,
    };

    let mut verifier_burns_tx_details: CreateTxOutputs =
        create_verifier_burns_tx(start_utxo, verifier_takes_after_utxo, operator, verifier, config);

    let verifier_presign = verifier.sign_taproot_script_spend_tx_new(&mut verifier_burns_tx_details, 0, 1).unwrap();
    let operator_presign = operator.sign_taproot_script_spend_tx_new(&mut verifier_burns_tx_details, 0, 1).unwrap();
    sig_tuple_vec.push((verifier_presign, operator_presign));
    let operator_commits_tx_details: CreateTxOutputs = create_operator_commits_tx(start_utxo, config);
    tx_vec.push((operator_commits_tx_details, verifier_burns_tx_details));

    (verifier_starts_tx, tx_vec, sig_tuple_vec)
}

fn calculate_amount(num_tx: usize) -> Amount {
    let mut amount: u64 = 0;
    Amount::from_sat(amount)
}

fn create_verifier_burns_tx(
    commit_utxo: OutPoint,
    burn_utxo: OutPoint,
    operator: &Actor,
    verifier: &Actor,
    config: &BridgeConfig,
) -> CreateTxOutputs {
    // Calculate the dummy_commit_address and dummy_commit_tree_info
    let dummy_commit_script = script_builder::generate_dummy_commit_script();
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);
    let dummy_commit_taproot = TaprootBuilder::new()
        .add_leaf(1, dummy_commit_script.clone())
        .unwrap()
        .add_leaf(1, musig_script.clone())
        .unwrap();
    let dummy_commit_tree_info = dummy_commit_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let dummy_commit_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        dummy_commit_tree_info.merkle_root(),
        config.network,
    );
    let first_prevout = TxOut {
        value: Amount::from_sat(19000),
        script_pubkey: dummy_commit_address.script_pubkey(),
    };

    // Calculate the challenger_takes_after_address and challenger_takes_after_tree_info
    let challenger_takes_after_script = script_builder::generate_challenger_takes_after_script(
        &config.verifiers_public_keys[0],
        1008,
    );
    let challenger_takes_after_taproot = TaprootBuilder::new()
        .add_leaf(0, challenger_takes_after_script.clone())
        .unwrap();
    let challenger_takes_after_tree_info = challenger_takes_after_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let challenger_takes_after_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        challenger_takes_after_tree_info.merkle_root(),
        config.network,
    );

    let second_prevout = TxOut {
        value: Amount::from_sat(500),
        script_pubkey: challenger_takes_after_address.script_pubkey(),
    };
    let prevouts = vec![first_prevout, second_prevout];
    let txins = TransactionBuilder::create_tx_ins(vec![commit_utxo, burn_utxo]);
    let txouts = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(19500),
        verifier.address.script_pubkey(),
    )]);
    let tx = TransactionBuilder::create_btc_tx(txins, txouts);
    let taproot_spend_infos = vec![dummy_commit_tree_info, challenger_takes_after_tree_info];
    CreateTxOutputs {
        tx,
        prevouts,
        scripts: vec![
            vec![dummy_commit_script, musig_script],
            vec![challenger_takes_after_script],
        ],
        taproot_spend_infos,
    }
}

fn create_operator_commits_tx(start_utxo: OutPoint, config: &BridgeConfig) -> CreateTxOutputs {
    // Calculate the dummy_commit_address and dummy_commit_tree_info
    let dummy_commit_script = script_builder::generate_dummy_commit_script();
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);
    let dummy_commit_taproot = TaprootBuilder::new()
        .add_leaf(1, dummy_commit_script.clone())
        .unwrap()
        .add_leaf(1, musig_script.clone())
        .unwrap();
    let dummy_commit_tree_info = dummy_commit_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let dummy_commit_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        dummy_commit_tree_info.merkle_root(),
        config.network,
    );
    let first_prevout = TxOut {
        value: Amount::from_sat(19000),
        script_pubkey: dummy_commit_address.script_pubkey(),
    };
    let txins = TransactionBuilder::create_tx_ins(vec![start_utxo]);
    let txouts = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(18500),
        dummy_commit_address.script_pubkey(),
    )]);
    let tx = TransactionBuilder::create_btc_tx(txins, txouts);
    let prevouts = vec![first_prevout];
    let scripts = vec![vec![dummy_commit_script, musig_script]];
    let taproot_spend_infos = vec![dummy_commit_tree_info];
    CreateTxOutputs {
        tx,
        prevouts,
        scripts,
        taproot_spend_infos,
    }
}

fn create_verifier_starts_tx(source_utxo: OutPoint, config: &BridgeConfig) -> Transaction {
    let txins = TransactionBuilder::create_tx_ins(vec![source_utxo]);

    // Calculate the dummy_commit_address and dummy_commit_tree_info
    let dummy_commit_script = script_builder::generate_dummy_commit_script();
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);
    let dummy_commit_taproot = TaprootBuilder::new()
        .add_leaf(1, dummy_commit_script.clone())
        .unwrap()
        .add_leaf(1, musig_script.clone())
        .unwrap();
    let dummy_commit_tree_info = dummy_commit_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let dummy_commit_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        dummy_commit_tree_info.merkle_root(),
        config.network,
    );

    // Calculate the challenger_takes_after_address and challenger_takes_after_tree_info
    let challenger_takes_after_script = script_builder::generate_challenger_takes_after_script(
        &config.verifiers_public_keys[0],
        1008,
    );
    let challenger_takes_after_taproot = TaprootBuilder::new()
        .add_leaf(0, challenger_takes_after_script.clone())
        .unwrap();
    let challenger_takes_after_tree_info = challenger_takes_after_taproot
        .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
        .unwrap();
    let challenger_takes_after_address = Address::p2tr(
        &utils::SECP,
        *utils::UNSPENDABLE_XONLY_PUBKEY,
        challenger_takes_after_tree_info.merkle_root(),
        config.network,
    );

    let txouts = TransactionBuilder::create_tx_outs(vec![
        (
            Amount::from_sat(19000),
            dummy_commit_address.script_pubkey(),
        ),
        (Amount::from_sat(500), challenger_takes_after_address.script_pubkey()),
    ]);
    let tx = TransactionBuilder::create_btc_tx(txins, txouts);
    // let start_utxo = OutPoint {
    //     txid: tx.compute_txid(),
    //     vout: 0,
    // };
    // let verifier_takes_after_utxo = OutPoint {
    //     txid: tx.compute_txid(),
    //     vout: 1,
    // };
    // (start_utxo, verifier_takes_after_utxo)
    tx
}
