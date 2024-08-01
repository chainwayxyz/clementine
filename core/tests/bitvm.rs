//! # Deposit and Withdraw Flow Test
//!
//! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Address, Amount, OutPoint, Transaction, TxOut};
use bitcoincore_rpc::RawTx;
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

#[derive(Clone, Debug)]
pub struct BitVMSequence {
    pub start_tx: Transaction,
    pub txs: Vec<(CreateTxOutputs, CreateTxOutputs)>,
    pub sigs: Vec<(Signature, Signature)>,
}

#[tokio::test]
async fn test_bitvm_1() {
    let mut config = create_test_config_with_thread_name!("test_config_bitvm_1.toml");
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
        5,
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
    // println!("{:?}", bitvm_setup);
    let verifier_sig = verifier.sign_taproot_pubkey_spend_tx(&mut bitvm_setup.0, &vec![verifier_source_utxo_as_prevout], 0).unwrap();
    handle_taproot_pubkey_spend_witness(&mut bitvm_setup.0, verifier_sig, 0).unwrap();
    let start_challenge_txid = rpc.send_raw_transaction(&bitvm_setup.0).unwrap();
    println!("Start Challenge TXID: {:?}", start_challenge_txid);
    // let control_block_operator_commits = bitvm_setup.1[0].0.taproot_spend_infos[0].control_block(&(dummy_commit_script.clone(), LeafVersion::TapScript)).unwrap();
    // bitvm_setup.1[0].0.tx.input[0].witness.push(dummy_commit_script.clone());
    // bitvm_setup.1[0].0.tx.input[0].witness.push(control_block_operator_commits.serialize());

    rpc.mine_blocks(7).unwrap();
    let verifier_sig = verifier.sign_taproot_script_spend_tx_new(&mut bitvm_setup.1[0].1, 1, 0).unwrap();
    let control_block_verifier_burns = bitvm_setup.1[0].1.taproot_spend_infos[1].control_block(&(challenger_takes_after_script.clone(), LeafVersion::TapScript)).unwrap();
    bitvm_setup.1[0].1.tx.input[1].witness.push(verifier_sig.serialize());
    bitvm_setup.1[0].1.tx.input[1].witness.push(challenger_takes_after_script.clone());
    bitvm_setup.1[0].1.tx.input[1].witness.push(control_block_verifier_burns.serialize());

    let control_block_musig = bitvm_setup.1[0].1.taproot_spend_infos[0].control_block(&(musig_script.clone(), LeafVersion::TapScript)).unwrap();
    println!("Control Block Musig: {:?}", control_block_musig);
    let verifier_musig = bitvm_setup.2[0].0;
    let operator_musig = bitvm_setup.2[0].1;
    bitvm_setup.1[0].1.tx.input[0].witness.push(operator_musig.serialize());
    bitvm_setup.1[0].1.tx.input[0].witness.push(verifier_musig.serialize());
    bitvm_setup.1[0].1.tx.input[0].witness.push(musig_script.clone());
    bitvm_setup.1[0].1.tx.input[0].witness.push(control_block_musig.serialize());
    println!("Verifier Sending Burning TX...: {:?}", bitvm_setup.1[0].1.tx.raw_hex());
    let verifier_burns_txid = rpc.send_raw_transaction(&bitvm_setup.1[0].1.tx);
    println!("Verifier Burns TXID: {:?}", verifier_burns_txid);


}


#[tokio::test]
async fn test_bitvm_2() {
    let mut config = create_test_config_with_thread_name!("test_config_bitvm_2.toml");
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
        5,
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
    // println!("{:?}", bitvm_setup);
    let verifier_sig = verifier.sign_taproot_pubkey_spend_tx(&mut bitvm_setup.0, &vec![verifier_source_utxo_as_prevout], 0).unwrap();
    handle_taproot_pubkey_spend_witness(&mut bitvm_setup.0, verifier_sig, 0).unwrap();
    let start_challenge_txid = rpc.send_raw_transaction(&bitvm_setup.0).unwrap();
    println!("Start Challenge TXID: {:?}", start_challenge_txid);
    let control_block_operator_commits = bitvm_setup.1[0].0.taproot_spend_infos[0].control_block(&(dummy_commit_script.clone(), LeafVersion::TapScript)).unwrap();
    bitvm_setup.1[0].0.tx.input[0].witness.push(dummy_commit_script.clone());
    bitvm_setup.1[0].0.tx.input[0].witness.push(control_block_operator_commits.serialize());
    let operator_commits_txid = rpc.send_raw_transaction(&bitvm_setup.1[0].0.tx).unwrap();
    println!("Operator Commits TXID: {:?}", operator_commits_txid);
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
        5,
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
    let txins = TransactionBuilder::create_tx_ins_with_sequence_flag(vec![commit_utxo, burn_utxo], 6, vec![false, true]);
    let txouts = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(19000),
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
    let dummy_commit_taproot: TaprootBuilder = TaprootBuilder::new()
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
        5,
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
    tx
}
